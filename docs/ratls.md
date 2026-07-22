# RA-TLS: how c8s components authenticate each other

RA-TLS (Remote Attestation TLS) is ordinary TLS 1.3 with one substitution: a
peer is trusted not because its certificate chains to a CA, but because the
certificate itself carries hardware attestation evidence proving that the TLS
key was generated inside a genuine TEE running measured code. Every trust
decision in c8s that crosses a machine boundary — mesh traffic between pods,
certificate issuance, allowlist reads, CA handoff — rides on it.

This doc walks the process step by step: what is in an RA-TLS certificate, how
a handshake verifies it, how the self-signed bootstrap regime upgrades to
CDS-issued certificates, what the whole construction does and does not
guarantee, how it operates under the two confidential shapes (node-as-CVM and
pod-as-CVM), and which certificate is used where.

Companion docs: [THREAT_MODEL.md](THREAT_MODEL.md) (adversaries, gates,
residual risk), [`cmd/ratls-mesh/DESIGN.md`](../cmd/ratls-mesh/DESIGN.md) (mesh
dataplane), [install-flows.md](install-flows.md) (which components deploy in
which mode).
The implementation is [`pkg/ratls`](../pkg/ratls/), with the CDS client flow in
[`pkg/attestclient`](../pkg/attestclient/) and
[`pkg/ratls/cdsclient`](../pkg/ratls/cdsclient/).

## The idea: bind a TLS key to the hardware root of trust

A TEE (AMD SEV-SNP or Intel TDX guest) can ask its hardware for an
**attestation report**: a structure, signed by a key fused into the CPU, that
contains the guest's **launch measurement** (a digest of exactly what booted)
and 64 bytes of caller-chosen **REPORTDATA**. c8s puts a hash of a
freshly-generated TLS public key into REPORTDATA. The signed report then says,
with the silicon vendor's authority: *this public key belongs to a key pair
created inside this measured guest*.

```text
AMD ARK ──signs──▶ ASK ──signs──▶ VCEK  (per-chip key, TCB-versioned)
(root, in verifier)                  │
                                     │ signs
                                     ▼
                          ATTESTATION_REPORT
                          ├─ MEASUREMENT: launch digest of the guest
                          ├─ REPORTDATA:  SHA-384(TLS pubkey ‖ nonce)
                          └─ policy bits: debug, TCB level, ...
                                     │
                                     │ binds (hash match)
                                     ▼
                          ECDSA P-256 TLS key pair
                          (generated in TEE memory, never on disk)
                                     │
                                     │ authenticates (TLS 1.3 handshake)
                                     ▼
                          the TLS session
```

For TDX the chain is the Intel equivalent (provisioning certification chain →
Quoting Enclave signs the quote) and the pinned measurement is MRTD. Everything
downstream is platform-agnostic.

Because trust flows from the hardware chain, the certificate's own signature is
irrelevant: RA-TLS certificates are self-signed, and the verifying side sets
`InsecureSkipVerify: true` and does all real verification in a
`VerifyPeerCertificate` callback (`pkg/ratls/tls.go`). A compromised network,
control plane, or host cannot mint a passing certificate — only the hardware
can sign a report, and only code inside the TEE ever holds the private key.

## Anatomy of an RA-TLS certificate

`pkg/ratls` builds certificates like this (`cert.go`, `extension.go`,
`provider.go`):

1. **Key generation.** An ECDSA P-256 key pair is generated in process memory.
   It is never written to disk and never leaves the TEE.
2. **Key→report binding.** `REPORTDATA = SHA-384(PKIX-DER(pubkey) ‖ nonce)`,
   zero-padded to the 64-byte REPORTDATA field (same layout on SEV-SNP and
   TDX). The nonce is optional on mesh handshakes (TLS 1.3 already prevents
   replay of the *session*) and mandatory in the CDS issuance flow (it proves
   report freshness). Flows that bind extra context fold it into REPORTDATA
   under a domain separator so the report vouches for that context too, via a
   domain-separated, length-framed transcript: the CDS handoff's operator-key
   commitment (`ReportDataForKeyWithContext`) and a cert's **config-claims**
   (operator-key set, allowlist seed, and the workload's **container-image
   digest**; see the Config-claims section) both use
   `ReportDataForKeyAndClaims`-style framing so no two distinct field triples can
   share a preimage.
3. **Evidence.** The component asks its **local attestation-api** (`POST
   /attest`, the Rust service from
   [attestation-rs](https://github.com/confidential-dot-ai/attestation-rs))
   for evidence over that REPORTDATA. The hardware signs the report inside the
   TEE.
4. **Certificate.** A self-signed X.509 certificate is created with the
   evidence embedded as a custom extension:

   ```text
   OID 1.3.6.1.4.1.59888.1.1  (RA-TLS attestation extension)
   TEEAttestation ::= SEQUENCE {
       teeType     INTEGER,      -- 1 = SEV-SNP, 2 = TDX
       report      OCTET STRING, -- evidence, two shapes (below)
       certChain   OCTET STRING  -- optional inline VCEK chain
   }
   ```

The `report` field carries one of two shapes, auto-detected on parse
(`extension.go`):

- **Bare-metal SNP**: the raw 1184-byte `ATTESTATION_REPORT`. Kept raw so a
  bare-metal report stays extractable by offline SNP verifiers.
- **Everything else** (`az-snp`, `gcp-snp`, `tdx`, `az-tdx`): the attestation-api's
  JSON evidence envelope, forwarded verbatim to `/verify` at handshake time. Both
  TDX shapes must use the envelope (c8s deliberately ships no in-process quote
  parser — see `verify.go`): native `tdx` carries a bulky `cc_eventlog` that is
  stripped before embedding, while Azure-vTPM `az-tdx` (the TD quote wrapped in the
  HCL report, alongside the vTPM quote) has no eventlog and is embedded as-is.
  Azure evidence wrapped in a Hyper-V HCL header is normalized back to the raw
  report where needed (`snp_report.go`).

Certificates live 24h by default and rotate in the background at 50% of TTL;
the old certificate keeps serving until the new one is provisioned, so an
attestation-api hiccup degrades rotation, not traffic (`tls.go`).

## The handshake, step by step

Both sides of a mesh connection run the same logic; the diagram shows one
direction. "attestation-api" is always the verifier's **own, same-TCB**
instance — never one across the network (see Guarantees).

```text
   A (dialer)                                B (listener)
   ──────────                                ────────────
1. TCP connect ────────────────────────────▶
2.             ◀───────────────────────────  TLS 1.3 ServerHello + leaf cert
                                             [ext 1.3.6.1.4.1.59888.1.1:
                                              report with REPORTDATA =
                                              SHA-384(B's pubkey)]
3. parse cert, extract extension
4. POST /verify to A's LOCAL attestation-api:
     { evidence, expected REPORTDATA,
       allow_debug, min_tcb }
   ◀── verdict: hardware chain valid,
       REPORTDATA matches, policy holds,
       launch digest = M
5. require M ∈ measurement allowlist
6. client cert ────────────────────────────▶ mTLS: B runs steps 3–5 on
                                             A's certificate
7. ◀═════════ application bytes, TLS 1.3 ═════════▶
```

Step by step:

1. **Server certificate provisioning is lazy and cached.** The first handshake
   triggers key generation + attestation (steps 1–4 of "Anatomy"); later
   handshakes reuse the cached certificate until rotation.
2. **The client sends no PKI trust anchors.** `NewClientTLSConfig` sets
   `InsecureSkipVerify: true`; `VerifyPeerCertificate` does the work.
3. **Extension extraction.** Missing extension → `ErrNotAttested`, connection
   refused (unless the CA-chain path applies — see dual verification below).
4. **Delegated verification.** The verifier computes the REPORTDATA it
   *expects* from the peer certificate's public key, then forwards evidence +
   expectation + policy to its local attestation-api `POST /verify`. The
   attestation-api checks the hardware signature chain (ARK→ASK→VCEK for SNP,
   Intel collateral for TDX), the REPORTDATA match (key binding), the debug
   policy (`AllowDebug`, default reject), and the minimum TCB (SNP only).
   There is **no in-process verification fallback**: no reachable
   attestation-api means no connection (fail closed).
5. **Measurement policy.** The verified launch digest returned by the
   attestation-api is compared against the caller's allowlist
   (`VerifyPolicy.Measurements`; SNP LAUNCH_DIGEST or TDX MRTD, 48 bytes). An
   **empty allowlist accepts any genuine TEE** — deliberate bootstrap
   ergonomics, loudly warned, and unsafe in production
   ([THREAT_MODEL.md](THREAT_MODEL.md) §5 Open).
6. **mTLS.** Servers configured with a `ClientPolicy` require a client
   certificate and verify it the same way (steps 3–5, roles swapped).

Verification failures map to typed sentinels (`errors.go`):
`ErrSignatureInvalid` (hardware chain), `ErrKeyBinding` (REPORTDATA mismatch —
the key was not generated in that TEE), `ErrPolicyViolation` (measurement not
allowlisted), `ErrNotAttested`, `ErrInvalidReport`, `ErrUnsupportedTEE`.

## From self-signed to CA-issued: the CDS regime

Self-signed RA-TLS needs zero infrastructure, but it verifies hardware
evidence on **every** handshake (with an attestation-api round trip), and it
gives relying parties no revocable, nameable identity. The Certificate
Distribution Service (CDS) layers a conventional CA on top — with the twist
that a CSR is signed **only after** the requester proves, via the same RA-TLS
evidence flow, that its key lives in an attested, measurement-allowlisted TEE.
"Bind identity to measurement": no verified measurement, no certificate.

```text
   requester                        CDS                    local attestation-api
   (get-cert / ratls-mesh)          ───                    ─────────────────────
   ──────────────────────
1. POST /authenticate ────────────▶
   ◀──────────────────────────────  challenge (single-use, 32 B, TTL-bound)
2. generate P-256 key + CSR
   (SAN = workload id / node)
3. REPORTDATA =
   SHA-384(CSR pubkey ‖ challenge)
   POST /attest (REPORTDATA) ─────────────────────────────▶
   ◀───────────────────────────────────── TEE evidence bound to key+challenge
4. POST /attest
   { challenge, evidence, CSR } ──▶
                                    verify evidence (CDS's own
                                    same-TCB attestation-api),
                                    enforce cds.measurements,
                                    validate SAN / CN policy,
                                    sign CSR with the mesh CA
   ◀──────────────────────────────  leaf certificate chain + CA bundle
```

Properties worth noting:

- **The transport for steps 1 and 4 is itself RA-TLS.** CDS self-provisions an
  RA-TLS serving certificate bound to its own launch measurement; clients pin
  it with `--cds-measurements`. The challenge–response plus the RA-TLS channel
  close the bootstrap window against a pod-network impostor — *iff*
  measurements are pinned.
- **The mesh CA private key exists only in CDS process memory** (P-384, CN
  `c8s Mesh CA`, 1-year validity, generated at startup). It is never a
  Kubernetes Secret, never on disk. With `cds.handoff.enabled`, a replacement
  replica adopts the CA from the surviving peer over the attested `/handoff`
  flow — the key crosses the wire only as recipient-encrypted ciphertext
  (X25519-ECDH → HKDF-SHA256 → AES-256-GCM, gated on both sides' EAR
  measurements and operator-key-policy equality). Without handoff, a
  (singleton) CDS restart mints a fresh CA and workloads re-bootstrap; see
  THREAT_MODEL.md §9.
- **Issued leaves are capped at 24h** and always carry a SHA-256 digest of
  the issuance evidence as an audit extension. When the CSR itself embeds an
  RA-TLS extension (the mesh client does; get-cert does not), it is copied
  into the leaf — that is what keeps the attestation fallback working on
  CDS-issued mesh certs (`internal/issuer/sign.go`).
- **The challenge is the freshness proof.** Single-use and TTL-bound
  server-side; REPORTDATA commits to it, so recorded evidence cannot be
  replayed into an issuance.
- **CA bundle distribution is continuity-checked.** `GET /ca` is deliberately
  unauthenticated; consumers seed trust from the *authenticated* issuance
  response and afterwards accept only bundle updates signed by an
  already-trusted CA (`pkg/ratls/cdsclient`). A MITM'd `/ca` read cannot
  inject a new root.
- **EAR tokens, not certs, for key-only attestation.** `POST /attest-key`
  runs the same challenge/evidence flow but returns a signed EAR JWT (ES256,
  JWKS at `/.well-known/jwks.json`) for a caller-held key instead of signing
  a CSR. Callers already holding an EAR can have a CSR signed via
  `POST /sign-csr`. Both are used by CDS's own handoff machinery.

### Dual verification and the upgrade path

Peers configured with a CA bundle accept **either** proof
(`dualVerifyPeerCallback`, `tls.go`):

1. **CA chain** (fast path): standard X.509 verification against the mesh CA
   bundle. No attestation-api call, no KDS dependency, per-connection cost is
   plain TLS.
2. **RA-TLS attestation** (fallback): the full evidence verification above.

This is what makes the bootstrap order-free: ratls-mesh boots self-signed with
no CDS dependency, a background goroutine obtains a CDS-issued certificate
(exponential backoff) and hot-swaps it via `CertManager.SwapProvider` — old
cert serves until the new one is ready — and mixed fleets interoperate
throughout. The multi-cert CA pool also absorbs CA rotation: old and new CA
coexist for the transition window, updated at runtime from `/ca` polling
(`DynamicCACert` + `UpdateCACerts`).

The trade to know about: a CA-chain-verified peer proved its measurement **at
issuance time**, not at handshake time, and today's leaf certificates do not
embed the verified measurement — post-bootstrap mesh peers are "chains to the
mesh CA", not "runs launch digest X" (peer measurement pinning is not
implemented).

## What RA-TLS guarantees — and what it does not

A successful handshake against a pinned policy proves, assuming the
[THREAT_MODEL.md](THREAT_MODEL.md) §6 assumptions hold:

1. **Genuine TEE.** The peer's evidence was signed by real AMD/Intel silicon —
   a hypervisor, control plane, or network attacker cannot forge it.
2. **Key residency.** The peer's TLS private key was generated inside that
   TEE (REPORTDATA binds the key), so nothing outside the encrypted guest —
   including the host — can hold or exfiltrate it.
3. **Code identity.** The guest booted exactly an allowlisted image: its
   launch digest (SNP LAUNCH_DIGEST / TDX MRTD) is in the verifier's pinned
   set. *This guarantee only exists when measurements are pinned.*
4. **Runtime policy floor.** Debug-mode guests are rejected by default;
   on SNP a minimum TCB (microcode/SNP firmware level) can be enforced.
5. **Channel security.** TLS 1.3 with ephemeral key exchange protects
   confidentiality and integrity; certificates rotate halfway through their
   TTL (24h default).
6. **Issuance freshness** (CDS flow): the challenge nonce in REPORTDATA
   prevents replaying recorded evidence into new certificates.

What it does **not** guarantee:

- **Nothing, with an empty measurement allowlist.** Any genuine TEE — including
  an attacker's own CVM on the pod network — is accepted. Both CDS and
  ratls-mesh ship with empty pins, warn loudly, and export
  `ratls_mesh_measurement_pinning=0` for alerting. Pinning is the operator's
  explicit production step.
- **A trustworthy verdict from an untrusted verifier.** The attestation-api's
  `/verify` response is **unsigned**; whoever can impersonate the configured
  `AttestationApiURL` forges "valid". Every deployment therefore keeps the
  verifier in the same TCB as the verifying component: a same-node DaemonSet
  behind `internalTrafficPolicy: Local` (node-as-CVM) or an in-guest loopback
  service (pod-as-CVM). Do not point it across a trust boundary.
- **Per-handshake measurement of CA-verified peers.** See "Dual verification"
  above: after the CDS upgrade, mesh peers are verified by CA chain only.
- **Full TDX runtime measurement.** Policy pins MRTD; RTMR[0..3] are not yet
  pinned, and `MinTCBVersion` is dropped on the TDX path (GAPS).
- **Workload-granular identity beyond the TEE boundary.** The unit of
  hardware attestation is the TEE: the whole node in node-as-CVM, one pod under
  pod-as-CVM. Config-claims narrow this — a workload's cert commits its
  container-image digest (see Config-claims), pinnable with
  `c8s verify --workload-image` — but that binding rests on the in-TCB broker,
  not on a fresh hardware measurement of the running container, and CDS does not
  bind the claim to what the pod runs. So the pin distinguishes **honest
  workloads only**: any admitted workload can assert any *allowlisted* image set
  (it can never assert a non-allowlisted one). Enforcing per-workload
  measurement at `/attest` is unimplemented (GAPS §Trust model).
- **Post-boot integrity.** The launch digest covers boot state; runtime
  compromise inside a measured guest is out of scope (that is the image
  allowlist and guest lockdown's job — [kata-image-policy.md](kata-image-policy.md)).
- **Availability.** A hostile host can always refuse service; RA-TLS turns
  host compromise into DoS, not data exposure.

## Config-claims: attesting configuration and workload identity

The attestation so far binds the *key* and the *launch measurement* — the image
that booted. It says nothing about **host-supplied configuration** (which
operator keys, which allowlist seed) or **which workload** stands behind a mesh
key when the TEE holds more than one. Config-claims close that gap: a second,
optional X.509 extension carrying a small set of digests the attesting
component vouches for, folded into the *same* hardware evidence as the key.

```text
OID 1.3.6.1.4.1.59888.1.3  (RA-TLS config-claims extension)
C8SConfigClaims ::= SEQUENCE {
    version             INTEGER,
    operatorKeysDigest  OCTET STRING (32),  -- unset = 32 zero bytes
    seedDigest          OCTET STRING (32),
    workloadDigest      OCTET STRING (32)
}
```

**Binding.** The claims DER is folded into REPORTDATA as a domain-separated,
length-framed transcript —
`SHA-384("c8s/config-claims/v1\0" ‖ framed(pubkey) ‖ framed(claimsDER) ‖ framed(nonce))`,
where `framed(x) = uint64-BE(len(x)) ‖ x` (`ReportDataForKeyAndClaims`) — so the
hardware report vouches for the digests, not just the key. The framing makes the
preimage unambiguous: no two distinct `(key, claims, nonce)` triples collide,
regardless of field lengths, so the binding does not rest on any field being
fixed-length or on the nonce's provenance. A certificate with no claims skips the
transcript and is byte-identical to a plain RA-TLS cert
(`SHA-384(pubkey ‖ nonce)`). A verifier that pins the expected digests turns a
config or
workload swap into a fail-closed error, the same way pinning a launch
measurement turns an image swap into one. This is **detection by pin-holding
verifiers**, not boot-time prevention.

**What commits what:**

- **CDS's serving cert** commits its loaded **operator-key set** and applied
  **allowlist seed** (workload digest unset). The empty key set has its own
  defined digest, so "writes disabled" is itself attestable. Verifiers pin with
  `c8s cds verify --operator-keys/--allowlist-seed`, which also cross-checks the
  served `/operator-keys` list against the attested digest. (The `/handoff`
  path commits the operator-key set separately, as a REPORTDATA-bound hash — see
  the CDS regime section above.)
- **A workload's mesh cert** commits its **container-image digest**: a
  role-partitioned hash over the pod's admitted init and main image digests
  (operator/seed unset). Verifiers pin with
  `c8s verify --workload-init-image/--workload-image`.

**How the container digest is obtained and why it can be trusted is its own
story** — get-cert fetches the pod's admitted images from a node-local broker
that binds the caller by kernel credentials, and CDS gates issuance on every
image being allowlisted. That flow, its corners, and its residual trust
assumptions are in
**[getcert-workload-binding.md](getcert-workload-binding.md)**. Wire format and
verification rules live in `pkg/ratls` (`claims.go`, `extension.go`,
`verify.go`).

**Reading a peer's claims.** Pinning answers "is this peer *X*?"; a relying
party often needs "*which* workload is this?" — to authorize, route, or log.
`ratls.PeerConfigClaims(*tls.ConnectionState)` returns a verified peer's claims
off a live connection (an HTTP server passes `r.TLS`), or nil when the peer
carried none. It reads the leaf extension and does **not** re-verify: a
completed RA-TLS handshake is the guarantee. The claims are covered on every
accept path — folded into REPORTDATA on the RA-TLS path, or signed by the mesh
CA on the CA path (dual mode) — so the accessor is safe on **any accepted
connection, and only on one**: never read the extension off a connection your
verify callback did not admit. Two limits: the CA-path guarantee is *CDS vouched
at issuance*, not fresh attestation (re-verify the leaf with `VerifyCert` if you
need freshness); and the honest-workload ceiling above holds — a workload digest
names what an *honest* peer runs. `WorkloadDigest` is the combined role-hash over
the pod's *whole* image set ([getcert-workload-binding.md](getcert-workload-binding.md),
"Corner 3"), not a per-image value, so an authorizer
compares it by recomputing `workloadclaims.Digest(init, main)` over the expected
set — the same call `c8s verify` makes.

**Cross-implementation note.** Any non-Go verifier (e.g. `c8s-verify-js`) must
reproduce these byte formats exactly to pin a config-claim: the SHA-384
REPORTDATA fold above, and the canonical digests it commits — the operator
key-set digest (`pkg/operatorauth` `KeySetDigest`), the seed digest
(`pkg/allowlist` `CanonicalDigest`, which is Go `json.Marshal` output, HTML
escaping included), and the role-partitioned workload digest
(`pkg/workloadclaims` `Digest`). A one-byte divergence in any of them fails the
pin. Keep the two implementations tested against shared vectors.

## Operation under the two confidential shapes

The RA-TLS machinery is identical in both shapes; what changes is **where the
TEE boundary sits**, and therefore where the components run, which device
evidence comes from, and what one attested identity covers.

```text
NODE-AS-CVM — one TEE, one identity, per node
╔═ node CVM (SEV-SNP/TDX guest; measured IGVM+UKI+dm-verity boot) ══════╗
║  workload pods (runc) ─┐ get-cert sidecars                            ║
║  ratls-mesh DaemonSet ─┼─ shares the NODE's TEE identity              ║
║  CDS (one pod)        ─┘                                              ║
║  attestation-api DaemonSet ── evidence from the node's TEE device     ║
║    (/dev/sev-guest, TDX TSM configfs, or vTPM on AKS)                 ║
╚═══════════════════════════════════════════════════════════════════════╝
   host / hypervisor: untrusted, sees ciphertext

POD-AS-CVM (kata) — one TEE, one identity, per pod
   host: ADVERSARIAL — operator+webhook, containerd, kata-shim,
         kata-deploy, image puller all run here, outside every TEE
╔═ workload pod CVM (kata-qemu-snp/tdx; measured guest image) ══════════╗
║  workload container(s) + get-cert sidecar                             ║
║  ratls-mesh (in-guest systemd service)      ┐ baked into the          ║
║  attestation-service @ 127.0.0.1:8400       ├ dm-verity rootfs —      ║
║  policy-monitor                             ┘ inside the measurement  ║
╚═══════════════════════════════════════════════════════════════════════╝
╔═ CDS pod CVM ═════════════════╗  ╔═ tls-lb pod CVM ══════════════════╗
║  same baked stack + CDS       ║  ║  same baked stack + nginx/attest  ║
╚═══════════════════════════════╝  ╚═══════════════════════════════════╝
```

### Node-as-CVM (base layout on CVM nodes)

The whole Kubernetes node is one confidential VM; pods are ordinary runc
containers inside it. (This is the base component layout — `c8s install` with
`--cvm-mode node|gke|aks` wiring the right TEE device — deployed onto nodes
that are themselves CVMs. Base on non-CVM nodes has the same layout and no
confidentiality.)

- **Evidence source:** the per-node attestation-api DaemonSet mounts the host
  TEE interface (`/dev/sev-guest`; TSM ConfigFS reports on TDX hosts; vTPM on
  AKS). Its Service uses `internalTrafficPolicy: Local` so `/attest` always
  produces evidence for the *caller's own node* — and so `/verify` verdicts
  never cross a node boundary.
- **RA-TLS endpoints:** ratls-mesh runs as a host-network DaemonSet
  (outbound :15001, inbound :15006). iptables/ipset interception DNATs
  pod-to-pod TCP through it; the node-to-node leg is attested mTLS; the final
  host-to-local-pod dial is plaintext *inside the node's encrypted memory*
  (see [`cmd/ratls-mesh/DESIGN.md`](../cmd/ratls-mesh/DESIGN.md)).
- **Identity granularity:** one launch digest covers the node — kubelet, CNI,
  every pod. All pods share the node's TEE identity; a workload leaf's SAN
  names the workload, but the attestation behind it is the node's quote. Pods
  are only kernel-isolated from each other.
- **Certificates:** get-cert sidecars fetch mesh-CA leaves from CDS through
  the node's attestation flow; ratls-mesh runs self-signed or `--cert-mode
  cds`.

### Pod-as-CVM (kata)

Every in-scope pod is its own `kata-qemu-snp`/`kata-qemu-tdx` CVM with its own
launch digest. The node is a launchpad and is fully adversarial; the chart
refuses to render host-side security components at all (they would be
theater), and CDS and tls-lb run in their own kata CVMs.

- **Evidence source:** the attestation-service is baked into the measured
  guest image and serves loopback `127.0.0.1:8400` inside each pod's VM. The
  guest kernel exposes the TEE device natively. The verifier, the mesh, and
  the image-policy enforcer are all *inside the launch measurement* — the host
  cannot swap them without changing the digest every peer pins.
- **RA-TLS endpoints:** `ratls-mesh in-guest` runs as a systemd service in
  each guest (same ports, fixed). Configuration arrives via the baked
  environment contract (`C8S_WORKLOAD_ID`, `C8S_CDS_URL`,
  `C8S_MESH_MEASUREMENTS`, `C8S_CDS_MEASUREMENTS`, ...). It always runs in
  CDS mode with a dynamically-fetched CA bundle. In-guest iptables REDIRECTs
  all non-loopback TCP through the proxy — no ipsets, no Kubernetes API
  dependency inside the guest.
- **Identity granularity:** per pod. Tenants on one node are isolated from
  each other by hardware memory encryption, and each workload proves its own
  guest state independently.
- **Sharp edges** (both tracked in [THREAT_MODEL.md](THREAT_MODEL.md) §5 /
  [pitfalls.md](pitfalls.md)): UID-0 egress is exempted from in-guest
  interception (so the attestation-service can reach AMD KDS) — root
  workloads bypass the mesh, run workloads non-root; and guests bake
  `C8S_MESH_INBOUND_PASSTHROUGH=tcp:8443` so the CDS/tls-lb front doors can
  accept certless external clients — inbound :8443 is unmeshed in every
  guest.

## Which certificate is used where

| Certificate | Private key lives | Signed by | Presented where | Verified by | Purpose |
|---|---|---|---|---|---|
| Self-signed RA-TLS cert (mesh bootstrap / `--cert-mode self-signed`) | ratls-mesh process memory (in the TEE) | itself — trust is the embedded attestation | mesh inbound :15006 and outbound dials (mTLS both ways) | peer's RA-TLS verification: local attestation-api `/verify` + measurement allowlist | pod-to-pod transport before (or without) CDS |
| CDS RA-TLS serving cert | CDS process memory | itself — attestation bound to CDS's own measurement | CDS API (:8443) | clients pin `--cds-measurements` (get-cert, ratls-mesh, allowlist CLI, nri-image-policy, policy-monitor) | protect the issuance/allowlist API from pod-network impostors |
| Mesh CA (P-384, CN `c8s Mesh CA`, 1y) | CDS process memory only — never a Secret, never disk | self-signed root, or adopted from a peer via attested `/handoff` (recipient-encrypted) | never served as a leaf; public bundle via `GET /ca` and issuance responses | continuity check: new bundle must be signed by an already-trusted CA | root of trust for the CA-chain fast path |
| CDS-issued workload leaf (≤ 24h) | pod volume written by get-cert (`/etc/c8s/certs`, key 0600) — inside the pod's TEE in both shapes | mesh CA, after challenge–attest–certify | workload's own listeners; tls-lb upstream mTLS | chain to the mesh CA bundle | nameable workload identity (SAN = workload id / `c8s-<id>` Service) |
| CDS-issued mesh leaf (`--cert-mode cds`) | ratls-mesh process memory | mesh CA; the leaf preserves the CSR's RA-TLS extension (CN `ratls-mesh-<nodeIP>`) | mesh ports, replacing the self-signed cert after `SwapProvider` | dual verification: CA chain fast path, RA-TLS fallback | post-bootstrap mesh identity without per-handshake attestation cost |
| tls-lb public leaf | tls-lb pod volume (get-cert init container), or an operator-supplied `publicTLS` Secret | mesh CA (default) or external CA | public HTTPS front door | browsers: standard TLS; verifiers: `cds-attest` binds the leaf SPKI or session keys into SNP REPORTDATA | TLS termination for external clients, attestably bound to the TEE |
| EAR JWT (token, not a cert) | per-process P-256 signer key in CDS memory (rotated with overlap) | CDS EAR issuer, ES256 (JWKS at `/.well-known/jwks.json`) | `/attest-key` responses; presented to `/sign-csr` and `/handoff` | JWKS + issuer + measurement + key-binding checks | TEE-bound authorization for key-only flows (CA handoff, EAR-gated signing) |

Adjacent surfaces that are deliberately **not** RA-TLS:

- **The admission webhook's TLS** is ordinary Kubernetes PKI (Secret +
  `caBundle`) — it is availability/injection machinery, not a confidentiality
  boundary, and its material is visible to etcd readers (THREAT_MODEL.md §2).
- **Browser verification** cannot use RA-TLS (browsers cannot inspect
  certificates mid-handshake). External clients get a challenge–response
  attestation and a post-quantum over-encrypted channel instead — see
  [c8s-verify-js](https://github.com/confidential-dot-ai/c8s-verify-js)
  and THREAT_MODEL.md §10.
- **Attested RKE2 credential release** (`c8s cred-release` /
  `c8s cds request-handoff`) and the operator/allowlist CLIs are RA-TLS
  *clients* of the surfaces above rather than new certificate types.

## Reading order for the curious

1. [`pkg/ratls/extension.go`](../pkg/ratls/extension.go) — the binding and the
   extension format (start here).
2. [`pkg/ratls/tls.go`](../pkg/ratls/tls.go) + [`verify.go`](../pkg/ratls/verify.go)
   — handshake wiring, rotation, dual verification, delegated verification.
3. [`pkg/attestclient/client.go`](../pkg/attestclient/client.go) — the CDS
   challenge–attest–certify flow.
4. [`cmd/ratls-mesh/DESIGN.md`](../cmd/ratls-mesh/DESIGN.md) — the dataplane
   that puts it on every connection.
5. [getcert-workload-binding.md](getcert-workload-binding.md) — how a workload's
   container-image digest is fetched, bound into its cert's config-claims, and
   enforced.
6. [THREAT_MODEL.md](THREAT_MODEL.md) — what all of this is for.
