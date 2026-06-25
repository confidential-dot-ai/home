# c8s threat model

## What is enforced today

The current milestone enforces these gates:

| Gate | Enforced by | Source of truth |
|---|---|---|
| TEE evidence is valid | attestation-api and CDS | hardware evidence verification |
| A CSR can be signed | CDS | EAR JWT, plus `cds.measurements` when configured |
| Image digest is allowed | nri-image-policy | CDS-served allowlist |
| Mesh peer cert chains to the mesh CA | ratls-mesh | mesh CA bundle |
| Workload is injection candidate | admission webhook | pod annotation `confidential.ai/cw` |
| LB attestation + session key are TEE-bound | `c8s cds-attest` sidecar | SNP report `report_data = SHA-384(session_pubkey \|\| nonce)` |

CRDs are not security inputs. `ConfidentialWorkload` is an operator UX/status
surface. A workload can be injected without a CR.

## Chart-managed bootstrap mode

The chart installs a self-contained certificate path served by a single CDS
binary:

- CDS verifies evidence and issues EAR tokens.
- CDS signs workload CSRs in-process with a chart-managed mesh CA generated
  inside CDS process memory. EAR validation and CSR signing happen in the same
  process, so there is no internal RA-TLS hop and no JWKS fetch between
  components.
- The default chart path does not store the mesh CA private key in a Kubernetes
  Secret or persistent volume. The persisted public CA bundle preserves
  verification of already-issued leaves across CDS restarts; it does
  not preserve issuance — a restart generates a new CA key, and workloads
  must re-bootstrap to trust new leaves. See docs/operator.md for the
  singleton-vs-handoff trade-off.
- The chart does not mount handoff private keys from Kubernetes Secrets.
  Attested CA handoff is in-process: CDS self-provisions its handoff signer EAR
  (signer key generated at startup, minted by its own EAR issuer — no external
  service to dial). It is opt-in via `cds.handoff.enabled=true`, which
  authorises peers whose launch digest is in `cds.measurements`; the chart
  fails to render if measurements is empty while handoff is enabled.
- `GET /ca` serves the public CA bundle without EAR authorization
  so ratls-mesh can poll trust anchors after its initial trust seed is
  established from the authenticated certificate issuance response.
  Chart-managed ratls-mesh accepts CA bundle updates only when each new CA is
  signed by an already trusted CA, so unauthenticated bundle reads cannot add
  unrelated trust roots.
- CDS's allowlist write EAR is bound to the request body: the EAR carries
  a `pbh` claim equal to SHA-256 of the canonicalised body, and the handler
  re-hashes and compares before accepting the mutation. A captured token
  cannot be replayed against a different payload within the EAR's TTL.

By default the chart pins no measurements. Two values control measurement
pinning and both ship empty:

- `cds.measurements`: the flat allowlist of SHA-384 hex launch digests
  permitted to call `/attest` and (when handoff is enabled) `/handoff`.
  Empty = no pinning, accept any TEE-attested caller.
- `ratls-mesh.measurements`: ratls-mesh pins CDS's RA-TLS peer cert during the
  initial cert provisioning handshake. Empty = accept any TEE-attested CDS.

With both empty, the chart's RA-TLS handshakes accept any peer that
produces a syntactically valid TEE attestation. An attacker who can serve
their own TEE attestation on the cluster Pod network (compromised CNI,
malicious sidecar, DNS hijack) can stand in for CDS at the bootstrap moment.
CDS logs a warning when its allowlist is empty; ratls-mesh does not. Pin both
in production.

The chart sets `cds.sanValidation=false` because under chart routing CSRs
arrive without a matching TCP source IP, so CDS cannot compare the CSR node IP
SAN to the workload's TCP source IP. DNS SAN and CN validation still run; DNS
SANs are rejected unless explicitly allowed. CA rotation runs inside CDS; the
replacement CA key is generated in process memory and only the public bundle
is persisted.

This is acceptable for demos, development, and environments that deliberately
place CDS inside the intended trust boundary. It is not the final whitepaper
production model by itself: chart-managed CDS still needs to run inside the
intended attested trust boundary, and measurement pinning is an explicit
configuration choice.

## Production direction

The CDS-shaped model uses a signing key generated and held inside attested CVM
memory. Replicas join through attested key handoff. The Kubernetes control
plane only sees ciphertext and public material.

In that model:

- the mesh CA private key is not stored in Kubernetes Secrets;
- new replicas receive CA signing material only after both sides validate EAR
  measurements allowed for handoff. The signature chain is
  transitive: each EAR carries a `tee_public_key` (ECDSA), and that key
  signs a transcript including the ephemeral X25519 KEM public key. The
  X25519 key is therefore bound to the EAR via the ECDSA proof-of-possession,
  not directly;
- scheduled CA rotation runs inside the active signer until active/active
  deployments coordinate post-rotation handoff;
- allowlists and policy are signed by an operator-held key;
- secret release is gated by workload attestation;
- recovery from total CDS outage means re-bootstrap and re-issue certificates.

### CDS is a stateful singleton until handoff is enabled

The CA private key lives only in the running CDS process memory.
A single-replica restart (Helm upgrade, node drain, OOMKill, HPA
replacement) generates a fresh CA whose public key is not signed by
anything ratls-mesh already trusts; the continuity check in
`pkg/ratls/cdsclient.continuityCABundle` rejects it, and every workload
must re-run initial CDS provisioning to converge.

The handoff endpoint (`/handoff`) closes this when the chart enables
`cds.handoff.enabled=true`: CDS generates an ECDSA handoff signer key in
process at startup and self-provisions its EAR via its own EAR issuer (no
external service to dial). No operator key file or Kubernetes Secret is
involved (the alternative — mounting a Secret-backed PEM — would put
CA-adjacent material into etcd, which the design forbids). Active/active
deployments can then handoff the active CA key to a joining replica without
re-issuing workload certs.

Until the operator turns handoff on, run CDS with `replicas: 1`
and `strategy: Recreate` (the chart defaults), guard it with a PDB, and
treat any restart as a planned re-bootstrap event. To turn handoff on,
set `cds.handoff.enabled=true` and pin `cds.measurements` to CDS's launch
digest — the same flat allowlist authorises `/handoff` (setting
handoff.enabled without measurements fails chart render). Then scale up
freely.

## Out of scope for this milestone

- Pod-spec integrity checking beyond image digest policy.
- Per-workload peer allowlists in the mesh.
- Measurement pinning in peer certificate verification.
- Attestation-gated application secret release.
- Multi-tenant isolation and federated multi-cluster control planes.

## Browser / out-of-cluster verification (c8s-verify)

The `c8s cds-attest` sidecar (proxied by the tls-lb nginx front-end) exposes a browser-facing surface over plain HTTPS so an
out-of-cluster client (the `c8s-verify-js` library, or `TEErminator`) can verify
the Load Balancer and open a post-quantum over-encrypted channel to its enclave.
The wire contract is `c8s-verify-js/PROTOCOL.md`.

- `GET /.well-known/c8s/cds-cert.pem` — the mesh CA / LB cert chain. Served
  **unauthenticated by design** (same reasoning as in-cluster `GET /ca`): the
  client MUST chain it through attested evidence before trusting it, never on the
  strength of the TLS connection it arrived over.
- `GET /.well-known/c8s/attestation?nonce=` — raw SEV-SNP evidence whose
  `report_data = SHA-384(x25519 || mlkem768 || nonce)` binds the per-session
  over-encryption key and the client nonce. The client verifies the hardware
  signature, the launch measurement against its pinned allowlist, and this
  binding before deriving the channel.
- `POST /.well-known/c8s/handshake` + over-encrypted application records —
  X25519 + ML-KEM-768 → HKDF-SHA256 → AES-256-GCM (`pkg/overenc`). The channel
  terminates inside the LB CVM, so a TLS-terminating proxy in front of the LB
  cannot read or forge application traffic even though it terminates the outer
  TLS.

The tls-lb nginx serves the static `cds-cert.pem`/`mesh-ca.pem` and reverse-proxies the dynamic `/.well-known/c8s/` paths to the sidecar on loopback.

Trust is transitive from this point: the user verifies only the LB (and, through
the served cert, the mesh CA); the in-cluster RA-TLS mesh vouches for the backend
pods the LB talks to.

The sidecar's `--evidence-fixture` flag serves recorded evidence for demos/tests and is
**DEV ONLY**: its `report_data` is fixed and does not bind a live session key, so
clients must run with freshness enforcement downgraded. Production uses
`--attestation-api-url`, where each session gets a fresh report bound to its
key and nonce.
