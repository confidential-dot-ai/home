# 2026-07-09 — `secretBroker.peerVerify` under `--kata`

Context: Stage-3 smoke of `feat/openbao-integration` (secret-broker + openbao
end-to-end) on an RKE2 + SEV-SNP + kata cluster surfaced that
`secretBroker.peerVerify` is dead code under `kata.enabled=true`. This
decision records what we saw, what we're doing about it now, and what a real
fix looks like.

## What we observed

- Under `--kata`, the in-guest `ratls-mesh` sidecar (baked into
  `kata-guest-base`) transparently intercepts every inbound TLS connection to
  a pod (iptables + tproxy). It terminates the connection with its own
  self-signed bootstrap RA-TLS cert (`O=Confidential, CN=RA-TLS Workload`),
  enforces mesh-CA + attestation on the caller against the mesh's own policy,
  and forwards **plaintext** to the local app on loopback.
- The secret-broker therefore never sees the external TLS handshake. Its
  `--peer-verify=ca` (verify against `--client-ca`) and `--peer-verify=ratls`
  (verify measurement from `.1.1` RA-TLS extension) are both applied on a
  connection that has already been terminated in front of it.
- Empirically, dialling the broker on port 8443 from inside the pod:
  - with the injected mesh leaf (`--cert /etc/c8s/certs/tls.crt`), the far
    side sends a TLS `bad certificate` alert regardless of `peerVerify`.
  - with plain HTTP (no client cert), the far side accepts the TCP but
    returns an empty reply (TLS-only listener on the broker; the mesh does
    not fold the connection into its policy path when the app speaks
    plaintext to a TLS destination).
- Additionally, the injected mesh leaf carries extension `.1.2` (EAR claims)
  but **not** `.1.1` (the raw RA-TLS extension `ratls.VerifyCert` requires).
  So even if the broker had visibility on the peer cert, `peerVerify=ratls`
  would reject every mesh caller anyway.

## Decision (interim)

1. Fail the chart render when `kata.enabled=true` **and**
   `secretBroker.peerVerify=ratls`. The knob is dead code in that shape and
   silently reads as measurement-pinning at the broker when the pin is
   actually held by the mesh.

2. Keep `secretBroker.peerVerify=ca` as the only usable value under `--kata`
   (matches the mesh-delivered peer identity via SAN). Measurement pinning
   for the workload happens at `ratlsMesh.measurements` / CDS allowlist, not
   here.

3. Document the interim state in `docs/pitfalls.md` under
   "`secretBroker.peerVerify=ratls` is inert under kata".

## What a real fix looks like (deferred)

Two mutually-exclusive paths — pick one before we ship this integration:

### A. Mesh embeds the workload's SNP report into the mesh leaf as `.1.1`

CDS's issuance path (`internal/issuer`) currently emits leaves with `.1.2`
(claims) but not `.1.1`. If CDS embedded the requester's freshly-verified SNP
report into `.1.1` at issuance time, `ratls.VerifyCert` on the resulting mesh
cert would succeed, and the broker's `peerVerify=ratls` would become
meaningful — the broker's `--measurements` gates callers, additively to the
mesh's own gate.

Pros: broker-side policy is enforced by the broker (defence in depth); the
release policy's `measurements` field regains a use.
Cons: mesh leaves become larger (SNP report is ~1.2 KB); every cert rotation
carries an attestation cost.

### B. Broker exposes an out-of-mesh port for direct ratls callers

Add a second listener on the broker (say `--ratls-port`) that ratls-mesh
does **not** intercept (either by not labelling the broker pod as a mesh
peer, or by an explicit ratls-mesh passthrough for that port). Callers that
want measurement-gated broker access dial that port directly with their own
in-guest bootstrap cert.

Pros: no CDS changes; mesh stays untouched; the broker's `peerVerify=ratls`
mode works verbatim as the standalone-demo script uses it (see
`scripts/secret-broker-demo.sh`).
Cons: two ports means two threat models to reason about; workloads need to
know which port carries which guarantee; the injected Vault Agent (Stage 4)
would have to know to hit the ratls port.

### C. Do nothing, delete the knob under kata

Drop `secretBroker.peerVerify` (default to `ca` always under kata, and remove
it from the values schema when `kata.enabled=true`). The mesh is the sole
peer authority. Cleanest today, but throws away the option to re-verify at
the broker, which is a legitimate defense-in-depth we may want later.

## Recommendation

Path A. It's a one-way door on the mesh leaf format, but it composes cleanly
with the existing broker semantics and keeps the openbao branch's release
policy schema honest. Ship it before the branch merges to main.

## Path A — step 1 landed in this change; still not sufficient alone

Landing in the same commit as this doc: `SignCSRParams.Attestation` in
`internal/issuer/sign.go` (accept a `*ratls.Attestation` from the caller and
embed it as OID `.1.1`), and `internal/cmds/cds/attest.go handleAttest`
building that value from the request's already-verified evidence via
`attestclient.RATLSEvidence` (SNP → raw report, TDX → JSON envelope). Every
mesh leaf CDS mints from now on will carry the workload's attestation as
`.1.1`, and downstream verifiers (`ratls.VerifyCert`, `c8s cds verify`) can
extract the same measurement CDS accepted.

**But under `--kata` this alone does not make the broker's
`--peer-verify=ratls` work.** The in-guest `ratls-mesh` sidecar is an L4
proxy: it terminates the inbound TLS handshake, verifies the caller against
the mesh policy, and then hands the broker a plain TCP stream with no peer
identity attached (no `Forwarded-Cert` / `X-RATLS-Report` header, no PROXY
protocol frame). So the broker still cannot re-verify the caller.

Step 2 of Path A is one of:

- **Identity forwarding** — teach `ratls-mesh` (in-guest) to inject an
  `X-RATLS-Peer-Cert` (or PROXY-protocol v2 TLV) frame carrying the DER of
  the caller's leaf. The broker's peer-verify parses that instead of
  `r.TLS.PeerCertificates`. Adds an L7-ish concern to what's currently a
  pure L4 proxy; needs care so the header can't be spoofed by a plain-HTTP
  caller (drop on ingress before the mesh appends).
- **Out-of-mesh port on the broker** — expose a second listener the mesh
  does not intercept, and callers that want the broker to re-verify dial
  that port directly with their own mesh cert. Simpler; costs a second
  threat model.

## Follow-ups

- [x] Path A step 1: mesh leaves now carry `.1.1`
      (`internal/issuer/sign.go`, `internal/cmds/cds/attest.go`,
      `internal/issuer/sign_test.go`).
- [ ] Path A step 2 (pick one before Stage 3 can produce a real
      end-to-end secret fetch through the broker under `--kata`).
- [ ] Chart validation `kind=broker_ratls_under_kata` stays until Path A
      step 2 lands. Update this doc when the choice is made.
- [ ] Broker (independently) should mark itself as a mesh peer
      (`confidential.ai/cw: c8s-secret-broker` or similar) so outbound
      traffic from CW pods to the broker rides the mesh's mTLS path
      instead of falling to plain TCP.
- [x] `docs/pitfalls.md` entry.
