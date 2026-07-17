# 2026-07-14 — Active/active CDS: the EAR/JWKS problem (stage 3)

Status: **proposed** (design only; not implemented).

## Context

Stages 1-2 (shipped on `feat/ca-handoff-e2e`) close the CDS *restart* window: a
starting CDS adopts the mesh CA from a surviving peer over attested `/handoff`
(`issuer.ProvisionCA`, `--handoff-peer-url`), and the chart uses a RollingUpdate
that keeps **exactly one** pod a Service endpoint at a time
(`maxUnavailable: 0`/`maxSurge: 1`). That is active/**standby**: continuity
across a rollover, but a node failure still drops the trust root — with no
surviving peer the replacement fails closed, and recovery is a deliberate
re-bootstrap (unset `peerUrl`; see docs/operator.md).

Stage 3 is active/**active**: two CDS pods both serving behind the Service, so a
node failure is survived with no gap. Proven on the SNP cluster, adoption keeps
the mesh CA identical across pods, and the CA path is already interchangeable.
RA-TLS is measurement-pinned (any same-image pod is acceptable) and `/ca` is
signature-continuity-checked. So for the CA, two active pods Just Work.

The **EAR signing key does not**. This is the blocker, and no shipped doc names
it, so this memo does.

## The blocker, precisely

Each CDS process generates its **own** EAR signing key at startup
(`internal/cmds/cds/run.go:101` `earsigner.Generate()`), and the token `kid` is
that key's own thumbprint (`internal/ear/issuer.go:81,176`). Handoff transfers
the CA **only**: `handoffPayload` (`internal/issuer/handoff.go:159-164`) and
`CASnapshot` (`handoff.go:109-113`) carry no EAR field, and the adopting pod
still calls `earsigner.Generate()` for a fresh key. So two pods behind one
Service have two distinct signing keys and two disjoint JWKS.

CDS verifies inbound EARs (on `/sign-csr` and `/handoff`) with its **rotator as
the KeyProvider** (`run.go:197,291`), and the rotator resolves a `kid` only
against keys it generated itself (`pkg/earsigner/rotator.go:104-119` →
`no token-signer key for kid`). External relying parties fetch JWKS from the
Service (load-balanced) via `issuer.JWKSKeyProvider`, which force-refreshes on a
kid-miss, rate-limited to 1/s (`internal/issuer/keyprovider.go:89-117`).

Result: with two active CDS pods, any EAR signed by pod A and presented to pod B
(inbound) or verified against pod B's JWKS (outbound) fails with
`invalid signature` / `no token-signer key`. Active/active is broken for the EAR
path until the two pods agree on signing keys.

## Options considered

### Option A — hand off the EAR signing key (both pods sign with one key)

Extend the handoff payload with the EAR private key so the adopting pod uses the
peer's key instead of generating its own. Mechanically small: add `ear_key` to
`handoffPayload` (`handoff.go:159`) and `CASnapshot` (`handoff.go:109`),
populate it in `wrap` (`handoff.go:290`) and the snapshot closure
(`run.go:296`), parse+validate in `ParseHandoffPayload` (`handoff.go:502`), and
feed it into `ear.NewIssuer`/`NewRotator` at `run.go:101` instead of
`Generate()`. The existing X25519+HKDF+AES-GCM, EAR-AAD-bound envelope already
protects arbitrary payload bytes, so no crypto change.

**Fatal flaw: rotation re-diverges the pods.** `rotator.rotate()`
(`rotator.go:145`) generates a **new random key** per pod on each tick, and
rotation is on by default (720h interval, `cmd.go:78`). Even if both pods start
with the same handed-off key, the first tick on either pod mints an independent
key and the kids diverge again. Keeping them in sync needs one of: (a) only one
pod rotates (leader election, no primitive exists), or (b) each rotation
re-hands-off the new key to peers (no mechanism). Both are as much work as
Option B and add coordination state CDS deliberately avoids.

**Trust cost:** the EAR key gates `/handoff` (CA export) and `/sign-csr`. Sharing
it makes one compromised pod's key mint EARs the sibling accepts for both: a
second copy of the key that authorizes CA export, widening the blast radius the
threat model scopes to one process (`docs/THREAT_MODEL.md:82-83,363`).

### Option B — aggregate JWKS (every pod serves the union of all pods' keys)

Each pod discovers its siblings' public keys and serves the union, and each
pod's verifier accepts sibling-signed tokens. Pods keep independent signing keys
(no shared secret, smaller blast radius). The client-side kid-miss refresh
(`keyprovider.go:89-99`) already makes this work for external consumers **once
every pod serves the full union**: a load-balanced re-fetch lands on some pod,
and any pod can resolve any kid.

**What's missing today:** the rotator has no API to inject a foreign public key
(`rebuildJWKS` only serves keys it generated, `rotator.go:191-205`), and the
inbound verifier is the rotator, which rejects sibling kids. So Option B needs:
1. A public-key ingest path on the rotator (an "external keys" set merged into
   `rebuildJWKS` and into `PublicKey(kid)` resolution).
2. Cross-pod discovery: each pod fetches siblings' `/.well-known/jwks.json` and
   merges. `JWKSKeyProvider` already fetches+caches one URL
   (`keyprovider.go:46-66`) and could be pointed at siblings; discovery of the
   sibling set needs a headless Service (all pod IPs, present under kata at
   `cds.yaml:322-332`, would need enabling non-kata) or the Kubernetes API.
3. Only public keys ever cross the wire (no secret sharing).

**Trust cost:** none beyond today's model. A pod trusts a sibling's *public* key
only if it is a same-measurement CDS (the sibling's JWKS is served over the
sibling's RA-TLS cert, measurement-pinned exactly like the adopt path). No pod
can sign as another.

## Decision

**Recommend Option B (aggregate JWKS), deferred until active/active is actually
required.** Reasons:

- Option A cannot stand without solving rotation coordination, which is the
  harder half of Option B anyway (both need cross-pod key agreement); A adds a
  shared secret on top.
- B keeps the one-key-per-pod trust boundary the threat model assumes: no pod
  can mint another's tokens, and only public keys are exchanged.
- B's client half already exists (kid-miss refresh); the work is bounded to a
  rotator external-key ingest + a sibling-JWKS merge + discovery.

Do **not** implement stage 3 now. Active/standby (stage 2) already gives
continuity across the common case (rolling restart, planned maintenance). True
node-failure HA is worth the added machinery only when an operator needs it;
this memo records the design for that follow-up.

## If/when implemented — shape

- **Rotator:** add `SetExternalKeys([]publicKey)` (kid + pubkey), merged in
  `rebuildJWKS` and in `PublicKey(kid)` after active/retiring. Sibling keys are
  never signed with, only served and accepted for verification.
- **Discovery:** a background loop per pod fetches each sibling's
  `/.well-known/jwks.json` over an RA-TLS-verifying client (reuse
  `ratls.NewVerifyingHTTPClient` + `JWKSKeyProvider`), pinned by
  `cds.measurements`, and calls `SetExternalKeys`. Sibling set from a headless
  CDS Service (enable `clusterIP: None` non-kata) or the pod-listing API.
- **Chart:** introduce a replicas knob (the template fixes `replicas: 1` today)
  and a true multi-endpoint Service (drop `maxUnavailable: 0`), gated behind a
  new `cds.ha.enabled`; keep the two-phase bootstrap (first pod generates, rest
  adopt CA + start serving the union). PDB `maxUnavailable` can rise to 1.
- **Readiness:** `/readyz` is already per-pod and peer-agnostic
  (`run.go:447-460`), so both pods can be endpoints simultaneously (no change).

## Test seams (no cluster needed)

- Rotator external-key ingest + union JWKS: extend `pkg/earsigner/rotator_test.go`
  (`TestRun_Rotation` already asserts multi-key JWKS output).
- Cross-pod verification: `internal/issuer/coverage_more_test.go`
  (`TestJWKSKeyProviderResolvesKid`/`KidMiss`) already drives a client against an
  httptest JWKS server, so assert a sibling kid resolves once the served set is
  a union.
- Sibling discovery merge: new test fronting two httptest JWKS servers.

## Verification (when built)

On the SNP cluster: install `cds.ha.enabled` with 2 replicas + `peerUrl=self`,
confirm both pods are Ready Service endpoints, then `kubectl delete pod` one and
confirm `/sign-csr` and `/attest` keep succeeding through the Service with **no**
EAR verification failures (the surviving pod serves the union, so tokens the
deleted pod signed still verify until they expire).
