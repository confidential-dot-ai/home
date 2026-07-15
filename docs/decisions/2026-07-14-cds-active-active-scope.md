# 2026-07-14 — Stage 3 scope: active/active CDS (JWKS aggregation)

Status: **scope** (breaks the design in `2026-07-14-cds-active-active-ear-jwks.md`
into workstreams). Tracks #75. Not started.

## Goal and non-goals

Goal: two CDS pods both serving behind the Service so a **node failure** is
survived with no trust-root gap. Stage 2 (shipped) already covers rolling
restart; stage 3 adds simultaneous serving.

Non-goals: >2 replicas (design for N but validate 2); sharing the EAR *signing*
key (rejected in the design memo, breaks on rotation); persisting any TEE-held
private (forbidden by the threat model).

## The one thing that makes this safe: pinned RA-TLS discovery

The control plane / etcd is **untrusted** (`THREAT_MODEL.md` row ~57), so a
sibling address learned from the K8s API or a headless Service is
attacker-influenced. This is safe **only because** a sibling's JWKS is fetched
over a measurement-pinned RA-TLS client: the exact pattern the adopt path
already uses (`internal/issuer/ca_provision.go:106-114`,
`ratls.NewVerifyingHTTPClient(pinned, attestationApiURL)` feeding
`NewJWKSKeyProvider`). A rogue endpoint the control plane injects **fails the
RA-TLS handshake** against `cds.measurements`; the control plane can supply the
*address list* but cannot forge a sibling that passes the pin. Stage 3 must
route every sibling fetch through this pinned client, never a plain one.

## Workstreams

### W1 — Rotator external-key ingest (`pkg/earsigner/rotator.go`)

The rotator (`sync.RWMutex` over `active` + `retiring []*managedKey`, JWKS body
in `atomic.Pointer`) is the single verifier for both `/sign-csr`
(`signcsr.go:78`) and `/handoff` (via `buildHandoffHandler` KeyProvider), so one
change fixes both paths.

- Add `external []externalKey` (kid + `*ecdsa.PublicKey`, **no private key**)
  guarded by the existing `mu`. Note: `managedKey` wraps a `*ecdsa.PrivateKey`
  (`rotator.go:31-36`), so external keys need a public-key-only element type,
  not `managedKey`.
- `SetExternalKeys(keys)`: write under `Lock`, then `rebuildJWKS()`.
- Merge `external` into `rebuildJWKS()` (after active/retiring) and into
  `PublicKey(kid)` lookup (both hold the same `mu`).
- **Concurrency gotcha:** `rebuildJWKS` is called single-threaded today
  (`NewRotator` + the one rotate goroutine). A discovery caller makes it the
  first concurrent path, and it only takes `RLock` then `jwksBody.Store`, so two
  concurrent rebuilds can race on which body wins. W1 must serialize rebuilds
  (take the write lock around the whole rebuild, or add a dedicated rebuild
  mutex).
- Sign only with `active` (unchanged); `external` keys are served + accepted for
  verification, never used to sign.
- Metric: a `cds_sibling_keys` gauge + fail-closed reachability gauge. Model on
  `NodeTracker` (`internal/issuer/nodetracker.go`: mutex set + `RunUpdater`) and
  `RunHandoffEARExpiryUpdater` (`handoff.go`: interval gauge that goes negative
  on error). `pkg/earsigner` has no metrics today, so this is its first.

Size: small, self-contained, unit-testable. Extend `rotator_test.go`
(`TestRun_Rotation`, `parseJWKS`, `firstKid`).

### W2 — Sibling discovery loop (new, `internal/issuer` or `internal/cmds/cds`)

Per-pod background loop: enumerate siblings → fetch each `/.well-known/jwks.json`
over the pinned RA-TLS client → union → `rotator.SetExternalKeys`. Runs on a
cadence (align with the JWKS cache TTL, `time.Minute`).

Caveat: `JWKSKeyProvider.PublicKey(kid)` returns one key for a kid and has no
enumerate-all accessor, so the union can't be built from it alone. Either fetch
the sibling's raw `jwk.Set` (a thin helper over the RA-TLS client) or add an
enumerate method; `SetExternalKeys` needs the full `{kid, pub}` list, not
per-kid lookups.

Enumeration options (all need W3 chart support):
- **Headless CDS Service** (cluster DNS returns all pod IPs). CDS Service is
  headless only under kata today (`cds.yaml:322` `clusterIP: None`); non-kata is
  NodePort. Would enable a second headless Service for sibling DNS.
- **Pod informer via K8s API.** There is a direct precedent: `ratlsmesh`
  discovers peers with a Pod informer (`internal/cmds/ratlsmesh/resolver_k8s.go`,
  `rest.InClusterConfig` + `pods:[get,list,watch]` RBAC in
  `ratls-mesh-rbac.yaml`) and its trust-model comment states exactly the model
  we need: "the API server provides routing hints; RA-TLS attestation is the
  actual trust boundary." CDS has **no** such access today (no RBAC bound to the
  CDS SA, and `automountServiceAccountToken: false`), so this is net-new but the
  pattern is proven in-repo.

Recommend headless Service (no new RBAC, no API client in CDS, and the RA-TLS
pin makes DNS-returned IPs safe). Self is excluded by comparing to own pod IP
(downward API, not wired for CDS today; add `POD_IP` env via fieldRef, as
`ratls-mesh-daemonset.yaml` already does).

Failure mode: a sibling unreachable or failing the pin is **logged + metric**,
not fatal: the pod keeps serving its own keys; it just can't verify that
sibling's tokens until discovery succeeds. Fail-open here is correct (a missing
sibling key is availability, not a trust downgrade).

Size: medium. This is the bulk of the work and the only net-new subsystem.

### W3 — Chart topology (`internal/helmchart/c8s/templates/cds.yaml`, values)

Gate behind a new `cds.ha.enabled` (implies `replicas: 2` + `peerUrl: self`):
- Introduce a replicas knob (the stage-2 template fixes `replicas: 1`; per-pod
  EAR keys make a second steady-state endpoint unsafe until W1/W2 land).
- Change strategy: drop `maxUnavailable: 0` (that keeps ONE endpoint); a plain
  RollingUpdate or `maxUnavailable: 1` lets both pods be simultaneous endpoints.
- Second headless Service for sibling discovery (W2), selecting the CDS pods.
- `POD_IP` downward-API env for self-exclusion.
- PDB `maxUnavailable` can rise to 1 (two pods, one can drain).
- Keep the persistence guard (still forbidden; the allowlist rebuilds from seed).

Readiness needs **no** change: `readinessFn` (`run.go` readinessFn) is already
per-pod and peer-agnostic.

Size: medium (chart + render tests, the stage-2 test pattern applies).

### W4 — Bootstrap: who generates vs who adopts (DECIDED)

**Decision: fail-closed-then-heal via the stage-2 two-phase install.** No
StatefulSet, no leader lease.

Why `peerUrl: self` is deterministic here (verified against the code, not
assumed). Two facts:

1. The CDS Service VIP is **outside the mesh** (`values.yaml:723`,
   `cmd/ratls-mesh/README.md:49`, "control-plane traffic dials Service VIPs the
   mesh never intercepts"; the mesh chains only match pod-IP destinations). This
   is correct, not a hole: CDS secures the connection with its own RA-TLS
   (measurement-pinned), not the mesh, so `self` is a plain kube-proxy dial that
   RA-TLS attests end to end.
2. `ProvisionCA` runs at `run.go:65`, but the server does not open its port until
   `run.go:257`, so an **adopting pod is never a Ready endpoint** (its readiness
   probe hits a closed port). A Service (VIP or headless) routes only to Ready
   endpoints in **every** kube-proxy mode (the EndpointSlice controller excludes
   not-ready pods before kube-proxy sees them, mode-independent, unlike the
   mesh's cw-drop rule). The headless (kata) Service does not set
   `publishNotReadyAddresses`, so headless DNS also returns ready-only.

So `peerUrl: self` can never resolve to the adopting pod itself, nor to another
still-adopting pod. Cases:

| Situation | `self` resolves to | Outcome |
|---|---|---|
| Cold start, 1st pod, no peer | 0 ready endpoints → conn refused | `PullTransient` → retries → **fails closed** at `--handoff-peer-timeout` (CrashLoop). Never self-generates. |
| HA on, 2nd pod joining, 1st serving | the 1 Ready endpoint = 1st pod (not itself) | adopts. Correct. |
| Rolling restart, one always Ready | whichever pod is Ready | adopts. Correct. |
| **Both pods down at once** (node reboot) | 0 ready endpoints | both fail closed and CrashLoop until an operator recovers. |

So the operator flow is: **install at `replicas: 1` with `peerUrl` empty** (first
pod self-generates, the stage-2 path), **then `helm upgrade --set
cds.ha.enabled=true`** to add the second pod, which adopts from the first. Every
subsequent roll adopts. This reuses machinery that already exists and ships in
stage 2; no new ordering primitive is added.

**The one real gap (must be a documented runbook, not a surprise):** if *both*
CDS pods are down simultaneously (whole-node reboot, or both deleted), no pod can
adopt (no serving peer) and none will self-generate (all set to adopt), so CDS
stays down until an operator recovers: scale to 1 with `peerUrl` cleared, let it
generate, re-enable HA. This is the safe failure for a trust root ("refuse rather
than risk a divergent CA"), but it trades zero-touch total-outage recovery for
operator intervention. Document it in `operator.md` alongside the HA toggle.

Rejected alternatives (kept for the record): a **StatefulSet** (`cds-0` always
generates, `cds-1` adopts) gives zero-touch total-outage recovery but is a much
larger change to a component that is a plain Deployment today; a **leader lease**
adds a control-plane liveness dependency. Neither is worth it for stage 3;
revisit the StatefulSet only if total-outage auto-recovery becomes a requirement.

## Test seams (no cluster)

- W1: `pkg/earsigner/rotator_test.go`, assert `SetExternalKeys` grows JWKS and
  `PublicKey` resolves an external kid.
- W2: new test fronting two httptest JWKS servers; assert union + fail-open on
  one unreachable. Reuse the `handoff_pull_test.go` httptest pattern.
- Cross-pod verify: `internal/issuer/coverage_more_test.go`
  (`TestJWKSKeyProviderResolvesKid`/`KidMiss`) already drives a client vs an
  httptest JWKS server.
- W3: chart render tests (stage-2 `TestChartCDS*` pattern).

## On-cluster verification (SNP)

Install `cds.ha.enabled` (2 replicas), confirm both pods are Ready Service
endpoints serving the union JWKS, then `kubectl delete pod` one and confirm
`/sign-csr` and `/attest` keep succeeding through the Service with **no** EAR
verification failures (the survivor serves the deleted pod's key until it
expires). Reuse the stage-1/2 Colima-build + `ctr import` image-load path.

## Rough size

W1 small · W2 medium (the real work) · W3 medium · W4 design-first then small-ish
depending on the choice (StatefulSet is the largest). No new external
dependencies. Land as its own stack after PR #74/#75 merge.
