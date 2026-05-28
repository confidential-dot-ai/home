# c8s gaps

These are known gaps after the operator consolidation milestone. They are
listed here so demos and reviews do not confuse bootstrap convenience with the
final security model. Each bullet links to the tracking issue.

## Trust model

- Chart-managed CDS runs as a singleton and keeps the active CA key in memory (tracked at [#18](https://github.com/lunal-dev/c8s/issues/18)).
- Active/active CDS replica handoff is opt-in via `cds.handoff.enabled`; it is off by default (tracked at [#18](https://github.com/lunal-dev/c8s/issues/18)).
- Application-secret release is not implemented (tracked at [#46](https://github.com/lunal-dev/c8s/issues/46)).
- Per-workload measurement allowlists are not enforced at `/attest` (tracked at [#57](https://github.com/lunal-dev/c8s/issues/57)).
- The c8s infrastructure images are not pinned into NRI policy by default (tracked at [#51](https://github.com/lunal-dev/c8s/issues/51)).

## Mesh and certificates

- Mesh peer verification checks the CA chain but does not pin peer measurement (tracked at [#47](https://github.com/lunal-dev/c8s/issues/47)).
- Leaf certificates do not embed a verified TEE measurement (tracked at [#47](https://github.com/lunal-dev/c8s/issues/47)).
- SPIFFE-style URI SANs are not implemented (tracked at [#47](https://github.com/lunal-dev/c8s/issues/47)).
- Strict/permissive mTLS modes are not configurable (tracked at [#47](https://github.com/lunal-dev/c8s/issues/47)).
- Per-workload `allowedPeers` policy is not enforced (tracked at [#47](https://github.com/lunal-dev/c8s/issues/47)).

## Image and pod spec

- The NRI plugin gates image digest, not args, env, mounts, capabilities, or
  other pod-spec fields (tracked at [#49](https://github.com/lunal-dev/c8s/issues/49)).

## Operations

- Chart-managed CDS is not highly available by default (broker side tracked at [#75](https://github.com/lunal-dev/c8s/issues/75)).
- Multi-tenancy isolation has no complete design (tracked at [#56](https://github.com/lunal-dev/c8s/issues/56)).
- Federation and multi-cluster orchestration remain fleet-level concerns.
