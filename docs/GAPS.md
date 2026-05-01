# c8s gaps

These are known gaps after the operator consolidation milestone. They are
listed here so demos and reviews do not confuse bootstrap convenience with the
final security model.

## Trust model

- The chart-managed mesh CA private key is Secret-backed.
- The CDS-shaped in-CVM signing-key model is not implemented.
- Active/active CDS replica handoff is not implemented.
- Application-secret release is not implemented.
- Per-workload measurement allowlists are not enforced at `/attest`.
- The c8s infrastructure images are not pinned into NRI policy by default.

## Mesh and certificates

- Mesh peer verification checks the CA chain but does not pin peer measurement.
- Leaf certificates do not embed a verified TEE measurement.
- SPIFFE-style URI SANs are not implemented.
- Strict/permissive mTLS modes are not configurable.
- Per-workload `allowedPeers` policy is not enforced.

## Image and pod spec

- The NRI plugin gates image digest, not args, env, mounts, capabilities, or
  other pod-spec fields.

## Operations

- Chart-managed Assam/cert-issuer is not highly available by default.
- Multi-tenancy isolation has no complete design.
- Federation and multi-cluster orchestration remain fleet-level concerns.

## Release cleanup

After the stacked PRs land, cut the release tag for the consolidated chart and
archive `lunal-dev/c8s-operator`. The per-role `lunal-dev/c8s-charts` and fleet
repositories continue independently.
