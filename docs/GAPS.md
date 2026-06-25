# c8s gaps

These are known gaps after the operator consolidation milestone. They are
listed here so demos and reviews do not confuse bootstrap convenience with the
final security model. Each bullet links to the tracking issue.

## Trust model

- Chart-managed CDS runs as a singleton and keeps the active CA key in memory (tracked at [#18](https://github.com/confidential-dot-ai/c8s/issues/18)).
- Active/active CDS replica handoff is opt-in via `cds.handoff.enabled`; it is off by default (tracked at [#18](https://github.com/confidential-dot-ai/c8s/issues/18)).
- Application-secret release is not implemented (tracked at [#46](https://github.com/confidential-dot-ai/c8s/issues/46)).
- Per-workload measurement allowlists are not enforced at `/attest` (tracked at [#57](https://github.com/confidential-dot-ai/c8s/issues/57)).
- The c8s infrastructure images are not pinned into NRI policy by default (tracked at [#51](https://github.com/confidential-dot-ai/c8s/issues/51)).

## Mesh and certificates

- Mesh peer verification checks the CA chain but does not pin peer measurement (tracked at [#47](https://github.com/confidential-dot-ai/c8s/issues/47)).
- Leaf certificates do not embed a verified TEE measurement (tracked at [#47](https://github.com/confidential-dot-ai/c8s/issues/47)).
- SPIFFE-style URI SANs are not implemented (tracked at [#47](https://github.com/confidential-dot-ai/c8s/issues/47)).
- Strict/permissive mTLS modes are not configurable (tracked at [#47](https://github.com/confidential-dot-ai/c8s/issues/47)).
- Per-workload `allowedPeers` policy is not enforced (tracked at [#47](https://github.com/confidential-dot-ai/c8s/issues/47)).

## Image and pod spec

- The NRI plugin gates image digest, not args, env, mounts, capabilities, or
  other pod-spec fields (tracked at [#49](https://github.com/confidential-dot-ai/c8s/issues/49)).

## Operations

- Chart-managed CDS is not highly available by default (broker side tracked at [#75](https://github.com/confidential-dot-ai/c8s/issues/75)).
- Multi-tenancy isolation has no complete design (tracked at [#56](https://github.com/confidential-dot-ai/c8s/issues/56)).
- Federation and multi-cluster orchestration remain fleet-level concerns.

## Browser / out-of-cluster verification

- The `c8s cds-attest` sidecar browser-facing endpoints (`/.well-known/c8s/attestation`,
  `cds-cert.pem`, `handshake`) and the post-quantum over-encryption channel
  (`pkg/overenc`) are implemented behind the tls-lb nginx front-end (chart flag
  `tlsLb.attest.enabled`); the matching browser client is
  `c8s-verify-js` (contract in `c8s-verify-js/PROTOCOL.md`).
- The sidecar's live evidence path requires `--attestation-api-url`; per-session
  binding of the over-encryption key into a fresh hardware report is enforced
  there. The `--evidence-fixture` path is DEV ONLY (fixed `report_data`).
- An optional CDS-issued EAR over the bundle (`ear` field) is defined in the
  contract but not yet populated by the LB.
- The over-encrypted tunnel is not streaming yet. The sidecar buffers each
  sealed request and each upstream response into a single tunnel envelope; HTTP
  chunked transfer from the upstream does not bypass that buffering. Today this
  means uploads are limited by the sidecar's request-record cap and upstream
  responses over 32 MiB fail instead of being forwarded. Large transfers need
  application-level range/chunk APIs or a future streaming tunnel protocol with
  multiple encrypted records.
