# cert-rotator

Rotates token-signer and mesh CA keypairs for the cert-issuer. Generates new certificates, updates Kubernetes Secrets and ConfigMaps with CA bundles, and verifies cert-issuer hot-reload via metrics polling.

Deployed as a Kubernetes CronJob via the `trustee_kbs` Ansible role.

## Build

```bash
make build-cert-rotator
```

## Flags

| Flag | Default | Description |
|------|---------|-------------|
| `--namespace` | `tee-attestation` | Trustee namespace (KBS Secrets location) |
| `--mesh-namespace` | `ratls-mesh-system` | ratls-mesh namespace (CA ConfigMap location) |
| `--components` | `token-signer,mesh-ca` | Comma-separated components to rotate |
| `--token-validity-days` | `365` | Token-signer certificate validity (days) |
| `--mesh-ca-validity-days` | `365` | Mesh CA certificate validity (days) |
| `--cert-issuer-url` | *(empty)* | cert-issuer metrics URL for hot-reload verification |
| `--verify-timeout` | `120s` | Timeout for reload verification polling |
| `--max-ttl` | `4h` | Max leaf cert TTL for CA bundle trimming cutoff |
| `--log-level` | `info` | Log level: `debug`, `info`, `warn`, `error` |

## Rotation Flow

1. Capture baseline cert-issuer metrics (if `--cert-issuer-url` set)
2. For each component in `--components`:
   - **token-signer**: Generate P-256 keypair, create self-signed certificate, update `kbs-token-signing-keys` Secret
   - **mesh-ca**: Generate P-384 keypair, create self-signed CA certificate, update `kbs-mesh-ca` Secret, build CA bundle (new cert + trimmed old certs), update `mesh-ca-cert` ConfigMap
3. Verify cert-issuer hot-reload via metrics polling (5s interval until reload counter increments AND CA fingerprint matches)

## CA Bundle Trimming

Old certificates in the CA bundle are removed when they expired more than `2 × --max-ttl` ago. This grace period ensures that leaf certificates signed by the old CA (which can live up to `--max-ttl`) remain verifiable during their lifetime. Unparseable PEM blocks are preserved.

## Rollback Behavior

If the ConfigMap update fails after a Secret update, the Secret is reverted to its original data. If rollback itself fails, a critical error is logged but the process does not abort — manual intervention is required.

## Audit Trail

Each rotation logs SHA-256 fingerprints for old and new certificates:

```json
{
  "level": "info",
  "msg": "mesh CA rotated",
  "old_fingerprint": "sha256:abc...",
  "new_fingerprint": "sha256:def...",
  "not_after": "2027-03-01T00:00:00Z"
}
```

Token-signer rotations are logged with the same structure.

## Deployment

Deployed as a Kubernetes CronJob via the `trustee_kbs` Ansible role in [`lunal-dev/deployment-scripts`](https://github.com/lunal-dev/deployment-scripts). See the role's README for CronJob configuration, RBAC, and Ansible variables.

## Testing

```bash
go test -race -count=1 -timeout=60s -v ./cmd/cert-rotator/...
```

## Security

- [Threat Model](../../docs/SECURITY/THREAT_MODEL.md) — Threats [T16](../../docs/SECURITY/THREAT_MODEL.md#t16-cert-rotator-secret-access), [T18](../../docs/SECURITY/THREAT_MODEL.md#t18-ca-bundle-trimming-removes-valid-cas)
- [Certificate Lifecycle](../../docs/SECURITY/CERT_LIFECYCLE.md) — Rotation flow, bundle trimming, configuration matrix
