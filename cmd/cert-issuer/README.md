# cert-issuer

Sidecar binary that runs alongside KBS (Key Broker Service) to issue CA-signed certificates for ratls-mesh nodes. It validates EAR (Entity Attestation Result) JWT tokens produced by KBS after successful TEE attestation and signs Certificate Signing Requests (CSRs) with a mesh CA key. Applications use the issued certificates for hardware-attested mTLS within the ratls-mesh.

## Architecture

```
                          KBS Pod
          ┌─────────────────────────────────────────┐
          │                                         │
          │  ┌─────────┐       ┌────────────────┐   │
   TEE    │  │         │  EAR  │                │   │
 evidence │  │   KBS   │──JWT──▶ cert-issuer│   │
──────────▶  │         │       │                │   │
          │  └─────────┘       └───────┬────────┘   │
          │   Verifies TEE              │            │
          │   attestation          Signs CSR         │
          │                        with CA key       │
          └─────────────────────────┼───────────────┘
                                    │
                                    ▼ Signed certificate
                         ┌─────────────────────┐
                         │  ratls-mesh node     │
                         │  (mTLS with peers)   │
                         └─────────────────────┘
```

**Trust model:** cert-issuer does NOT talk to AMD KDS or verify attestation evidence directly. It trusts that KBS has already performed hardware attestation and expresses the result as a signed EAR JWT. The sidecar validates only the JWT signature against the KBS token-signer certificate.

**Enabled via:** `trustee_mesh_ca_enabled: true` in Ansible.

> **Standalone mode:** When `trustee_cert_issuer_standalone: true`, cert-issuer runs as a separate Deployment (not a KBS sidecar). NetworkPolicy restricts ingress to `ratls-mesh-system` and `monitoring` namespaces. This decouples cert-issuer scaling and restarts from KBS.

## Build

```bash
make build-cert-issuer
```

## Usage

```bash
cert-issuer \
  --ca-key /secrets/mesh-ca.key \
  --ca-cert /secrets/mesh-ca.crt \
  --token-cert /secrets/kbs-token-signer.crt \
  --max-ttl 12h \
  --listen :8090 \
  --rate-limit 10 \
  --rate-burst 20 \
  --san-validation true \
  --log-level info
```

## Flags

| Flag | Default | Description |
|------|---------|-------------|
| `--listen` | `:8090` | Listen address |
| `--ca-key` | (required) | Path to CA private key PEM (ECDSA) |
| `--ca-cert` | (required) | Path to CA certificate PEM |
| `--token-cert` | (required) | Path to KBS token-signer certificate PEM (for JWT verification) |
| `--max-ttl` | `24h` | Maximum certificate TTL (requested TTLs are capped to this value) |
| `--log-level` | `info` | Log level: `debug`, `info`, `warn`, `error` |
| `--rate-limit` | `10` | Maximum sign-csr requests per second per source IP |
| `--rate-burst` | `20` | Maximum burst size per source IP |
| `--san-validation` | `true` | Validate CSR IP SANs match request source IP |
| `--parent-cert` | *(empty)* | Path to parent (root) CA certificate for intermediate CA chain validation |
| `--dns-san-pattern` | *(empty)* | Regex for allowed DNS SANs in CSRs (empty = reject all DNS SANs) |
| `--allowed-cn-pattern` | *(empty)* | Regex for allowed CN in CSRs (empty = no restriction) |
| `--expected-issuer` | *(empty)* | Expected JWT `iss` claim (empty = skip validation, with warning) |
| `--rate-limiter-max-entries` | `10000` | Max entries in per-IP rate limiter (bounds memory) |
| `--request-timeout` | `5s` | Per-request timeout for sign-csr handler |

## API

### `POST /v1/sign-csr` -- Sign a CSR

Requires a valid EAR JWT token from KBS. Returns a CA-signed certificate and the CA certificate for chain building.

**Request:**

```json
{
  "ear": "<EAR JWT token from KBS>",
  "csr": "<PEM-encoded Certificate Signing Request>",
  "ttl": "12h"
}
```

**Response (200):**

```json
{
  "certificate": "<PEM-encoded signed certificate>",
  "ca_certificate": "<PEM-encoded CA certificate>"
}
```

**Error codes:**

| Status | Condition |
|--------|-----------|
| 400 | Invalid JSON, missing fields, invalid CSR, bad TTL |
| 401 | EAR JWT signature invalid or token expired |
| 403 | Key binding failed (CSR public key does not match TEE-attested key) |
| 429 | Rate limit exceeded |
| 500 | Internal signing failure |

### `GET /v1/ca` -- Get CA certificate

Returns the CA certificate in PEM format. Public endpoint, no authentication required. Used by ratls-mesh nodes to build the certificate trust chain.

**Response:** `application/x-pem-file` with the CA certificate.

### `GET /metrics` -- Prometheus metrics

Returns Prometheus-format metrics. Key metrics:

| Metric | Type | Description |
|--------|------|-------------|
| `cert_issuer_sign_requests_total{result}` | Counter | Requests by result: success, bad_request, unauthorized, forbidden, error |
| `cert_issuer_sign_latency_seconds` | Histogram | Signing request latency |
| `cert_issuer_certificates_issued_total` | Counter | Successfully issued certificates |
| `cert_issuer_token_validation_failures_total{reason}` | Counter | Token failures: expired, invalid_signature, key_binding, malformed |
| `cert_issuer_active_requests` | Gauge | In-flight sign-csr requests |
| `cert_issuer_ca_cert_expiry_seconds` | Gauge | Seconds until CA cert expires |
| `cert_issuer_token_cert_expiry_seconds` | Gauge | Seconds until token-signer cert expires |
| `cert_issuer_rate_limit_rejections_total` | Counter | Rate-limited requests |
| `cert_issuer_cert_reloads_total` | Counter | Successful certificate hot-reloads |
| `cert_issuer_cert_reload_failures_total` | Counter | Failed hot-reload attempts |
| `cert_issuer_ca_cert_fingerprint_info` | Gauge | Current CA cert SHA-256 fingerprint (label: `fingerprint`) |
| `cert_issuer_dns_san_validation_failures_total` | Counter | DNS SAN validation rejections |
| `cert_issuer_rate_limiter_entries` | Gauge | Current per-IP rate limiter entries |

### `GET /live` -- Liveness probe

Returns 200 when the process is running.

### `GET /ready` -- Readiness probe

Returns 200 when the server is accepting requests.

## Sign-CSR Flow

The `/v1/sign-csr` endpoint performs the following validation steps in order:

1. **Validate EAR JWT signature** -- Verifies the token was signed by KBS using the token-signer certificate. Supports ES256 (P-256) and ES384 (P-384) algorithms.
2. **Check token expiry** -- Rejects tokens past their `exp` claim.
3. **Parse CSR and verify signature** -- Decodes the PEM CSR and checks its self-signature, proving the requester holds the private key.
4. **Verify key binding** -- If the EAR token contains a `tee-pubkey` claim, the CSR's public key must match it. This binds the certificate to the TEE-attested key from the attestation report's REPORTDATA.
5. **Validate SANs** -- If `--san-validation` is enabled: each IP SAN must match the requester's source IP. DNS SANs must match `--dns-san-pattern` (rejected if no pattern set). CN must match `--allowed-cn-pattern` (if set).
6. **Parse and cap TTL** -- Uses the requested TTL or defaults to `--max-ttl`. Requested values exceeding `--max-ttl` are silently capped.
7. **Sign certificate** -- Issues a certificate signed by the CA key with the properties described below.

## Issued Certificate Format

| Field | Value |
|-------|-------|
| Key type | ECDSA (curve from CSR, typically P-256) |
| Subject | CN only (O, OU, C etc. stripped from CSR Subject) |
| DNS SANs | Copied from CSR |
| IP SANs | Copied from CSR |
| KeyUsage | DigitalSignature, KeyEncipherment |
| ExtKeyUsage | ServerAuth, ClientAuth |
| Serial | 128-bit random |
| Validity | `now` to `now + TTL` |
| Attestation digest extension | OID `1.3.6.1.4.1.59888.1.2` -- SHA-256 of raw attestation evidence for audit trail |

The attestation digest extension embeds a SHA-256 hash of the raw EAR attestation evidence into the certificate as a non-critical X.509 extension. This creates a cryptographic link between the issued certificate and the specific attestation that authorized it, enabling offline audit.

## Security Properties

| Property | Status | Implementation |
|----------|--------|----------------|
| JWT signature verification | Enforced | ECDSA verify against token-signer cert |
| Key binding (CSR <-> TEE pubkey) | Enforced | SHA-256 hash comparison |
| Proof of key possession | Enforced | `csr.CheckSignature()` |
| TTL capping | Enforced | `parseTTL()` caps to `--max-ttl` |
| Request size limit | Enforced | `http.MaxBytesHandler(64KB)` |
| Rate limiting | Enforced | Per-source-IP token bucket (`--rate-limit`, `--rate-burst`) |
| Non-root execution | Enforced | `runAsUser: 65534`, `runAsNonRoot: true` |
| Read-only filesystem | Enforced | `readOnlyRootFilesystem: true` |
| All capabilities dropped | Enforced | `capabilities: { drop: [ALL] }` |
| SAN validation (IP match) | Enforced | Every IP SAN must equal requester's `RemoteAddr` (`--san-validation`) |
| DNS SAN rejection (default) | Enforced | No `--dns-san-pattern` set → reject all DNS SANs |
| CN pattern validation | Optional | `--allowed-cn-pattern` regex; empty = no restriction |
| JWT issuer verification | Optional | `--expected-issuer`; warns at startup if unset |
| Intermediate chain validation | Enforced | `validateChain()` at startup + every hot-reload (when `--parent-cert` set) |
| Atomic cert bundle swap | Enforced | `atomic.Pointer[certBundle]` — no partial reads |
| Bounded rate limiter memory | Enforced | `--rate-limiter-max-entries` (default 10000), 5min idle eviction |
| Per-request timeout | Enforced | `--request-timeout` (default 5s) |
| Graceful shutdown | Enforced | `srv.Shutdown()` with 10s drain timeout |

## Hot-Reload

cert-issuer watches its certificate files for changes using fsnotify, enabling zero-downtime certificate rotation:

- **File watching**: Monitors parent directories of cert files (handles Kubernetes Secret/ConfigMap symlink swaps correctly)
- **Debounce**: 2-second debounce window coalesces rapid filesystem events
- **Chain validation**: On reload, `validateChain()` verifies the intermediate→root chain if `--parent-cert` is set
- **Failure handling**: Failed reloads increment `cert_issuer_cert_reload_failures_total`; the previous certificate bundle is preserved
- **Atomic swap**: New certificates are swapped in via `atomic.Pointer[certBundle]` — in-flight requests see a consistent bundle

## Audit Logging

Successful signings emit a structured JSON log line:

```json
{
  "level": "info",
  "msg": "certificate issued",
  "serial": "0x...",
  "subject": "CN=...",
  "ip_sans": ["10.0.0.1"],
  "dns_sans": [],
  "not_after": "2026-03-03T...",
  "ttl": "4h0m0s",
  "source_ip": "10.0.0.1",
  "attestation_digest": "sha256:..."
}
```

## Deployment

Deployed via the `trustee_kbs` Ansible role when mesh CA is enabled:

```
ansible_collections/lunal/kubernetes/roles/trustee_kbs/
```

**Sidecar mode** (default): cert-issuer runs as a container in the KBS pod.

```yaml
trustee_mesh_ca_enabled: true
```

**Standalone mode**: cert-issuer runs as a separate Deployment with independent scaling.

```yaml
trustee_mesh_ca_enabled: true
trustee_cert_issuer_standalone: true
trustee_cert_issuer_replicas: 2  # optional
```

## Testing

```bash
# Unit tests with race detector
go test -race -count=1 -timeout=60s -v ./cmd/cert-issuer/...
```

Tests use generated ephemeral CA and token-signer keypairs -- no KBS or TEE hardware required. Covers: full sign-CSR flow with certificate chain verification, expired token rejection, invalid JWT signature rejection, TTL capping, CA endpoint, TTL parsing, liveness probe, ES384 algorithm, key binding mismatch, attestation digest extension, missing TEE pubkey, future IAT rejection, serial number return, metrics instrumentation, rate limiting, and typed token validation errors.

## Security

- [Threat Model](../../docs/SECURITY/THREAT_MODEL.md) — Threats [T9](../../docs/SECURITY/THREAT_MODEL.md#t9-kbs-ear-token-replay-kbs-mode), [T12](../../docs/SECURITY/THREAT_MODEL.md#t12-cert-issuer-compromise-kbs-mode), [T15](../../docs/SECURITY/THREAT_MODEL.md#t15-standalone-cert-issuer-network-exposure), [T17](../../docs/SECURITY/THREAT_MODEL.md#t17-hot-reload-toctou-cert-issuer)
- [Certificate Lifecycle](../../docs/SECURITY/CERT_LIFECYCLE.md) — CA management, issuance flow, hot-reload
- [Production Hardening](../../docs/SECURITY/PRODUCTION_HARDENING.md) — Hardening checklist for cert-issuer deployment
