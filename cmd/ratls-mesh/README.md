# ratls-mesh

Transparent L4 TCP proxy that wraps inter-node Kubernetes traffic in RA-TLS (Remote Attestation TLS). Each node runs one DaemonSet pod that intercepts all outbound TCP via iptables, establishes hardware-attested mTLS to remote nodes, and delivers traffic to local pods on the inbound side. Applications require zero modification.

See [DESIGN.md](DESIGN.md) for architecture, trust model, and design decisions.

## Build

```bash
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o ratls-mesh ./cmd/ratls-mesh
```

## Usage

### Proxy mode (default)

```bash
ratls-mesh \
  --platform sev-snp \
  --attestation-service-url http://localhost:8400 \
  --outbound-port 15001 \
  --inbound-port 15006 \
  --resolver k8s \
  --health-port 15021
```

Node IP is auto-detected from the `NODE_IP` environment variable (Kubernetes downward API) or set via `--node-ip`.

### Subcommands

```bash
# Set up iptables NAT rules (runs as init container)
ratls-mesh iptables-setup --outbound-port 15001 --inbound-port 15006 --uid 1337

# Remove iptables NAT rules (runs as preStop hook)
ratls-mesh iptables-cleanup --outbound-port 15001 --inbound-port 15006 --uid 1337
```

## Flags

| Flag | Default | Description |
|------|---------|-------------|
| `--platform` | `sev-snp` | TEE platform: `sev-snp` or `tdx` |
| `--attestation-service-url` | (required) | URL of the local attestation service (e.g. `http://localhost:8400`) |
| `--outbound-port` | `15001` | Outbound listener port (iptables redirect target) |
| `--inbound-port` | `15006` | Inbound listener port (RA-TLS from remote nodes) |
| `--node-ip` | `$NODE_IP` | This node's IP address |
| `--resolver` | `static` | Resolver type: `static` or `k8s` |
| `--health-port` | `15021` | Health/metrics HTTP port |
| `--max-conns` | `0` | Max concurrent connections (0 = unlimited) |
| `--idle-timeout` | `0` | Close connections idle longer than this (0 = disabled) |
| `--keepalive` | `30s` | TCP keepalive interval (0 = disabled) |
| `--dial-timeout` | `5s` | Plain TCP dial timeout |
| `--tls-dial-timeout` | `10s` | RA-TLS dial timeout |
| `--dest-header-timeout` | `5s` | Inbound destination header read timeout |
| `--drain-timeout` | `30s` | Graceful shutdown drain timeout |
| `--measurements` | `""` | Comma-separated hex SHA-384 launch measurements (empty = accept any TEE, warns) |
| `--cert-mode` | `self-signed` | Certificate mode: `self-signed` or `assam` |
| `--assam-url` | `""` | Assam service URL for attestation (required for `assam` cert mode) |
| `--attestation-service-url` | (required) | Local attestation service URL (required for `assam` cert mode) |
| `--cert-issuer-url` | `""` | Cert-issuer URL for CA bundle refresh after authenticated provisioning (required for `assam` cert mode) |
| `--ca-cert` | `""` | Path to CA certificate PEM for X.509 chain verification |
| `--cert-ttl` | `24h` | Certificate lifetime; rotates at 50% of TTL |
| `--rotation-timeout` | `30s` | Max time for background certificate rotation |
| `--log-level` | `info` | Log level: `debug`, `info`, `warn`, `error` |

## Certificate Modes

The `--cert-mode` flag controls how ratls-mesh obtains TLS certificates:

| Mode | Behavior |
|------|----------|
| `self-signed` | Default. RA-TLS self-signed certificates with attestation evidence embedded as X.509 extensions. Peers verify via hardware attestation chain. |
| `assam` | Boots with self-signed RA-TLS, then a background goroutine contacts assam with exponential backoff (2s → 60s), obtains CA-signed certificates, and hot-swaps them. Once upgraded, stays on CA-signed certs. |

### Bootstrap flow (assam mode)

1. Proxy starts immediately with self-signed RA-TLS certificates (no assam dependency at startup)
2. Background goroutine initiates assam attestation: authenticate → attest → obtain cert and authenticated CA bundle
3. On success, `CertManager.SwapProvider()` hot-swaps to CA-signed certificates
4. `/ca` polling starts only after that authenticated CA bundle has seeded trust, and accepts only continuity-signed updates
5. Peer verification accepts BOTH RA-TLS attestation AND CA-chain during the transition (dual verification)
6. Once all nodes upgrade, CA-chain verification is the fast path

This design ensures zero-downtime upgrades — nodes can be upgraded from self-signed to assam-issued certificates without service interruption.

### Dual verification

When `--ca-cert` is provided, the mesh accepts peers verified via either:
- A valid CA-signed certificate chain (fast path, standard X.509)
- A valid RA-TLS attestation extension (fallback, hardware verification)

This enables rolling upgrades where some nodes have assam-issued certificates and others still use self-signed RA-TLS.

## Deployment

Deployed as a Kubernetes DaemonSet via the `ratls_mesh` Ansible role:

```
ansible_collections/lunal/kubernetes/roles/ratls_mesh/
```

Key Ansible variables (in `defaults/main.yml`):

| Variable | Default | Description |
|----------|---------|-------------|
| `ratls_mesh_namespace` | `ratls-mesh-system` | Kubernetes namespace |
| `ratls_mesh_platform` | `{{ tee_platform }}` | TEE platform |
| `ratls_mesh_resolver` | `k8s` | Resolver type |
| `ratls_mesh_health_port` | `15021` | Health port |
| `ratls_mesh_max_conns` | `0` | Connection limit |
| `ratls_mesh_idle_timeout` | `""` | Idle timeout |
| `ratls_mesh_log_level` | `info` | Log level |
| `ratls_mesh_uid` | `1337` | Mesh process UID |
| `ratls_mesh_resources` | `k8s_resources.small` | CPU/memory limits |
| `ratls_mesh_node_selector` | `{}` | Optional node selector |
| `ratls_mesh_cert_mode` | `self-signed` | Certificate mode |
| `ratls_mesh_assam_url` | `""` | Assam URL for attestation |
| `ratls_mesh_attestation_service_url` | `""` | Attestation service URL |
| `ratls_mesh_cert_issuer_url` | `""` | Cert-issuer URL for CA bundle refresh |

## Observability

### Health probes

```
GET :15021/live    → 200 (always)
GET :15021/ready   → 200 (ready) / 503 (not ready or shutting down)
GET :15021/metrics → Prometheus text format
```

### Metrics

All metrics are prefixed with `ratls_mesh_`. Key metrics:

- `ratls_mesh_active_connections{direction}` — current open connections
- `ratls_mesh_connections_total{direction,result}` — total connections
- `ratls_mesh_bytes_total{direction,side}` — bytes transferred
- `ratls_mesh_tls_dial_failures_total` — RA-TLS failures
- `ratls_mesh_route_errors_total` — routing failures
- `ratls_mesh_process_goroutines` — goroutine count
- `ratls_mesh_cert_mode` — current certificate mode gauge (0=self-signed, 1=assam)
- `ratls_mesh_process_heap_alloc_bytes` — heap usage

### Logs

JSON structured logs to stdout. Each connection gets a unique `conn` ID:

```json
{"level":"INFO","msg":"connection done","conn":42,"dir":"outbound-ratls","dst":"10.244.1.5:8080","node":"10.0.0.2:15006","fwd":1024,"rev":512,"dur":"150ms"}
```

## Testing

```bash
# Unit tests with race detector
go test -race -count=1 -timeout=60s -v ./...

# Cross-compile for Linux (production target)
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o /dev/null ./...
```

Tests use fake SNP attestation reports — no AMD hardware required. 27 tests covering:
proxy data flow, RA-TLS end-to-end, concurrent connections, graceful drain, connection limits, idle timeout, resolver logic, health endpoints, metrics accounting, iptables rule generation.

## Security

- [Threat Model](../../docs/SECURITY/THREAT_MODEL.md) — 21 analyzed threats (T1-T21) with mitigations and risk matrix
- [Measurement Pinning](../../docs/SECURITY/MEASUREMENT_PINNING.md) — Production setup for TEE launch digest pinning
- [Certificate Lifecycle](../../docs/SECURITY/CERT_LIFECYCLE.md) — Issuance, rotation, dual verification, bundle management
- [Production Hardening](../../docs/SECURITY/PRODUCTION_HARDENING.md) — Must/should/could checklist
