# ratls-mesh Design Document

Transparent L4 proxy that replaces Istio ambient mTLS with hardware-attested (AMD SEV-SNP) mTLS between Kubernetes nodes. One DaemonSet pod per node — all pods on a node share the same TEE identity.

## Architecture

```
Node A                                          Node B
┌─────────────────────────────┐     ┌─────────────────────────────┐
│  App Pod (10.244.1.5:8080)  │     │  App Pod (10.244.2.3:8080)  │
│          │                  │     │          ▲                  │
│  iptables NAT OUTPUT        │     │          │                  │
│  REDIRECT → :15001          │     │          │                  │
│          │                  │     │          │                  │
│  ┌───────▼────────────┐    │     │  ┌───────┴────────────┐    │
│  │ ratls-mesh          │    │     │  │ ratls-mesh          │    │
│  │  outbound :15001    │    │     │  │  inbound :15006     │    │
│  │  resolver: pod→node │    │     │  │  TLS server         │    │
│  │  RA-TLS client ─────┼────┼─────┼──▶  dest header parse  │    │
│  │                     │    │     │  │  dial local pod     │    │
│  │  inbound  :15006    │    │     │  │  outbound :15001    │    │
│  │  health   :15021    │    │     │  │  health   :15021    │    │
│  └─────────────────────┘    │     │  └─────────────────────┘    │
└─────────────────────────────┘     └─────────────────────────────┘
          RA-TLS (TLS 1.3 + AMD SEV-SNP attestation)
```

### Data flow

1. App sends TCP to `10.244.2.3:8080`
2. iptables NAT OUTPUT redirects to `:15001` (outbound listener)
3. Proxy reads original destination via `SO_ORIGINAL_DST`
4. Resolver maps pod IP `10.244.2.3` to node IP `10.0.0.2`
5. If local (same node): direct TCP pipe, no TLS
6. If remote: RA-TLS dial to `10.0.0.2:15006`, send `10.244.2.3:8080\n` header
7. Remote inbound listener reads header, dials local pod, pipes bytes
8. App receives response — unaware of the mesh

### Local vs remote path

The resolver determines whether destination pod is on the same node. Local traffic bypasses RA-TLS entirely — it's a plain TCP pipe from `:15001` to the original destination. This avoids TLS overhead for node-internal communication where the TEE boundary already covers both pods.

## Trust Model

Three security boundaries, layered:

### 1. Hardware attestation (RA-TLS)

Every TLS handshake embeds an AMD SEV-SNP attestation report in the X.509 certificate. The report's `REPORTDATA` field contains `SHA-384(public_key || nonce)`, binding the TLS key to the TEE identity. The trust chain is:

```
AMD Root Key (ARK) → AMD Signing Key (ASK) → VCEK → Attestation Report → TLS Key Binding
```

This proves the remote peer is running inside a genuine AMD SEV-SNP CVM. A compromised control plane or network cannot forge this — only AMD hardware can produce valid reports.

### 2. Kubernetes resolver (routing hints)

The K8s informer watches Pod objects and caches `podIP → nodeIP` mappings. This is a routing optimization, **not a trust boundary**:

- **Compromised API server**: Can return wrong nodeIP → proxy dials wrong node → RA-TLS handshake fails (non-TEE node can't produce valid attestation) → **DoS, not data leakage**
- **Stale cache**: Pod deleted but IP reused → proxy dials old node → handshake fails or new pod responds → RA-TLS still validates
- **Unknown IP** (service VIP, external): Falls through as remote → proxy dials IP directly → either connects (external endpoint) or fails

The resolver is purely advisory. RA-TLS is the actual trust anchor.

### 3. iptables interception

`NET_ADMIN` iptables rules in the NAT OUTPUT chain redirect all TCP traffic through the proxy. Loop prevention via UID exclusion (mesh process UID 1337 is exempt). This ensures applications cannot bypass the mesh for TCP traffic.

**Not protected by iptables**: UDP, raw sockets, and ICMP. DNS (UDP :53) is not intercepted. Kubernetes NetworkPolicy should complement iptables for non-TCP protocols. Both `iptables` (IPv4) and `ip6tables` (IPv6) rules are installed to prevent dual-stack bypass.

### Threat model

| Threat | Impact | Mitigation |
|--------|--------|------------|
| Compromised K8s API server | Routing DoS (wrong node) | RA-TLS rejects non-TEE peers |
| Compromised pod application | App-level data exposure | Out of scope (TEE protects transport, not app logic) |
| Compromised control plane | Can't forge attestation | Hardware-rooted trust (AMD VCEK) |
| Network attacker (MITM) | Can't decrypt traffic | TLS 1.3 + attestation binding |
| Side-channel attacks | Potential data leakage | SEV-SNP memory encryption (hardware limitation) |
| UID 1337 collision | Pod with `runAsUser: 1337` bypasses mesh entirely | Enforce via admission webhook / OPA policy. Drop `CAP_SETUID` on application pods to prevent runtime UID switch. |
| UDP exfiltration | DNS, custom UDP protocols bypass mesh unencrypted | Kubernetes NetworkPolicy restricting UDP egress |
| ICMP reconnaissance | Network topology mapping, covert channels | Kubernetes NetworkPolicy blocking ICMP egress |
| Raw socket bypass | Complete mesh bypass at IP layer | Drop `CAP_NET_RAW` on application pods (PodSecurity or OPA) |
| Inbound open relay | Compromised RA-TLS peer redirects to arbitrary local services | Inbound destination validated against resolver cache (only known local pod IPs allowed) |
| TLS cert reconnaissance | Connecting client sees server attestation report (CPU model, measurements) before client auth | Acceptable: attestation reports are designed to be public. Restrict port 15006 access via NetworkPolicy if needed. |
| Empty measurement policy | Any TEE-attested binary accepted (no code identity check) | Use `--measurements` flag to pin expected launch digests in production |

## Protocol

### Destination header

When the outbound proxy dials a remote node's inbound port, the first data sent (before piping application bytes) is the destination header:

```
<host>:<port>\n
```

- Max size: 256 bytes (enforced by `bufio.NewReaderSize`)
- Read deadline: 5 seconds (configurable via `--dest-header-timeout`)
- Format: Standard `net.JoinHostPort` output (IPv6 addresses are bracketed: `[::1]:8080`)
- Validation: Parsed with `net.SplitHostPort` — invalid format is rejected

The header tells the inbound proxy where to deliver the traffic locally. It is sent in plaintext inside the already-encrypted TLS tunnel — no additional encryption needed.

### Buffered connection

After reading the destination header with `bufio.Reader`, any bytes already buffered (application data sent immediately after the header) must not be lost. The `bufferedConn` wrapper delegates `Read()` to the `bufio.Reader` while forwarding all other `net.Conn` methods to the underlying connection.

## Design Decisions

| Decision | Reasoning | Tradeoff |
|----------|-----------|----------|
| Transparent L4 proxy | Apps need zero modification. Any TCP-based protocol (HTTP, gRPC, database protocols) works automatically. | Requires iptables redirect (Linux-only). No protocol-aware features (retries, circuit breaking). |
| RA-TLS instead of Istio mTLS | Istio trusts the control plane for identity — if istiod is compromised, all mTLS is meaningless. RA-TLS roots trust in AMD hardware, making control plane compromise a DoS issue, not a data leakage issue. | Requires AMD SEV-SNP hardware. More complex certificate handling. |
| Node-level TEE boundary | Azure CVMs run SEV-SNP at the VM level. All pods on a node share the same TEE. Per-pod TEE would require nested virtualization (not available on Azure). | Can't distinguish between pods on the same node at the attestation level. |
| K8s informer for pod→node mapping | O(1) lookups via in-memory cache. Alternative (per-connection API call) would be too slow and create API server hotspot. | Memory proportional to pod count. Watches all namespaces. |
| Static resolver fallback | Single-node K3s deployments don't need K8s API access. Loopback and node IP are local; everything else is remote. | Can't detect same-node pods (always treats non-loopback as remote). |
| UID-based iptables exclusion | Mesh process (UID 1337) must be exempt from redirect to prevent infinite loops. UID matching is the simplest Linux mechanism for this. | Fixed UID (must not collide with other processes). |
| `hostNetwork: true` | Required for iptables rules to see all pod traffic in the host network namespace. Without hostNetwork, the proxy only sees its own pod's traffic. | Pod uses host network stack (port conflicts possible). |
| `hostPort` on inbound only | Inbound port (15006) must be reachable from remote nodes. Outbound port (15001) is only accessed via iptables redirect (no external access needed). | Fixed port allocation per node for inbound. |
| Channel semaphore for connection limit | Non-blocking try-send gives O(1) admission control. Rejected connections get immediate RST (fail-fast, no queuing). | Hard limit — no backpressure or queueing. |
| `idleConn` deadline wrapper | Per-I/O deadline reset catches zombie connections where one side stopped sending. Alternative (periodic health check per connection) would be more complex. | Extra `SetReadDeadline`/`SetWriteDeadline` syscall per I/O operation. |
| `sync.Pool` for 32KB buffers | Reduces GC pressure under high connection churn. `*[]byte` (pointer to slice) prevents interface boxing. | Fixed buffer size. Pool may retain memory during low-traffic periods. |
| Hand-written Prometheus format | Zero external dependencies. The proxy is a single static binary with no runtime requirements beyond libc. | Must maintain format manually. No histograms (would require bucketing logic). |
| Atomic counters (not histograms) | Counters + gauges cover the essential observability needs. Histograms would add complexity without proportional value for an L4 proxy. | Can't answer "what's the p99 connection duration?" from metrics alone (use logs). |
| `preStop` cleanup + sleep | iptables rules must be removed before pod termination to prevent traffic black-holing. The 5s sleep gives K8s time to update endpoints after cleanup. | Adds 5s to every pod termination. |
| No retry logic | This is an L4 proxy — it doesn't understand the application protocol. Retrying at L4 would duplicate TCP streams, potentially causing data corruption. Retries belong in the application or L7 proxy. | App-visible connection failures on transient network issues. |
| No connection pooling | Each app TCP connection maps 1:1 to a proxied connection. L4 transparency requires preserving connection boundaries. | RA-TLS handshake per connection (mitigated by cert caching). |
| Inbound destination validation | Inbound handler validates destination IP against resolver cache (must be a known pod on this node). Prevents compromised RA-TLS peers from using the inbound listener as an open relay to localhost, metadata endpoints, or other services. | Static resolver allows all destinations (single-node dev has no cache). |
| Dual-stack iptables | Both `iptables` (IPv4) and `ip6tables` (IPv6) rules are installed. Prevents IPv6 traffic from bypassing the mesh on dual-stack clusters. | Requires `ip6tables` binary in container image. |
| Measurement pinning | `--measurements` flag accepts expected SHA-384 launch digests. Without it, any valid TEE is accepted (logged as warning). | Requires redeployment when binary changes. |

## Assam Certificate Issuance

### Architecture

When `--cert-mode assam` is used, the mesh obtains CA-signed certificates via assam attestation instead of self-signing:

```
Bootstrap (ratls-mesh dials Assam over its own self-signed RA-TLS cert):

  1. ratls-mesh                       boot with self-signed RA-TLS cert
                                      (provider = self-signed)

  2. ratls-mesh -> assam              POST /authenticate
                <- assam              challenge

  3. ratls-mesh -> attestation-svc    POST /attest (challenge nonce, pubkey)
                <- attestation-svc    SNP evidence

  4. ratls-mesh -> assam              POST /attest (evidence + CSR)
                   assam -> att-svc   verify(evidence)
                          <- att-svc  ok
                   assam -> ci        POST /sign-csr (CSR + EAR)
                          <- ci       signed leaf cert
                <- assam              leaf cert + CA bundle

  5. ratls-mesh                       SwapProvider() hot-swaps the TLS
                                      provider to the CA-signed cert

  6. ratls-mesh -> cert-issuer        GET /ca (continuity-checked refresh)
                <- cert-issuer        updated CA bundle
```

### CertProvider Abstraction

The `ratls.CertProvider` interface decouples certificate provisioning from the TLS stack:

```go
type CertProvider interface {
    Provision(ctx context.Context) (*tls.Certificate, time.Duration, error)
}
```

Two implementations:
- `SelfSignedProvider`: generates key, obtains hardware attestation, creates self-signed cert with attestation extension
- `assamclient.Provider`: generates key, embeds a RA-TLS attestation extension in the CSR, performs assam attestation flow, obtains a CA-signed cert and authenticated CA bundle, then uses `/ca` only for later continuity-checked bundle refreshes

The abstraction enables runtime provider swapping via `CertManager.SwapProvider()` — the old cert continues serving while the new one provisions.

### Dual Verification

With `CACert` set on `ServerConfig` or `ClientConfig`, the `dualVerifyPeerCallback` accepts peers via two paths:

1. **CA chain** (fast path): `cert.Verify(x509.VerifyOptions{Roots: caPool})` — standard X.509 chain validation
2. **RA-TLS** (fallback): `VerifyCert(cert, policy, nonce)` — hardware attestation verification

This dual mode is essential for rolling upgrades:
- T=0: All nodes self-signed → all verify via RA-TLS
- T=1: Some nodes upgraded to CA-signed → upgraded nodes verify via CA chain, others can still verify the preserved RA-TLS extension
- T=2: All nodes CA-signed → all verify via CA chain (fast path)

If both verification paths fail, the error includes both failure reasons for diagnostics.

### Bootstrap Design Decision

The mesh boots with self-signed RA-TLS first, then upgrades to assam-issued certificates in the background. This design was chosen because:

1. **Zero startup dependency on assam** — the mesh is immediately functional even if assam is down or not yet deployed
2. **Rolling upgrade safety** — mixed clusters (some self-signed, some CA-signed) work correctly via dual verification
3. **Failure resilience** — if assam upgrade fails, the mesh continues operating with self-signed RA-TLS
4. **No coordination needed** — each node upgrades independently on its own schedule

## iptables Rules

### Rule generation

`buildRules(outboundPort, inboundPort, uid)` produces two NAT rules placed in a dedicated `RATLS-MESH` chain, applied to both `iptables` and `ip6tables` for dual-stack coverage:

```
-t nat -N RATLS-MESH                                                                    # create chain
-t nat -F RATLS-MESH                                                                    # flush stale rules
-t nat -A RATLS-MESH -p tcp -m owner ! --uid-owner 1337 --dport 1:14999     -j REDIRECT --to-port 15001
-t nat -A RATLS-MESH -p tcp -m owner ! --uid-owner 1337 --dport 15007:65535 -j REDIRECT --to-port 15001
-t nat -A OUTPUT -j RATLS-MESH                                                          # jump from OUTPUT
```

The port range `[15000, 15006]` is excluded:
- **15001**: Outbound listener (would cause redirect loop)
- **15006**: Inbound listener (must receive RA-TLS connections directly)
- **15000, 15002-15005**: Safety buffer between mesh ports

### Dedicated chain (T5 mitigation)

Rules are placed in a custom `RATLS-MESH` chain instead of directly in OUTPUT. This provides atomic stale rule cleanup: on startup, the chain is flushed (`-F`) before inserting new rules, clearing any remnants from a previous crash or version change. The jump rule from OUTPUT to `RATLS-MESH` is idempotent (check before add).

### Idempotent setup

```
for each iptables binary (iptables, ip6tables):
    create chain RATLS-MESH (idempotent: -N fails if exists)
    flush chain RATLS-MESH (clear stale rules)
    add redirect rules to RATLS-MESH
    if jump rule not in OUTPUT:
        add jump rule to OUTPUT
```

Running setup N times produces exactly one copy of each rule.

### Cleanup

Removes the jump from OUTPUT, flushes the chain, and deletes it (`-D`, `-F`, `-X`). If rules don't exist (already cleaned up), logs a warning but continues. The preStop hook runs cleanup followed by a 5s sleep (separated by newline, not `&&`, so sleep always runs regardless of cleanup exit code).

## Connection Lifecycle

### Accept → pipe → close

```
accept(conn)
├── connection limit check (semaphore try-send)
│   ├── rejected → close, increment connLimitRejected
│   └── accepted → activeConns.Add(1)
├── handler(ctx, conn)
│   ├── outbound: origDst → resolve → local/remote dial → pipe
│   └── inbound: read dest header → dial local pod → pipe
├── pipe(a, b)
│   ├── goroutine 1: io.CopyBuffer(a←b) with 32KB pool buffer
│   ├── goroutine 2: io.CopyBuffer(b←a) with 32KB pool buffer
│   └── CloseWrite on each direction when done (half-close)
├── log connection (conn ID, direction, bytes, duration, errors)
├── record metrics
└── defer: close conn, release semaphore, activeConns.Done()
```

### Idle timeout

Optional `idleConn` wrapper resets `SetReadDeadline`/`SetWriteDeadline` on every `Read`/`Write`. If no data flows for the configured duration, the OS closes the connection with a timeout error. Applied to both sides of the pipe.

### TCP keepalive

Set at listener level (`net.ListenConfig{KeepAlive: 30s}`) and dialer level (`net.Dialer{KeepAlive: 30s}`). Detects dead peers via TCP keepalive probes (OS-level, not application-level).

### Buffer pool

```go
var bufPool = sync.Pool{
    New: func() any {
        b := make([]byte, 32*1024)
        return &b  // pointer to slice avoids interface boxing
    },
}
```

Each direction of a pipe borrows a 32KB buffer from the pool. Returned after the copy completes. Under high connection churn, this prevents per-connection allocations.

## Resolver

### K8s resolver

Uses `SharedInformerFactory` to watch all Pod objects across all namespaces. The informer maintains a long-lived watch stream to the API server (single connection, not per-lookup).

```
Pod event → onPod/onDeletePod → update podMap (RWMutex-protected)
Resolve(podIP) → RLock → lookup podMap → compare hostIP to nodeIP → local/remote
```

Cache size is sampled every 10 seconds and exposed as a Prometheus gauge. The cache is bounded by the number of running pods (entries are deleted on pod deletion events).

### Resolve logic

```
Resolve(podIP):
    if podIP ∈ {127.0.0.1, ::1, nodeIP}:  → (nodeIP, local)
    if podIP in podMap:                     → (hostIP, hostIP == nodeIP)
    else:                                   → (podIP, remote)  # fallback for VIPs
```

Unknown IPs (service VIPs, external addresses) fall through as remote with the original IP used as the dial target. If the target is not a mesh node, the RA-TLS handshake will fail (expected behavior).

## Observability

### Metrics

All atomic counters, zero external dependencies. Exposed as Prometheus text format on `GET /metrics`.

| Metric | Type | Labels | Description |
|--------|------|--------|-------------|
| `ratls_mesh_active_connections` | gauge | `direction` | Currently open connections |
| `ratls_mesh_connections_total` | counter | `direction`, `result` | Total connections handled |
| `ratls_mesh_bytes_total` | counter | `direction`, `side` | Bytes transferred |
| `ratls_mesh_tls_dial_failures_total` | counter | — | RA-TLS connection failures |
| `ratls_mesh_dial_failures_total` | counter | — | Plain TCP dial failures |
| `ratls_mesh_connection_limit_rejected_total` | counter | — | Semaphore rejections |
| `ratls_mesh_route_errors_total` | counter | — | origDst/resolve/parse failures |
| `ratls_mesh_dest_header_errors_total` | counter | `side` | Header read/write failures |
| `ratls_mesh_resolver_cache_entries` | gauge | — | Pod→node cache size |
| `ratls_mesh_process_uptime_seconds` | gauge | — | Seconds since start |
| `ratls_mesh_process_goroutines` | gauge | — | Current goroutine count |
| `ratls_mesh_process_heap_alloc_bytes` | gauge | — | Heap allocation |
| `ratls_mesh_process_heap_sys_bytes` | gauge | — | Heap memory from OS |

### Health endpoints

| Endpoint | Response | Purpose |
|----------|----------|---------|
| `GET /live` | Always 200 | Liveness probe |
| `GET /ready` | 200 when ready, 503 otherwise | Readiness probe |
| `GET /metrics` | Prometheus text | Metrics scraping |

Readiness transitions:
- **False → True**: After both listeners bind and (for K8s resolver) cache sync completes
- **True → False**: Immediately on SIGTERM, before listeners close

### Structured logging

JSON to stdout via `slog.JSONHandler`. Every connection gets a monotonic `conn` ID for correlation:

```json
{"level":"DEBUG","msg":"inbound started","conn":42,"src":"10.0.0.1:54321"}
{"level":"INFO","msg":"connection done","conn":42,"dir":"inbound","dst":"10.244.1.5:8080","fwd":1024,"rev":512,"dur":"150ms"}
```

## Graceful Shutdown

```
SIGTERM received
    │
    ▼
onShutdown() → health.ready = false → /ready returns 503
    │                                  (K8s stops routing new traffic)
    ▼
Listeners close → accept loops exit
    │
    ▼
Wait for activeConns (up to drainTimeout=30s)
    ├── All connections drained → clean exit
    └── Timeout exceeded → warn and force exit
    │
    ▼
preStop hook (separate from Go process):
    iptables-cleanup → remove NAT rules
    sleep 5          → allow endpoints to update
```

The `terminationGracePeriodSeconds: 45` on the DaemonSet gives enough time for the preStop hook (5s), the Go drain (30s), and margin.

## DaemonSet Deployment

### Security context

- **Pod level**: `seccompProfile: RuntimeDefault`
- **Init container**: `NET_ADMIN` capability (iptables), `readOnlyRootFilesystem`, runs as root
- **Main container**: UID 1337, `runAsNonRoot`, `readOnlyRootFilesystem`, no capabilities

### Probes

- **Startup**: `httpGet /ready` every 2s, 30 failures allowed (60s total for TLS provisioning + cache sync)
- **Readiness**: `httpGet /ready` with configurable period
- **Liveness**: `httpGet /live` with configurable period

### PodDisruptionBudget

`maxUnavailable: 1` — ensures `kubectl drain` respects `terminationGracePeriodSeconds` and at most one node loses mesh coverage during rolling upgrades.

### Prometheus scraping

Annotations on the pod template:
```yaml
prometheus.io/scrape: "true"
prometheus.io/port: "15021"
prometheus.io/path: "/metrics"
```

## Certificate Lifecycle

Certificates are provisioned lazily on the first TLS handshake and cached in memory:

1. Generate ECDSA P-256 key pair
2. Compute `REPORTDATA = SHA-384(pubkey || nonce)`
3. Request attestation evidence from the attestation service (`POST /attest` with REPORTDATA)
4. Extract raw attestation report from the structured evidence response
5. Embed attestation report in X.509 certificate extension
6. Cache certificate in `certState` (RWMutex-protected)
7. Rotate at 50% of TTL (default 12h → rotate at 6h)

The `certState.mu` mutex serializes certificate provisioning — at most one attestation process runs at a time per cert type (server/client). After the first provisioning, the cached cert is returned for all subsequent handshakes until rotation.

### Assam-Issued Certificates

When using `--cert-mode assam`, the lifecycle changes:

1. Initial boot: self-signed RA-TLS certificate (same flow as above)
2. Background goroutine contacts assam: authenticate → attest → obtain cert and authenticated CA bundle
3. `CertManager.SwapProvider()` atomically swaps the provider:
   - Acquires lock, replaces provider, clears cert cache and rotation timer
   - Releases lock, provisions new cert synchronously
   - On success: new CA-signed cert served to all subsequent handshakes
   - On failure: old self-signed cert continues serving (error logged)
4. CA bundle polling starts only after the authenticated bundle has seeded trust, and accepts only continuity-signed updates from `/ca`
5. Rotation continues at 50% of TTL, now using the assam provider
6. Peer verification uses `dualVerifyPeerCallback`: CA chain (fast) or RA-TLS (fallback)

## Comparison to Alternatives

| | Istio ambient | ratls-mesh | **assam-mode ratls-mesh** |
|--|--------------|------------|--------------------------|
| **Trust root** | istiod CA (software) | AMD SEV-SNP (hardware) | Mesh CA (issued after hardware attestation) |
| **Control plane compromise** | Full mTLS bypass | DoS only (can't forge attestation) | DoS only (CA is in-TEE sidecar) |
| **Certificate issuance** | Centralized CA | Per-node self-signed with attestation | Per-node CA-signed after assam attestation |
| **Protocol** | L4/L7 (ztunnel + waypoint) | L4 only | L4 only |
| **Dependencies** | istiod, ztunnel, CNI plugin | Single binary + iptables | Single binary + iptables + assam + cert-issuer |
| **Node-to-node encryption** | HBONE (HTTP/2 tunnel) | TLS 1.3 direct | TLS 1.3 direct |
| **Per-pod identity** | SPIFFE identity per pod | Node-level TEE identity | Node-level TEE identity |
| **Hardware requirement** | None | AMD SEV-SNP CVM | AMD SEV-SNP CVM + assam infrastructure |
