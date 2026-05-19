# assam

The main key broker service binary. Assam verifies TEE attestation evidence via an external attestation service and issues signed X.509 certificates via cert-issuer.

## Usage

```bash
assam \
  --attestation-service-url http://attestation-service:8400 \
  --cert-issuer-url http://cert-issuer:8090 \
  --whitelist-db /data/whitelist.db \
  --resource-map /etc/assam/resource-map.json
```

Whitelist writes are authorized with `Authorization: Bearer <EAR>`. The EAR
must be issued by Assam and its launch measurement must be allowed for
`assam/whitelist-write` in the resource map:

```json
{
  "<sha384-launch-measurement>": ["assam/whitelist-write"]
}
```

## Flags

| Flag | Short | Default | Description |
|------|-------|---------|-------------|
| `--host` | | `0.0.0.0` | Host address to bind to |
| `--port` | `-p` | `8080` | Port to listen on |
| `--attestation-service-url` | | *(required)* | URL of the attestation service |
| `--cert-issuer-url` | | *(required)* | URL of the cert-issuer service |
| `--ear-issuer` | | `assam` | Issuer name for EAR tokens |
| `--cert-ttl` | | `24h` | TTL for issued certificates |
| `--challenge-ttl` | | `1m` | Challenge validity period |
| `--readiness-interval` | | `10s` | Interval between readiness health checks |
| `--whitelist-db` | | *(required)* | Path to the whitelist SQLite database file |
| `--resource-map` | | | Path to JSON resource map file for EAR-authorized whitelist mutations |
| `--jwt-clock-skew` | | `30s` | Maximum acceptable clock skew for whitelist EAR validation |
| `--token-signer-rotation-interval` | | `720h` | How often to rotate the EAR signing key (0 = disable) |
| `--token-signer-overlap` | | `25h` | How long a retired key stays in JWKS after rotation |
| `--token-signer-rotation-jitter` | | `0.1` | Fraction of rotation interval to jitter the first tick |

## Graceful shutdown

The server handles SIGINT (Ctrl+C) and SIGTERM signals for graceful shutdown.
