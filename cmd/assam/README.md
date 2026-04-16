# assam

The main key broker service binary. Assam verifies TEE attestation evidence via an external attestation service and issues signed X.509 certificates via cert-issuer.

## Usage

```bash
assam \
  --attestation-service-url http://attestation-service:8400 \
  --cert-issuer-url http://cert-issuer:8090 \
  --ear-key /secrets/ear-signing-key.pem \
  --whitelist-db /data/whitelist.db \
  --whitelist-admin-password secret
```

## Flags

| Flag | Short | Default | Description |
|------|-------|---------|-------------|
| `--host` | | `0.0.0.0` | Host address to bind to |
| `--port` | `-p` | `8080` | Port to listen on |
| `--attestation-service-url` | | *(required)* | URL of the attestation service |
| `--cert-issuer-url` | | *(required)* | URL of the cert-issuer service |
| `--ear-key` | | *(required)* | Path to EC private key PEM for signing EAR tokens |
| `--ear-issuer` | | `assam` | Issuer name for EAR tokens |
| `--cert-ttl` | | `24h` | TTL for issued certificates |
| `--challenge-ttl` | | `1m` | Challenge validity period |
| `--readiness-interval` | | `10s` | Interval between readiness health checks |
| `--whitelist-db` | | *(required)* | Path to the whitelist SQLite database file |
| `--whitelist-admin-password` | | *(required)* | Admin password for whitelist mutation endpoints |

## Graceful shutdown

The server handles SIGINT (Ctrl+C) and SIGTERM signals for graceful shutdown.
