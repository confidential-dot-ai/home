# get-cert

A CLI tool for obtaining TLS certificates through the assam TEE attestation flow. It generates (or loads) an ECDSA P-256 key pair, creates a CSR with a specified Subject Alternative Name (SAN), and runs the full attestation-verification-certification flow via assam.

Designed to run as a Kubernetes init container or renewal sidecar alongside a workload that uses the obtained certificate.

## Usage

Obtain a certificate with a DNS SAN:

```bash
get-cert \
  --assam-url http://assam:8080 \
  --attestation-service-url http://localhost:8400 \
  --san api.example.com \
  --out /tls/cert.pem \
  --key-out /tls/key.pem
```

Obtain a certificate with an IP SAN:

```bash
get-cert \
  --assam-url http://assam:8080 \
  --attestation-service-url http://localhost:8400 \
  --san 10.0.0.1 \
  --out /tls/cert.pem \
  --key-out /tls/key.pem
```

Use an existing private key:

```bash
get-cert \
  --assam-url http://assam:8080 \
  --attestation-service-url http://localhost:8400 \
  --san api.example.com \
  --key my-key.pem \
  --out cert.pem
```

## Flags

| Flag | Short | Default | Description |
|------|-------|---------|-------------|
| `--assam-url` | | *(required)* | URL of the running assam service |
| `--attestation-service-url` | | *(required)* | URL of the local attestation service |
| `--san` | | *(required)* | Subject Alternative Name — IP address or hostname |
| `--out` | `-o` | *(stdout)* | Path to write the signed certificate chain PEM |
| `--key` | | *(ephemeral)* | Path to an existing PEM private key for the CSR |
| `--key-out` | | | Path to write the generated private key PEM |
| `--key-mode` | | `0600` | Octal mode for a generated private key |
| `--renew-interval` | | `0` | Re-obtain the certificate at this interval; `0` runs once and exits |
| `--reload-nginx` | | `true` | SIGHUP nginx after certificate renewal or watched file changes |
| `--continue-on-initial-error` | | `false` | In renewal mode, keep running when the first certificate request fails |
| `--verbose` | `-v` | `false` | Enable debug logging |

## Output path validation

Before generating keys or contacting assam, get-cert verifies that the output directories for `--out` and `--key-out` exist and are writable. This prevents requesting certificates that can't be saved.

## SAN detection

The `--san` flag accepts either an IP address or a hostname. get-cert automatically detects which:

- **IP addresses** (IPv4 or IPv6) are added to the CSR as `IPAddresses`
- **Hostnames** are added as `DNSNames`

## Certificate TTL

Certificate lifetime is controlled server-side by assam's `--cert-ttl` flag (default 24h). get-cert does not set the TTL — configure it on the assam server.

For long-running pods, set `--renew-interval` shorter than the server-side TTL. When the workload is not nginx, pass `--reload-nginx=false` and have the workload reload the refreshed cert files using its own mechanism.
