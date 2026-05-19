# cert-issuer

`cert-issuer` validates EAR JWTs from Assam and signs CSRs with a mesh CA key
held in process memory. The chart-managed shape does not load the CA key from a
Kubernetes Secret or persist it to disk. Only the public CA bundle is persisted
— this preserves verification of already-issued leaves across cert-issuer
restarts; a restart generates a new CA key and workloads must re-bootstrap to
trust new issuances (see docs/operator.md for the singleton-vs-handoff
trade-off).

## Usage

```bash
cert-issuer \
  --ca-common-name "c8s Mesh CA" \
  --ca-rotation-interval 720h \
  --ca-repo-dir /var/lib/cert-issuer/public-bundle \
  --jwks-url http://assam.c8s-system.svc:8080/.well-known/jwks.json \
  --expected-issuer assam \
  --max-ttl 24h \
  --listen :8090
```

## Flags

| Flag | Default | Description |
|---|---:|---|
| `--listen` | `:8090` | Listen address |
| `--ca-common-name` | `c8s Mesh CA` | Common name for the generated mesh CA |
| `--ca-rotation-interval` | `720h` | Positive interval for scheduled in-process mesh CA rotation |
| `--ca-repo-dir` | empty | Optional directory for public CA bundle write-back |
| `--ca-bundle-path` | `ca-bundle.pem` | Public bundle path below `--ca-repo-dir` |
| `--jwks-url` | empty | JWKS endpoint for EAR signature verification |
| `--token-cert` | empty | Token-signer certificate when `--jwks-url` is unset |
| `--expected-issuer` | empty | Expected EAR `iss` claim |
| `--resource-map` | empty | JSON measurement-to-resource map |
| `--max-ttl` | `24h` | Maximum leaf certificate TTL |
| `--ca-cert-validity` | `8760h` | Validity for generated/rotated CA certificates |
| `--min-ca-validity` | `1h` | Minimum remaining CA validity for readiness |
| `--san-validation` | `true` | Validate CSR IP SANs against request source IP |
| `--dns-san-pattern` | empty | Regex for allowed DNS SANs; empty rejects DNS SANs |
| `--allowed-cn-pattern` | empty | Regex for allowed CNs |

## Resources

The resource map uses launch measurements as keys and cert-issuer resource
paths as values:

```json
{
  "<sha384-launch-measurement>": [
    "cert-issuer/sign-csr",
    "cert-issuer/handoff"
  ]
}
```

`GET /ca` is unauthenticated: it serves only public trust anchors and mesh
clients poll it for bundle updates. The continuity check in
`pkg/ratls/assamclient` rejects any update whose new CA is not signed by an
already-trusted CA, so an unauthenticated reader cannot poison the trust set.
CA rotation is in-process and does not use a Kubernetes Secret, external
controller, or remote HTTP API.

## API

### `POST /sign-csr`

Requires a valid EAR JWT and returns a signed leaf certificate plus the public
CA bundle:

```json
{
  "ear": "<EAR JWT>",
  "csr": "<PEM CSR>",
  "ttl": "12h"
}
```

### `GET /ca`

Returns the public CA bundle as `application/x-pem-file`.
