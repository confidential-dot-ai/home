# c8s

Confidential computing infrastructure for Kubernetes. Provides TEE attestation, certificate management, RA-TLS mesh networking, and container image policy enforcement.

## Components

| Component | Description | Docs |
|---|---|---|
| [`cmd/cds`](cmd/cds/) | Certificate Distribution Service - verifies TEE attestation evidence, issues EAR tokens, and signs workload CSRs with an in-process mesh CA | [operator docs](docs/operator.md) |
| [`cmd/c8s`](cmd/c8s/) | Operator and install CLI for CRDs, status mirroring, webhook injection, and the embedded Helm chart | [operator docs](docs/operator.md) |
| [`cmd/get-cert`](cmd/get-cert/) | CLI tool and init-container for TEE-attested certificate provisioning | [README](cmd/get-cert/README.md) |
| [`cmd/ratls-mesh`](cmd/ratls-mesh/) | Transparent L4 proxy wrapping inter-node K8s traffic in RA-TLS | [README](cmd/ratls-mesh/README.md) |
| [`cmd/nri-image-policy`](cmd/nri-image-policy/) | NRI plugin enforcing container image digest whitelists | - |

## Libraries

| Package | Description |
|---|---|
| [`pkg/ratls`](pkg/ratls/) | RA-TLS library for hardware-attested mTLS (AMD SEV-SNP, Intel TDX) |
| [`pkg/ratls/cdsclient`](pkg/ratls/cdsclient/) | CDS attestation client for certificate provisioning |
| [`pkg/attestclient`](pkg/attestclient/) | High-level client for the CDS attestation flow |
| [`pkg/attestationclient`](pkg/attestationclient/) | Low-level HTTP client for the attestation service |
| [`pkg/whitelistclient`](pkg/whitelistclient/) | CRUD client for the CDS whitelist API |
| [`pkg/whitelist`](pkg/whitelist/) | Whitelist types and JSON parsing |
| [`pkg/types`](pkg/types/) | Shared request/response types |
| [`pkg/issuerapi`](pkg/issuerapi/) | Certificate issuer API types |
| [`pkg/earsigner`](pkg/earsigner/) | EAR token-signing key lifecycle, rotation, and JWKS serving |
| [`pkg/certutil`](pkg/certutil/) | Certificate utility functions |

## Project structure

```
cmd/
  cds/                     Certificate Distribution Service binary (attestation, EAR, mesh CA)
  c8s/                     Operator and Helm install CLI
  get-cert/                TEE-attested cert provisioning CLI/init-container
  ratls-mesh/              Transparent L4 RA-TLS proxy (DaemonSet)
  nri-image-policy/        NRI container image policy plugin
internal/
  attestation/             Attestation handlers and challenge store
  cmds/                    Subcommand entrypoints (cds, get-cert, ratls-mesh, ...)
  controller/              Operator manager and ConfidentialWorkload reconciler
  ear/                     EAR JWT token issuer (ES256)
  issuer/                  Mesh CA signing, rotation, bundle, and handoff
  helmchart/               Embedded c8s Helm chart
  readiness/               Background health checker
  server/                  Chi router and middleware
  webhook/                 Pod injection admission webhook
  whitelist/               Whitelist handlers and SQLite store
  audit/                   NRI policy audit logging
  cache/                   NRI policy whitelist cache
  containerd/              Containerd tag-to-digest resolver
pkg/
  ratls/                   RA-TLS library (AMD SEV-SNP, Intel TDX)
    cdsclient/             CDS attestation client
  attestclient/            High-level attestation flow client
  attestationclient/       Attestation service HTTP client
  whitelistclient/         Whitelist CRUD + fetch client
  whitelist/               Whitelist types
  types/                   Shared request/response types
  issuerapi/               Cert issuer API types
  earsigner/               EAR token-signing key rotation and JWKS
  certutil/                Certificate utilities
test/
  integration/             Docker-compose integration tests
```

## Build

Requires Go 1.26.3+.

```bash
# Build all binaries
make build

# Build individual binary
make build-c8s
make build-ratls-mesh
make build-nri-image-policy
# ... etc

# Run tests
make test

# Lint (format check + vet)
make lint

# Clean build artifacts
make clean
```

## Install and demos

- [Quickstart](docs/QUICKSTART.md) is the supported install entry point.
- [Demo](docs/DEMO.md) shows the self-contained chart-managed CDS path.
- [Kata runtime](docs/kata.md) covers `c8s install --kata[-enforce]`: Kata
  Containers installation and pod-as-kata-cvm enforcement.
- [Threat model](docs/THREAT_MODEL.md) documents what is enforced today and
  what chart-managed bootstrap means.
- [Gaps](docs/GAPS.md) tracks the CDS-shaped follow-up work.

## Docker images

All images are published to GHCR on push to `main` and `feat/**` branches:
per-role image names remain stable, but each image copies the same multi-mode
`c8s` binary and sets an appropriate entrypoint.

| Image | Base | Notes |
|---|---|---|
| `ghcr.io/lunal-dev/c8s-operator` | distroless | Multi-mode `c8s` binary for operator/install and non-node roles |
| `ghcr.io/lunal-dev/cds` | distroless | |
| `ghcr.io/lunal-dev/get-cert` | distroless | |
| `ghcr.io/lunal-dev/ratls-mesh` | debian-slim | Needs iptables |
| `ghcr.io/lunal-dev/nri-image-policy` | debian-slim | |

## Related repos

- [`lunal-dev/deployment-scripts`](https://github.com/lunal-dev/deployment-scripts) - Ansible roles for deploying these components
- [`lunal-dev/attestation-service`](https://github.com/lunal-dev/attestation-service) - TEE attestation evidence verification service
