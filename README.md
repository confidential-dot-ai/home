# c8s

Confidential computing infrastructure for Kubernetes. Provides TEE attestation, certificate management, RA-TLS mesh networking, and container image policy enforcement.

## Components

| Component | Description | Docs |
|---|---|---|
| [`cmd/cds`](cmd/cds/) | Certificate Distribution Service - verifies TEE attestation evidence, issues EAR tokens, and signs workload CSRs with an in-process mesh CA | [operator docs](docs/operator.md) |
| [`cmd/c8s`](cmd/c8s/) | Operator and install CLI for CRDs, status mirroring, webhook injection, and the embedded Helm chart | [operator docs](docs/operator.md) |
| [`cmd/get-cert`](cmd/get-cert/) | CLI tool and init-container for TEE-attested certificate provisioning | [README](cmd/get-cert/README.md) |
| [`cmd/ratls-mesh`](cmd/ratls-mesh/) | Transparent L4 proxy wrapping inter-node K8s traffic in RA-TLS | [README](cmd/ratls-mesh/README.md) |
| [`cmd/nri-image-policy`](cmd/nri-image-policy/) | NRI plugin enforcing container image digest allowlists | - |

## Libraries

| Package | Description |
|---|---|
| [`pkg/ratls`](pkg/ratls/) | RA-TLS library for hardware-attested mTLS (AMD SEV-SNP, Intel TDX) |
| [`pkg/ratls/cdsclient`](pkg/ratls/cdsclient/) | CDS attestation client for certificate provisioning |
| [`pkg/attestclient`](pkg/attestclient/) | High-level client for the CDS attestation flow |
| [`pkg/attestationclient`](pkg/attestationclient/) | Low-level HTTP client for the attestation-api |
| [`pkg/allowlistclient`](pkg/allowlistclient/) | CRUD client for the CDS allowlist API |
| [`pkg/allowlist`](pkg/allowlist/) | Allowlist types and JSON parsing |
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
  allowlist/               Allowlist handlers and SQLite store
  audit/                   NRI policy audit logging
  cache/                   NRI policy allowlist cache
  containerd/              Containerd tag-to-digest resolver
pkg/
  ratls/                   RA-TLS library (AMD SEV-SNP, Intel TDX)
    cdsclient/             CDS attestation client
  attestclient/            High-level attestation flow client
  attestationclient/       attestation-api HTTP client
  allowlistclient/         Allowlist CRUD + fetch client
  allowlist/               Allowlist types
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
# Build the c8s binary for the container images (linux/amd64)
make build

# Build and install the c8s CLI for your host platform, onto PATH
make install

# Run tests
make test

# Lint (format check + vet)
make lint

# Clean build artifacts
make clean
```

## Install and demos

- [Quickstart](docs/QUICKSTART.md) is the supported install entry point.

### Local clusters pulling from a private registry

While the c8s images are private, a local cluster needs a registry credential
in place **before** the install, in this order:

```sh
# 1. Create the release namespace (the Secret must live where the pods run;
#    `c8s install` labels it pod-security=privileged later, so pre-creating
#    it is fine).
kubectl create namespace c8s-system

# 2. Create the pull secret in that namespace (idempotent; re-run to rotate).
#    Defaults: SECRET_NAME=ghcr-pull-secret, REGISTRY=ghcr.io.
IMAGE_PULL_SECRET=<ghcr-token> NAMESPACE=c8s-system ./scripts/deploy-image-pull-secret.sh

# 3. THEN install, referencing the Secret by name.
c8s install --namespace c8s-system --image-pull-secret ghcr-pull-secret
```

The chart wires the Secret into every component's `imagePullSecrets`
(kubelet pulls, and under `--kata` the kata-image-puller's oras pull too), so
all pods authenticate from first start. The order matters: the install fails
fast if the Secret is not already in the release namespace — note the
script's `NAMESPACE` defaults to `default`, where kubelet cannot see it from
`c8s-system` pods. See [Quickstart — private registry
credentials](docs/QUICKSTART.md#private-registry-credentials) for details.
- [Demo](docs/DEMO.md) shows the self-contained chart-managed CDS path.
- [Kata runtime](docs/kata.md) covers `c8s install --kata`: Kata Containers
  installation and pod-as-kata-CVM enforcement — `--kata` is enforcing, there
  is no kata-without-enforcement shape.
- [Threat model](docs/THREAT_MODEL.md) documents what is enforced today and
  what chart-managed bootstrap means.
- [Gaps](docs/GAPS.md) tracks the CDS-shaped follow-up work.

## Docker images

All images are published to GHCR on push to `main` and `feat/**` branches:
per-role image names remain stable, but each image copies the same multi-mode
`c8s` binary and sets an appropriate entrypoint.

| Image | Base | Notes |
|---|---|---|
| `ghcr.io/confidential-dot-ai/c8s-operator` | distroless | Multi-mode `c8s` binary for operator/install and non-node roles |
| `ghcr.io/confidential-dot-ai/cds` | distroless | |
| `ghcr.io/confidential-dot-ai/get-cert` | distroless | |
| `ghcr.io/confidential-dot-ai/ratls-mesh` | debian-slim | Needs iptables |
| `ghcr.io/confidential-dot-ai/nri-image-policy` | debian-slim | |

## Related repos

- [`confidential-dot-ai/deployment-scripts`](https://github.com/confidential-dot-ai/deployment-scripts) - Ansible roles for deploying these components
- [`confidential-dot-ai/attestation-rs`](https://github.com/confidential-dot-ai/attestation-rs) - TEE attestation evidence verification service (publishes the `attestation-api` image)
