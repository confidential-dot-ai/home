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

Requires Go 1.26+.

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
c8s install --namespace c8s-system --image-pull-secret ghcr-pull-secret \
  --workload-ref vllm=<namespace>/deployment/<vllm-deployment>:8000 --upstream vllm
```

For existing workloads, `c8s install --workload-ref <cw-id>=<namespace>/<kind>/<name>`
adopts them as CWs and resolves their images into the NRI bootstrap allowlist.
See [existing workload adoption](docs/operator.md#existing-workload-adoption).

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

## Managing the allowlist

CDS serves the image-digest allowlist that `nri-image-policy` enforces on every
node. The `c8s allowlist` command reads and mutates it.

CDS has **no public ingress**. Reach it over a port-forward (the CLI verifies
CDS's attestation, so the localhost hop is fine):

```sh
kubectl port-forward -n c8s-system svc/c8s-cds 8443:8443 &
CDS=https://localhost:8443
```

or front it via the tls-lb. The examples below use `$CDS`. The URL must be
`https://` (RA-TLS); a plaintext `http://` endpoint is refused unless you pass
`--insecure` (dev/test only, skips CDS attestation).

**Reads** are unauthenticated:

```sh
# List the live allowlist (text or -o json)
c8s allowlist list --url $CDS \
  --measurements <cds-sha384-launch-digest> \
  --attestation-api-url <attestation-api-url>

# Back it up / show what a file would change
c8s allowlist export --url $CDS > allowlist.json
c8s allowlist diff allowlist.json --url $CDS
```

An `https://` URL is verified via CDS's RA-TLS attestation — pass
`--measurements` (repeatable/comma-separated, or `--measurements-file`) to pin
CDS's launch measurement; an empty set accepts any attested CDS (UNSAFE).
Verification currently reaches the attestation-api at `--attestation-api-url`
(forward it too, or run the CLI where it is reachable); local RA-TLS-cert
verification like `c8s verify` is a planned improvement (see `docs/GAPS.md`).

**Writes** require the operator key (see below):

```sh
# Add or remove single digests (--dry-run prints the change without calling CDS)
c8s allowlist add    sha256:<digest> registry.example.com/app@sha256:<digest> --url $CDS --operator-key operator.key
c8s allowlist remove sha256:<digest> --url $CDS --operator-key operator.key

# Replace the whole allowlist from a file (CDS assigns the new version)
c8s allowlist upload allowlist.json --url $CDS --operator-key operator.key
```

`upload` refuses a file that names none of the core c8s components
(`cds`, `ratls-mesh`, `nri-image-policy`, `attestation-api`, `nginx`) — a
cluster missing them cannot pull its own control plane. Re-run with `--force`
to override, or change the required set with `--require`.

### Operator allowlist credentials

Allowlist writes are authenticated by an operator **EC key** whose **public**
half CDS pins (`cds.operatorKeys`). The CLI signs a short-lived,
request-body-bound token with the private key — so a captured token cannot be
replayed against a different payload. Generate a keypair and pin the public half
(P-256 EC):

```sh
# Operator private key — keep it safe (vault/HSM/hardware token). It never
# leaves the operator's machine.
openssl ecparam -name prime256v1 -genkey -noout -out operator.key

# Public key — this is what CDS pins.
openssl ec -in operator.key -pubout -out operator.pub
```

Pin the public key(s) on CDS at install time (writes stay disabled until you do;
concatenate several `operator.pub` blocks into one file to authorize multiple
operators):

```sh
c8s install --operator-keys operator.pub   # plus your other install flags
```

Installing **without** `--operator-keys` leaves allowlist writes disabled (nobody
can use `c8s allowlist` add/remove/upload), so `c8s install` refuses it on the
default path unless you pass `--force` to acknowledge.

If you set `cds.operatorKeys` yourself (a values file, a Flux HelmRelease, or
helm `--set-file`), the value is the PEM **content**, never a file path — the
chart fails the render otherwise. `c8s render-values --operator-keys
operator.pub` embeds the content for GitOps consumers.

Supply the operator key to the CLI by flag (`--operator-key`) or environment
(`C8S_OPERATOR_KEY`); the flag wins.

`c8s cds verify` reports the fingerprints of the keys a CDS actually pins
(fetched over a connection bound to the attested serving cert). Compare against
your local key with:

```sh
openssl pkey -pubin -in operator.pub -outform DER | sha256sum
```

The key list is CDS-reported config — it is **not** covered by the launch
measurement (see `docs/pitfalls.md`).

**Revocation is coarse (stop-gap):** operator keys are long-lived and CDS
consults no CRL/OCSP, so revoking an operator means removing its public key from
`cds.operatorKeys` and re-installing. The pinned-key list is also host-supplied
config that is only read at CDS start and is not yet in CDS's attestation — see
[`docs/pitfalls.md`](docs/pitfalls.md). A CA + operator certificates (with
single-file cert+key credentials and CA-based revocation) is the planned
improvement; see [`docs/decisions`](docs/decisions/) and `docs/GAPS.md`.

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
