# c8s quickstart

This is the supported install path for the consolidated c8s chart.

## Prerequisites

- A Kubernetes cluster with platform-admin permissions.
- Helm 3 and `kubectl` on PATH, plus `crane` (digest resolution is on by
  default; not needed if you pass `--resolve-digests=false`).
- c8s images published with the same tag as the release, for example `v0.1.0`,
  resolved to digests by default or supplied in a values file.
- One node labelled to run CDS (`role=cds` by default).
- Nodes with the TEE device shape expected by `attestationApi.teeDevices`.

## Install c8s

This installs the supported chart-managed CVM shape: operator, RBAC, CRDs,
webhook, attestation-api, and CDS.

```sh
c8s install --namespace c8s-system --workload-ref vllm=<namespace>/deployment/<vllm-deployment>:8000 --upstream vllm
```

tls-lb ships no default upstream: `--upstream` (with the port on its
`--workload-ref`) points tls-lb at an adopted workload's mesh-wrapped headless Service.
Without an upstream choice, tls-lb renders no catch-all route until one is
attached rather than shipping an unencrypted inference hop. Alternatives and details: the
[Upstream](operator.md#tls-lb-upstream).

For existing workloads, use `--workload-ref <cw-id>=<namespace>/<kind>/<name>` so install
adopts them as CWs and resolves their images into the NRI bootstrap allowlist.
Details and the vLLM router/engine example: [existing workload adoption](operator.md#existing-workload-adoption).

By default `c8s install` resolves each component image tag to its registry
digest (via `crane`) and pins it. The image policy admits c8s components by
digest, so this is what lets a plain install satisfy the floor: without pinned
digests the render fails closed rather than ship a cluster whose own components
its image policy would deny. `crane` must be on PATH. To pin the digests
yourself instead, pass `--resolve-digests=false` and supply them via
`-f values.yaml`.

Label the node that will run CDS so the chart's default `role: cds` selector
matches (override `cds.node.selector` for a different label):

```sh
kubectl label node <cds-node> role=cds
```

`c8s install` passes the CLI build version as the chart image tag, but only when
it is a release tag (for example `v0.1.0`), the version CI publishes a matching
image for. Any other build (a local `git describe` derivative, a commit SHA, or
the unstamped default) falls back to the `main` branch tag, the only other tag
every component publishes.

The chart itself is versioned separately. CI publishes it to
`oci://ghcr.io/confidential-dot-ai/charts` under a SemVer chart version (`1.2.3` for a
release tag, `<Chart.yaml version>-g<short-sha>` for a `main` build), never a
`main` tag, because Helm chart versions must be SemVer. The chart carries no
default image tag of its own, so the image tag above is supplied by
`c8s install` rather than baked into the published chart.

To install without the advisory CRDs:

```sh
c8s install --namespace c8s-system --install-crds=false \
  --workload-ref vllm=<namespace>/deployment/<vllm-deployment>:8000 --upstream vllm
```

The cluster still runs without CRDs. CRDs only provide demo/status UX such as
`kubectl get cwl`; pod injection is driven by pod annotations. In this mode the
status-mirror controller is disabled.

## Private registry credentials

When the c8s images (or your mirrors of them) live in a registry that requires
authentication, create a registry-credential Secret in the release namespace
and pass its name at install time:

```sh
kubectl create namespace c8s-system
kubectl create secret docker-registry ghcr-pull-secret \
  -n c8s-system \
  --docker-server=ghcr.io \
  --docker-username=<user-or-x-access-token> \
  --docker-password="$GITHUB_TOKEN"

c8s install --namespace c8s-system --image-pull-secret ghcr-pull-secret \
  --workload-ref vllm=<namespace>/deployment/<vllm-deployment>:8000 --upstream vllm
```

`scripts/deploy-image-pull-secret.sh` wraps the secret-creation step
idempotently (re-run it to rotate the credential in place):

```sh
IMAGE_PULL_SECRET=<ghcr-token> NAMESPACE=c8s-system ./scripts/deploy-image-pull-secret.sh
c8s install --namespace c8s-system --image-pull-secret ghcr-pull-secret \
  --workload-ref vllm=<namespace>/deployment/<vllm-deployment>:8000 --upstream vllm
```

Pass `NAMESPACE=c8s-system` explicitly — the script defaults to `default`,
and `imagePullSecrets` references are namespace-local, so a Secret there is
invisible to the c8s pods.

The chart appends the Secret to every component's `imagePullSecrets` —
including components that set their own local list — so all pods authenticate
from their first start: no Secret references to patch in afterwards, no pods
to bounce. The install fails fast if the named Secret is missing from the
namespace or is not a registry-credential type
(`kubernetes.io/dockerconfigjson`). Helm-values consumers (e.g. a fleet
HelmRelease) get the same behavior by setting `imagePullSecret`.

The chart never creates or adopts the Secret itself, so it works equally with
a kubectl-created Secret, external-secrets, or a previous manual rollout, and
rotating the credential is a plain Secret update with no helm interaction.

Note this is the cluster-side (kubelet) credential: `--resolve-digests` runs
`crane` on your workstation and uses your local docker login, not this
Secret.

Under `--cvm-mode=pod`, the same Secret also feeds the kata-image-puller's in-pod
`oras pull` of the kata-guest-base artifact, which reads
`/root/.docker/config.json` rather than kubelet pull secrets (set
`kata.guestImage.pullerAuthSecret` if that artifact needs a different
credential). The one pull this does **not** cover (see docs/pitfalls.md):
guest-side workload image pulls inside kata CVMs
(`agent.image_registry_auth`).

On kata clusters, also raise kubelet's `runtime-request-timeout` (default
2 m): the effective ceiling on kata pod creation is `min(kubelet timeout,
kata timeout)`, and a slow path — cold registry, a multi-GB model image
guest-pulled inside the VM — hits the 2 m wall with the cause hidden. RKE2:
`kubelet-arg: runtime-request-timeout=20m` in `/etc/rancher/rke2/config.yaml`.
Details: docs/pitfalls.md "kubelet's runtime-request-timeout".

## Certificate path

The chart wires workload injection to chart-managed CDS. CDS generates its
mesh CA key in process memory and persists only the public CA bundle. The
persisted bundle lets already-issued leaves keep verifying across CDS
restarts; it does not preserve issuance — a restart generates a new CA key,
and workloads must re-bootstrap to trust new leaves. See docs/operator.md
for the singleton-vs-handoff trade-off. Run this chart inside the intended
CVM trust boundary; the supported chart path no longer has external CDS
URL values.

The chart's RA-TLS handshakes accept any TEE-attested peer unless the
operator pins `cds.measurements` and `ratlsMesh.measurements` to the
expected launch digests. Leave these empty only on a trusted Pod network;
see docs/THREAT_MODEL.md for the threat surface.

## Workload opt-in

Application teams opt in by annotating their pod templates:

```yaml
metadata:
  annotations:
    confidential.ai/cw: api
```

The webhook injects `c8s get-cert` as an init container and renewal sidecar.
They write `tls.crt` and `tls.key` into `/etc/c8s/certs`.

See:

- `docs/DEMO.md` for a minimal demo flow.
- `docs/THREAT_MODEL.md` for what the chart does and does not prove.
- `docs/GAPS.md` for remaining production-readiness gaps.
