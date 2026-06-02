# c8s quickstart

This is the supported install path for the consolidated c8s chart.

## Prerequisites

- A Kubernetes cluster with platform-admin permissions.
- Helm 3 and `kubectl` on PATH, plus `crane` (digest resolution is on by
  default; not needed if you pass `--resolve-digests=false`).
- c8s images published with the same tag as the release, for example `v0.1.0`,
  resolved to digests by default or supplied in a values file.
- One node labelled to run CDS (`role=cds` by default).
- Nodes with the TEE device shape expected by `attestationService.teeDevices`.

## Install c8s

This installs the supported chart-managed CVM shape: operator, RBAC, CRDs,
webhook, attestation-service, and CDS.

```sh
c8s install --namespace c8s-system
```

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
`oci://ghcr.io/lunal-dev/charts` under a SemVer chart version (`1.2.3` for a
release tag, `<Chart.yaml version>-g<short-sha>` for a `main` build), never a
`main` tag, because Helm chart versions must be SemVer. The chart carries no
default image tag of its own, so the image tag above is supplied by
`c8s install` rather than baked into the published chart.

To install without the advisory CRDs:

```sh
c8s install --namespace c8s-system --install-crds=false
```

The cluster still runs without CRDs. CRDs only provide demo/status UX such as
`kubectl get cwl`; pod injection is driven by pod annotations. In this mode the
status-mirror controller is disabled.

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
operator pins `cds.measurements` and `ratls-mesh.measurements` to the
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
