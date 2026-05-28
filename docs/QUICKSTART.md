# c8s quickstart

This is the supported install path for the consolidated c8s chart.

## Prerequisites

- A Kubernetes cluster with platform-admin permissions.
- Helm 3.
- c8s images published with the same tag as the release, for example `v0.1.0`,
  or explicit image digests supplied in a values file.
- Nodes with the TEE device shape expected by `attestationService.teeDevices`.

## Install c8s

This installs the supported chart-managed CVM shape: operator, RBAC, CRDs,
webhook, attestation-service, and CDS.

```sh
c8s install --namespace c8s-system
```

`c8s install` passes the CLI build version as the chart image tag. Official
release images are tagged with the literal Git tag, for example `v0.1.0`.
Unstamped local builds report version `dev`; for that path, `c8s install` uses
the `latest` image tag because CI does not publish `dev`.

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
