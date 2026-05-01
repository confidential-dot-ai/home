# c8s quickstart

This is the supported install path for the consolidated c8s chart.

## Prerequisites

- A Kubernetes cluster with platform-admin permissions.
- Helm 3.
- c8s images published with the same tag as the release, for example `v0.1.0`,
  or explicit image digests supplied in a values file.
- Nodes with the TEE device shape expected by `attestationService.teeDevices`.

## Install the platform-only control plane

This installs the operator, RBAC, CRDs, and attestation-service. It does not
mutate workloads because the webhook is disabled by default.

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

## Enable the full demo certificate path

For bootstrap and demos, c8s can install Assam and cert-issuer together:

```sh
c8s install \
  --namespace c8s-system \
  --enable-webhook \
  --install-assam \
  --workload-namespace default
```

This creates a chart-managed Assam Deployment, cert-issuer Deployment,
Secret-backed mesh CA, and a workload-namespace API-key Secret. That is
convenient for demos, but it is not the whitepaper production trust model.

For production-shaped deployments, run Assam/CDS and cert signing inside the
attested trust boundary and point c8s at that endpoint:

```sh
c8s install \
  --namespace c8s-system \
  --enable-webhook \
  --assam-url http://assam.c8s-system.svc:8080 \
  --attestation-secret-name c8s-workload-attestation \
  --attestation-secret-key token
```

## Workload opt-in

Application teams opt in by annotating their pod templates:

```yaml
metadata:
  annotations:
    confidential.ai/cw: api
    confidential.ai/td: default
```

The webhook injects `c8s get-cert` as an init container. It writes
`tls.crt`, `tls.key`, and the CA bundle into `/etc/c8s/certs`.

See:

- `docs/DEMO.md` for a minimal demo flow.
- `docs/THREAT_MODEL.md` for what the chart does and does not prove.
- `docs/GAPS.md` for the future CDS-shaped work.
