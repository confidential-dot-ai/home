# c8s operator and Helm chart

The c8s operator installs the Kubernetes-facing c8s components. It hosts
status-mirror controllers, serves the pod-injection admission webhook, and
ships an embedded Helm chart for installing the operator, CRDs, RBAC, webhook
resources, attestation-service DaemonSet, and optional Assam.

## Overview

The operator tree is built around these pieces:

- `cmd/c8s operator` runs the controller-runtime manager, the
  `ConfidentialWorkload` status-mirror controller, and the pod-injection
  admission webhook.
- `cmd/c8s install` extracts the embedded chart from `internal/helmchart`
  and shells out to `helm upgrade --install`.
- `internal/helmchart/c8s` installs the operator Deployment and Service, the
  CRDs, RBAC, optional webhook configuration, and an attestation-service
  DaemonSet. It can also install Assam and cert-issuer when
  `assam.enabled=true` and `certIssuer.enabled=true`.
- `internal/webhook` injects an init container into opted-in pods so each
  workload can fetch a leaf certificate through Assam.

The operator does not inject the RA-TLS mesh sidecar. Pod-to-pod mTLS remains
the responsibility of the node-level `ratls-mesh` DaemonSet.

## Ownership model

Installing the c8s chart is a platform-admin operation, not a fully
self-service application-team workflow.

The install creates or updates cluster-scoped resources such as CRDs, RBAC,
the operator Deployment, the webhook Service and configuration, and the
attestation-service DaemonSet. Enabling injection also requires platform-owned
prerequisites:

- an Assam endpoint reachable from workload pods;
- if chart-managed Assam is enabled, a cert-issuer URL, whitelist storage and
  admin secret handling, and an explicit decision about whether this deployment
  is inside the production trust boundary;
- if chart-managed cert-issuer is enabled, a Secret-backed mesh CA bootstrap
  and an explicit decision that this is acceptable for the environment;
- nodes with the expected TEE device access for attestation-service;
- permission for Helm to create workload auth Secrets in any namespaces listed
  under `webhook.apiKeySecret.createInNamespaces`;
- those workload namespaces must already exist, or be created by the platform
  before rendering the chart.

After the platform installs those pieces, workload opt-in is self-service:
application teams annotate their pod templates with `confidential.ai/cw` and,
optionally, `confidential.ai/td`. The `td` suffix means trust domain.

## Code layout

The main source directories are:

| Path | Purpose |
|---|---|
| `cmd/c8s/` | User-facing operator and install CLI commands. |
| `internal/controller/` | controller-runtime manager, webhook bootstrap, and status mirror setup. |
| `internal/webhook/` | Pod mutation logic, init container args, SecretRef auth, cert volume permissions, and unit tests. |
| `internal/helmchart/c8s/` | Embedded Helm chart templates and defaults. |
| `internal/helmchart/chart_test.go` | Helm render tests for default behavior, Assam gating, SecretRef auth, and scoped workload Secrets. |
| `cmd/get-cert/` | Init-container certificate fetcher, including private-key file mode handling and API-key environment fallback. |

## Default install behavior

The chart is intentionally conservative by default:

- `webhook.enabled` defaults to `false`.
- If the webhook is enabled, either `assam.url` or `assam.enabled=true` is
  required at template time.
- The chart deploys the attestation-service DaemonSet, but it does not deploy
  Assam unless `assam.enabled=true`, and it does not deploy cert-issuer unless
  `certIssuer.enabled=true`.
- `image.tag` or `image.digest`, `attestationService.image.tag` or
  `attestationService.image.digest`, and, when enabled, `assam.image.tag` or
  `assam.image.digest` and `certIssuer.image.tag` or
  `certIssuer.image.digest` are required; the CLI passes its build version when
  running `c8s install`. Unstamped local builds report version `dev`, and the
  install CLI maps that to the `latest` image tag because CI does not publish
  `dev`.

This means a default platform install creates the operator, CRDs, RBAC, and
attestation-service without mutating application workloads. `c8s install
--install-crds=false` passes Helm's `--skip-crds`; CRDs are advisory and not
required for pod injection. That path also disables the CRD-backed status
mirror controller; if CRDs are absent at runtime, the operator skips that
controller rather than failing startup. Injection is an explicit platform
follow-up after Assam is reachable. Once injection is enabled, application teams
can opt workloads in by annotation.

Enable injection with Helm values:

```yaml
webhook:
  enabled: true

assam:
  url: http://assam.c8s-system.svc:8080
```

Or with the install CLI:

```bash
c8s install \
  --enable-webhook \
  --assam-url http://assam.c8s-system.svc:8080
```

## Chart-managed Assam

`assam.enabled` defaults to `false`. The default production posture is to point
the webhook at an Assam/CDS endpoint that the platform already operates inside
the intended c8s trust boundary:

```yaml
webhook:
  enabled: true

assam:
  url: http://assam.c8s-system.svc:8080
```

When `assam.enabled=true`, the chart installs an Assam Deployment, Service,
ServiceAccount, admin-password Secret, and either an `emptyDir` whitelist DB or
a PVC when `assam.persistence.enabled=true`. The operator then injects pods
with the chart-managed Assam Service URL, so `assam.url` can be omitted.
If both `assam.url` and `assam.enabled=true` are set, `assam.url` remains an
explicit override for the injected endpoint.

Chart-managed Assam is useful for bootstrap/dev and for platforms that
deliberately run Assam as part of their attested infrastructure. It is not, by
itself, the complete whitepaper production security model. For production
guarantees, Assam/CDS must run inside the attested trust boundary; whitelist
state, signing material, admin credentials, and recovery procedures must not
depend only on ordinary Kubernetes Secret/PV confidentiality.

Minimal chart-managed Assam + cert-issuer values:

```yaml
webhook:
  enabled: true

assam:
  enabled: true

certIssuer:
  enabled: true
```

Equivalent install CLI:

```bash
c8s install \
  --enable-webhook \
  --install-assam
```

When `--install-assam` is used without `--assam-cert-issuer-url`, the install
CLI also enables chart-managed cert-issuer and bootstraps a mesh CA Secret.
Set `--assam-cert-issuer-url` to use an external cert-issuer instead.

The chart-managed Assam manifest deliberately injects
`C8S_ATTESTATION_SERVICE_API_KEY` and
`C8S_ASSAM_WHITELIST_ADMIN_PASSWORD` from Secrets instead of serializing those
values as process arguments.

## Chart-managed cert-issuer

`certIssuer.enabled` defaults to `false`. When enabled with chart-managed Assam,
cert-issuer validates EAR JWTs through Assam's JWKS endpoint:

```yaml
assam:
  enabled: true

certIssuer:
  enabled: true
```

The chart creates or reuses a mesh CA Secret with `mesh-ca.crt` and
`mesh-ca.key`, plus a ConfigMap containing `ca.pem`. The generated key is ECDSA
so it matches cert-issuer's key loader. Existing Secrets are reused on Helm
upgrades via `lookup`; fresh keys are generated only when no existing Secret or
explicit `certIssuer.ca.certPEM` / `certIssuer.ca.keyPEM` values are present.

This is a bootstrap/demo path. The mesh CA key is readable by cluster-admins
and any principal granted read access to that Secret. The production direction
is the CDS-shaped in-CVM key model described in `docs/THREAT_MODEL.md` and
`docs/GAPS.md`.

## Injection contract

The webhook only reads pod metadata. A `ConfidentialWorkload` CR is not
required for injection.

Opt a pod template in with:

```yaml
metadata:
  annotations:
    confidential.ai/cw: api
    confidential.ai/td: default
```

`confidential.ai/cw` is required and becomes the certificate SAN. The
`confidential.ai/td` annotation is optional, defaults to `default`, and is the
trust-domain selector passed to the init container as `C8S_TRUST_DOMAIN`.
Injection does not require a `TrustDomain` CR lookup; it only copies the
selected trust-domain name from pod metadata.

For opted-in pods, the webhook:

- adds an in-memory `emptyDir` volume named `c8s-certs`;
- mounts that volume read-only into application containers at
  `/etc/c8s/certs`;
- prepends a `c8s-init-cert` init container that runs the `get-cert` subcommand;
- stamps `confidential.ai/c8s-injected=true` to make reinvocation a no-op.

The init container runs:

```bash
get-cert \
  --assam-url=<assam.url> \
  --attestation-service-url=<release-attestation-service-url> \
  --san=<confidential.ai/cw> \
  --out=/etc/c8s/certs/tls.crt \
  --key-out=/etc/c8s/certs/tls.key \
  --key-mode=<webhook.certVolume.keyMode>
```

## Attestation-service auth

The chart-managed attestation-service runs in hosted mode, so protected
endpoints are gated by API keys.

The operator no longer reads the API key and serializes it into every mutated
Pod spec. Instead, the injected init container gets
`C8S_ATTESTATION_SERVICE_API_KEY` from a workload-namespace `SecretKeyRef`.
That avoids exposing a cluster-wide key to anyone who can `get pods` in an
application namespace.

Relevant values:

```yaml
webhook:
  apiKeySecret:
    name: ""
    key: apiKey
    createInNamespaces: []
```

If `name` is empty, the injected Secret name defaults to the chart-managed
attestation-service API-key Secret name. That Secret only exists in the release
namespace unless copied or created elsewhere.

For chart-managed per-namespace workload keys, set:

```yaml
webhook:
  apiKeySecret:
    name: c8s-workload-attestation
    key: token
    createInNamespaces:
      - tenant-a
      - tenant-b
```

The chart will create one Secret per listed namespace and add each generated
key to the attestation-service `api_keys` allowlist.

The install CLI exposes the same path:

```bash
c8s install \
  --enable-webhook \
  --assam-url http://assam.c8s-system.svc:8080 \
  --attestation-secret-name c8s-workload-attestation \
  --attestation-secret-key token \
  --workload-namespace tenant-a \
  --workload-namespace tenant-b
```

## Certificate file permissions

`get-cert` writes the private key with the mode passed by `--key-mode`. The
webhook default is `0640`, and it sets `fsGroup: 65532` on injected pods that
do not already define an `fsGroup`. This lets application containers running
as a different non-root UID read `tls.key` through the shared group.

Relevant values:

```yaml
webhook:
  certVolume:
    fsGroup: 65532
    keyMode: "0640"
  initContainer:
    runAsUser: 65532
    runAsGroup: 65532
    runAsNonRoot: true
```

Set `webhook.certVolume.fsGroup` to `-1` to disable pod `fsGroup` mutation.
The webhook preserves an existing pod `fsGroup`.

For Kata deployments that require UID 0 inside the guest, set
`webhook.initContainer.runAsUser=0`, `webhook.initContainer.runAsGroup=0`, and
`webhook.initContainer.runAsNonRoot=false`. The install CLI exposes those as
`--webhook-init-run-as-user`, `--webhook-init-run-as-group`, and
`--webhook-init-run-as-non-root=false`.

The injected init container also uses a locked-down security context:

- `allowPrivilegeEscalation: false`
- `readOnlyRootFilesystem: true`
- `runAsNonRoot: true` by default
- drops all Linux capabilities
- `seccompProfile: RuntimeDefault`

## Validation

Run the full Go suite:

```bash
go test ./...
```

Run the chart tests only:

```bash
go test ./internal/helmchart
```

Run Helm lint:

```bash
helm lint internal/helmchart/c8s \
  --set image.tag=latest \
  --set attestationService.image.tag=latest \
  --set assam.image.tag=latest
```

Render the chart defaults. The output should not include a
`MutatingWebhookConfiguration`, `--operator-image`, `--assam-url`, or a literal
`C8S_ATTESTATION_SERVICE_API_KEY` environment variable:

```bash
helm template c8s internal/helmchart/c8s \
  --namespace c8s-system \
  --set image.tag=latest \
  --set attestationService.image.tag=latest \
  --set assam.image.tag=latest
```

Verify webhook enablement requires Assam:

```bash
helm template c8s internal/helmchart/c8s \
  --namespace c8s-system \
  --set image.tag=latest \
  --set attestationService.image.tag=latest \
  --set assam.image.tag=latest \
  --set webhook.enabled=true
```

That command should fail with:

```text
assam.url must be set when webhook.enabled=true unless assam.enabled=true
```

Render enabled injection with chart-managed Assam:

```bash
helm template c8s internal/helmchart/c8s \
  --namespace c8s-system \
  --set image.tag=latest \
  --set attestationService.image.tag=latest \
  --set assam.image.tag=latest \
  --set webhook.enabled=true \
  --set assam.enabled=true \
  --set-string assam.certIssuerURL=http://cert-issuer.c8s-system.svc:8090
```

The rendered manifests should include:

- an Assam Deployment, Service, ServiceAccount, and admin Secret;
- the operator arg `--assam-url=http://c8s-assam.c8s-system.svc:8080`;
- Assam SecretRef environment variables for attestation-service auth and the
  whitelist admin password;
- `confidential.ai/trust-boundary-warning` annotations on the chart-managed
  Assam resources.

Render enabled injection with scoped workload auth:

```bash
helm template c8s internal/helmchart/c8s \
  --namespace c8s-system \
  --set image.tag=latest \
  --set attestationService.image.tag=latest \
  --set assam.image.tag=latest \
  --set webhook.enabled=true \
  --set-string assam.url=http://assam.c8s-system.svc:8080 \
  --set-string webhook.apiKeySecret.name=c8s-workload-attestation \
  --set-string webhook.apiKeySecret.key=token \
  --set 'webhook.apiKeySecret.createInNamespaces={tenant-a,tenant-b}'
```

The rendered manifests should include:

- operator args for `--assam-url`, `--attestation-service-api-key-secret-*`,
  `--cert-fs-group`, `--cert-key-mode`, and init-container UID/GID/non-root
  settings;
- workload-auth Secrets in `tenant-a` and `tenant-b`;
- the generated workload keys included in the attestation-service allowlist.
