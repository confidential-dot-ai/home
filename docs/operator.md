# c8s operator and Helm chart

The c8s operator installs the Kubernetes-facing c8s components. It hosts
status-mirror controllers, serves the pod-injection admission webhook, and
ships an embedded Helm chart for installing the operator, CRDs, RBAC, webhook
resources, attestation-service DaemonSet, Assam, and cert-issuer.

## Overview

The operator tree is built around these pieces:

- `cmd/c8s operator` runs the controller-runtime manager, the
  `ConfidentialWorkload` status-mirror controller, and the pod-injection
  admission webhook.
- `cmd/c8s install` extracts the embedded chart from `internal/helmchart`
  and shells out to `helm upgrade --install`.
- `internal/helmchart/c8s` installs the operator Deployment and Service, the
  CRDs, RBAC, webhook configuration, attestation-service DaemonSet, Assam, and
  cert-issuer.
- `internal/webhook` injects get-cert containers into opted-in pods so each
  workload can fetch and renew a leaf certificate through Assam.

The operator does not inject the RA-TLS mesh sidecar. Pod-to-pod mTLS remains
the responsibility of the node-level `ratls-mesh` DaemonSet. The chart-managed
mesh excludes `kube-system` and its own release namespace as local traffic
sources, so c8s control-plane agents (and, on kind/kubeadm-style clusters where
the API server runs as a `kube-system` pod, in-cluster webhook callers) do not
get captured by the pod-to-pod mesh path. The exclusion is one-sided: it
removes those pods as PREROUTING sources but keeps their IPs in the destination
ipset, so a workload that connects to a `kube-system` or release-namespace pod
by pod IP — bypassing the Service VIP — will still be DNATed into the mesh and
fail mTLS against a peer with no ratls sidecar. In-cluster Service-VIP traffic
to those namespaces is unaffected because kube-proxy DNATs the VIP before the
mesh chain matches.

## Ownership model

Installing the c8s chart is a platform-admin operation, not a fully
self-service application-team workflow.

The install creates or updates cluster-scoped resources such as CRDs, RBAC,
the operator Deployment, the webhook Service and configuration, and the
attestation-service DaemonSet. Enabling injection also requires platform-owned
prerequisites:

- the chart-managed Assam Service reachable from workload pods;
- whitelist storage and a measurement resource map for any workload allowed to
  mutate the whitelist;
- a cert-issuer public-bundle PVC for CA continuity;
- nodes with the expected TEE device access for attestation-service;

After the platform installs those pieces, workload opt-in is self-service:
application teams annotate their pod templates with `confidential.ai/cw`.

## Code layout

The main source directories are:

| Path | Purpose |
|---|---|
| `cmd/c8s/` | User-facing operator and install CLI commands. |
| `internal/controller/` | controller-runtime manager, webhook bootstrap, and status mirror setup. |
| `internal/webhook/` | Pod mutation logic, get-cert args, cert volume permissions, and unit tests. |
| `internal/helmchart/c8s/` | Embedded Helm chart templates and defaults. |
| `internal/helmchart/chart_test.go` | Helm render tests for the supported chart-managed CVM-only shape. |
| `cmd/get-cert/` | Certificate bootstrap and renewal helper, including private-key file mode handling. |

## Default install behavior

The supported chart shape is chart-managed and CVM-only. The chart does not
support a non-CVM install shape or a bring-your-own Assam/cert-issuer endpoint
shape.

- The chart renders webhook, attestation-service, Assam, and cert-issuer
  together.
- The webhook is wired to the chart-managed Assam Service.
- Assam is wired to the chart-managed cert-issuer Service.
- cert-issuer validates EAR JWTs through chart-managed Assam's JWKS endpoint.
- whitelist admin is EAR-authorized through Assam; the chart does not render an
  Assam whitelist password or attestation-service API key into Kubernetes
  Secrets.
- `image.tag` or `image.digest`, `attestationService.image.tag` or
  `attestationService.image.digest`, `assam.image.tag` or
  `assam.image.digest`, and `certIssuer.image.tag` or
  `certIssuer.image.digest` are required; the CLI passes its build version when
  running `c8s install`. Unstamped local builds report version `dev`, and the
  install CLI maps that to the `latest` image tag because CI does not publish
  `dev`.

This means a default platform install creates the operator, CRDs, RBAC,
webhook, attestation-service, Assam, and cert-issuer. It does not mutate
application workloads until those workloads opt in with
`confidential.ai/cw`.

Install with the CLI:

```bash
c8s install
```

`c8s install --install-crds=false` passes Helm's `--skip-crds`; CRDs are
advisory and not required for pod injection. That path also disables the
CRD-backed status mirror controller; if CRDs are absent at runtime, the
operator skips that controller rather than failing startup.

## Kata runtime installation and enforcement

`c8s install --kata` additionally installs the Kata Containers runtime onto
the cluster: the embedded chart renders the upstream `kata-deploy` DaemonSet
(which installs QEMU, the kata runtime, and the `containerd-shim-kata-v2`
shim onto every node) and the `kata-qemu` / `kata-clh` / `kata-qemu-snp`
RuntimeClass objects. `--distro` (`k8s` or `rke2`) selects the host
containerd config path.

`c8s install --kata-enforce` also turns on enforcement (it implies `--kata`):

- the operator's pod webhook injects a `runtimeClassName` into workload pods
  that don't request one — `kata-qemu`, or `kata-qemu-snp` for pods annotated
  `confidential.ai/cw`;
- a `ValidatingAdmissionPolicy` rejects workload pods that request a non-kata
  `runtimeClassName`.

Host-namespace pods and system namespaces are exempt. The Kata stack is off
by default — a plain `c8s install` is unchanged.

See [`docs/kata.md`](kata.md) for the design (why it wraps upstream
kata-deploy), the threat model, distro support, the one-shot bootstrap-window
caveat, and the SEV-SNP-host / GPU constraints.

## Chart-managed Assam

The supported deployment is chart-managed Assam plus cert-issuer running inside
the intended CVM trust boundary.

The chart installs an Assam Deployment, Service, ServiceAccount, and either an
`emptyDir` whitelist DB or a PVC when `assam.persistence.enabled=true`. The
operator injects pods with the chart-managed Assam Service URL. Whitelist
writes use `Authorization: Bearer <EAR>`. Assam accepts `POST /whitelist` and
`DELETE /whitelist` only when the EAR was issued by Assam and the requester's
normalized launch measurement is allowed for `assam/whitelist-write` in
`assam.resourceMap`.

Internal Assam, cert-issuer, and CA-bundle refresh traffic uses chart-managed
cluster Services. Trust for those flows comes from EAR validation, measurement
allowlists, and CA continuity checks rather than WebPKI on the Service hop.

Minimal whitelist-write values:

```yaml
assam:
  resourceMap:
    "<sha384-launch-measurement>":
      - assam/whitelist-write
```

## Chart-managed cert-issuer

Cert-issuer validates EAR JWTs through chart-managed Assam's JWKS endpoint.

The chart does not render a CA private key into a Kubernetes Secret. Cert-issuer
generates its mesh CA key inside the process, keeps it in memory, and persists
only the public CA bundle in the configured public-bundle PVC.

### Operational warning: cert-issuer is a singleton until handoff is enabled

By default, cert-issuer runs as a single replica with the in-memory mesh CA
key, and **any restart is a full re-bootstrap event**: the replacement pod
generates a fresh CA whose public key is not signed by anything ratls-mesh
already trusts. `pkg/ratls/assamclient`'s continuity check then refuses the
new CA on the next `/ca` poll, cert-issuer keeps signing leaves with the
new key, no workload trusts them, and the mesh degrades as old leaves
expire. Recovery is to restart every workload so its get-cert init container
re-runs the Assam provisioning flow.

Scheduled in-process CA rotation (`--ca-rotation-interval`) is **not** a
re-bootstrap: the rotator signs the new CA with the still-live current
CA's key, the continuity check accepts it, and workloads pick it up on
their next `/ca` refresh. Only restart loses the signing key.

To remove this restriction, enable in-process handoff bootstrap by setting
`certIssuer.handoff.enabled=true` in values and pinning
`certIssuer.measurements` to cert-issuer's launch digest. The chart
auto-injects the `cert-issuer/handoff` entry into the rendered
resourceMap from those measurements (so the value is set in one place,
not two); enabling handoff without measurements fails chart render. With
that flag set, cert-issuer generates an ECDSA handoff signer key in process
at startup and exchanges it for an Assam-issued EAR via Assam's
`/attest-key` endpoint (over the H1 RA-TLS channel). No operator key file
or Kubernetes Secret is rendered — the alternative would put CA-adjacent
material into etcd, which the chart-managed CVM design forbids.

Until handoff is enabled:

- run cert-issuer with `replicas: 1` and `strategy: Recreate` (default in
  this chart);
- guard the cert-issuer Deployment with a PodDisruptionBudget that blocks
  voluntary disruptions;
- treat any cert-issuer restart as a planned maintenance event with workload
  churn;
- monitor the `cert_ca_fingerprint_info{fingerprint=…}` metric — a
  fingerprint change without a planned rotation means a restart happened
  and workload re-provisioning is needed.

After enabling handoff, verify the bootstrap succeeded by checking
cert-issuer logs for `attested CA handoff enabled` and
`handoff EAR refreshed` lines. Failures will be logged at warn-level
without crashing the binary; the handoff handler stays unregistered and the
restart-fragility window above applies until the operator fixes the
underlying issue.

## Injection contract

The webhook only reads pod metadata. A `ConfidentialWorkload` CR is not
required for injection. For tls-lb pods in the c8s release namespace, the
chart uses a dedicated webhook entry selected by the chart's existing
`app.kubernetes.io/name=tls-lb` and release instance labels. That avoids
sending every platform pod to the webhook during bootstrap while still ensuring
tls-lb cannot silently start if its c8s annotation set is partially rendered or
invalid.

Opt a pod template in with:

```yaml
metadata:
  annotations:
    confidential.ai/cw: api
```

`confidential.ai/cw` is required and becomes the certificate SAN. Injection
does not require a CR lookup.

For opted-in pods, the webhook:

- adds an in-memory `emptyDir` volume named `c8s-certs`;
- mounts that volume read-only into application containers at
  `/etc/c8s/certs`;
- prepends a `c8s-init-cert` init container that fetches the first cert before
  application containers start;
- adds a native `c8s-renew-cert` sidecar init container that refreshes
  `tls.crt` every `webhook.getCert.renewInterval`;
- stamps `confidential.ai/c8s-injected=true` to make reinvocation a no-op.

The init container runs:

```bash
get-cert \
  --assam-url=http://<release>-assam.<namespace>.svc:8080 \
  --attestation-service-url=<release-attestation-service-url> \
  --san=<confidential.ai/cw> \
  --out=/etc/c8s/certs/tls.crt \
  --key-out=/etc/c8s/certs/tls.key \
  --key-mode=<webhook.certVolume.keyMode>
```

The renewal sidecar runs the same flow with `--key=/etc/c8s/certs/tls.key`,
`--renew-interval=<webhook.getCert.renewInterval>`, and
`--reload-nginx=false`. It renews the file on disk; application-level TLS
reload remains the workload's responsibility unless the pod opts into one of
the c8s reload annotations.

Platform-owned workloads can specialize the same webhook behavior with typed
c8s annotations for the cert volume, cert/key filenames, renewal interval,
nginx reload, Secret watch paths, discovery output, and get-cert UID/GID. The
tls-lb chart uses those annotations to keep its PKI volumes and nginx config in
the chart while dogfooding the webhook-injected get-cert containers. The
webhook rejects incomplete reload-watch or discovery annotation sets during pod
admission instead of admitting a pod that cannot serve its configured
certificate/discovery path.

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
  getCert:
    renewInterval: 6h
    runAsUser: 65532
    runAsGroup: 65532
    runAsNonRoot: true
```

Set `webhook.certVolume.fsGroup` to `-1` to disable pod `fsGroup` mutation.
The webhook preserves an existing pod `fsGroup`.

For Kata deployments that require UID 0 inside the guest, set
`webhook.getCert.runAsUser=0`, `webhook.getCert.runAsGroup=0`, and
`webhook.getCert.runAsNonRoot=false`. The install CLI exposes those as
`--webhook-get-cert-run-as-user`, `--webhook-get-cert-run-as-group`, and
`--webhook-get-cert-run-as-non-root=false`. The renewal interval is exposed as
`--webhook-get-cert-renew-interval`.

The injected get-cert containers also use a locked-down security context:

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
  --set assam.image.tag=latest \
  --set certIssuer.image.tag=latest
```

Render the chart defaults. The output should include the chart-managed Assam
and cert-issuer Services wired through the operator and Assam args:

```bash
helm template c8s internal/helmchart/c8s \
  --namespace c8s-system \
  --set image.tag=latest \
  --set attestationService.image.tag=latest \
  --set assam.image.tag=latest \
  --set certIssuer.image.tag=latest
```

Render the supported shape with a whitelist-write allowlist:

```bash
helm template c8s internal/helmchart/c8s \
  --namespace c8s-system \
  --set image.tag=latest \
  --set attestationService.image.tag=latest \
  --set assam.image.tag=latest \
  --set certIssuer.image.tag=latest \
  --set 'assam.resourceMap.<sha384-launch-measurement>[0]=assam/whitelist-write'
```

The rendered manifests should include:

- an Assam Deployment, Service, ServiceAccount, and resource-map ConfigMap;
- the operator arg `--assam-url=http://c8s-assam.c8s-system.svc:8080`;
- no Assam admin-password Secret and no attestation-service API-key Secret;
- `confidential.ai/trust-boundary-warning` annotations on the chart-managed
  Assam resources.
