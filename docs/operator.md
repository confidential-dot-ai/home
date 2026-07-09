# c8s operator and Helm chart

The c8s operator installs the Kubernetes-facing c8s components. It hosts
status-mirror controllers, serves the pod-injection admission webhook, and
ships an embedded Helm chart for installing the operator, CRDs, RBAC, webhook
resources, attestation-api DaemonSet, and CDS (the Certificate
Distribution Service trust root).

## Overview

The operator tree is built around these pieces:

- `cmd/c8s operator` runs the controller-runtime manager, the
  `ConfidentialWorkload` status-mirror controller, and the pod-injection
  admission webhook.
- `cmd/c8s install` extracts the embedded chart from `internal/helmchart`
  and shells out to `helm upgrade --install`.
- `internal/helmchart/c8s` installs the operator Deployment and Service, the
  CRDs, RBAC, webhook configuration, attestation-api DaemonSet, and CDS.
- `internal/webhook` injects get-cert containers into opted-in pods so each
  workload can fetch and renew a leaf certificate through CDS.

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

Confidential-workload pods (label `confidential.ai/cw`) get a stricter
inbound posture from the always-on cw guard: the mesh drops FORWARD-path
traffic to their pod IPs, so Service-VIP dials and excluded-namespace sources
are blocked instead of reaching the workload in plaintext.
`ratlsMesh.cwInboundEnforcement.passthrough` (default `udp:53,tcp:53`) is the
reply allowlist that keeps DNS working; an empty list is strict drop-all.
Only mesh-delivered traffic and node-local host processes
(kubelet probes) reach cw pods.

## Ownership model

Installing the c8s chart is a platform-admin operation, not a fully
self-service application-team workflow.

The install creates or updates cluster-scoped resources such as CRDs, RBAC,
the operator Deployment, the webhook Service and configuration, and the
attestation-api DaemonSet. Enabling injection also requires platform-owned
prerequisites:

- the chart-managed CDS Service reachable from workload pods;
- allowlist storage and a measurement allowlist for any workload allowed to
  mutate the allowlist;
- a CDS public-bundle PVC for CA continuity;
- nodes with the expected TEE device access for attestation-api;

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
support a non-CVM install shape or a bring-your-own CDS endpoint shape.

- The chart renders webhook, attestation-api, and CDS together.
- The webhook is wired to the chart-managed CDS Service.
- CDS verifies evidence, issues EAR tokens, and signs workload CSRs in one
  process; EAR validation and signing share that process, so there is no
  internal Service hop or JWKS fetch between them.
- allowlist admin is EAR-authorized through CDS; the chart does not render a
  CDS allowlist password or attestation-api API key into Kubernetes
  Secrets.
- `image.tag` or `image.digest`, `attestationApi.image.tag` or
  `attestationApi.image.digest`, and `cds.image.tag` or
  `cds.image.digest` are required; the CLI passes its build version when
  running `c8s install`. Unstamped local builds report version `dev`, and the
  install CLI maps that to the `main` branch tag because CI does not publish
  `dev` (and `cds` publishes only `main`, not `latest`).

This means a default platform install creates the operator, CRDs, RBAC,
webhook, attestation-api, and CDS. It does not mutate
application workloads until those workloads opt in with
`confidential.ai/cw`.

Install with the CLI. `--engine` derives tls-lb's mesh-wrapped upstream from
the inference workload's `confidential.ai/cw` id:

```bash
c8s install --engine vllm --engine-workload-id <cw-id>
```

`c8s install --install-crds=false` passes Helm's `--skip-crds`; CRDs are
advisory and not required for pod injection. That path also disables the
CRD-backed status mirror controller; if CRDs are absent at runtime, the
operator skips that controller rather than failing startup.

## Kata runtime installation and enforcement

`c8s install --kata` additionally installs the Kata Containers runtime onto
the cluster: the embedded chart renders the upstream `kata-deploy` DaemonSet
(which installs QEMU, the kata runtime, and the `containerd-shim-kata-v2`
shim onto every node) and the `kata-qemu` / `kata-clh` / `kata-qemu-snp` /
`kata-qemu-tdx` RuntimeClass objects. The host containerd config path (`k8s` vs `rke2`
layout) is detected from the cluster's kubelet versions.

`--kata` is **enforcing** — there is no kata-without-enforcement shape:

- the operator's pod webhook injects a `runtimeClassName` into workload pods
  that don't request one — `kata-qemu`, or `kata-qemu-snp` for pods annotated
  `confidential.ai/cw`;
- a `ValidatingAdmissionPolicy` rejects workload pods that request a non-kata
  `runtimeClassName`;
- the host-side ratls-mesh, attestation-api, and nri-image-policy are
  disabled — their function runs inside the kata-guest-base VM image.

Host-namespace pods and system namespaces are exempt. The Kata stack is off
by default — a plain `c8s install` is unchanged.

See [`docs/kata.md`](kata.md) for the design (why it wraps upstream
kata-deploy), the threat model, distro support, the one-shot bootstrap-window
caveat, and the SEV-SNP-host / GPU constraints.

## Uninstall

`c8s uninstall` reverses `c8s install`. It runs `helm uninstall` to remove the
release (operator, CDS, attestation-api, ratls-mesh, tls-lb, the
webhook configuration, RuntimeClasses, and the enforcement policy). The chart's
`pre-delete` hook deletes the `MutatingWebhookConfiguration` by name first, so a
`failurePolicy: Fail` webhook can never outlive the operator Service and block
pod creation cluster-wide.

For a `--kata` install it then **sweeps the host-side kata artifacts** that the
`kata-deploy` preStop cleanup cannot guarantee: a short-lived privileged
DaemonSet removes `/opt/kata`, the containerd runtime drop-in (restarting the
runtime only when the drop-in was still registered), the pulled
`kata-guest-base` image, the RKE2 containerd-prep template, and the
`katacontainers.io/kata-runtime` node labels. The sweep set and host paths are
read from the release's computed values *before* deletion, so install-time `-f`
overrides are honored; it is skipped automatically for a non-kata install.

Guardrails:

- Uninstall **refuses to run while pods with a kata RuntimeClass are still
  scheduled** — pulling the runtime out from under a confidential workload kills
  it without cleanup. Delete those workloads first, or pass `--force` (the kata
  VMs keep running unmanaged but cannot restart).
- `--host-sweep-only` runs only the kata sweep, for a cluster whose release a
  bare `helm uninstall` already removed but whose nodes still carry artifacts;
  it uses the chart defaults and the distro detected from the cluster.
- `--delete-crds` and `--delete-namespace` are **off by default** and
  destructive: the former deletes the `ConfidentialWorkload` CRD and every
  `ConfidentialWorkload` object with it; the latter deletes the release
  namespace and everything left in it.

Requires the `helm` and `kubectl` CLIs on `PATH`. See
[`docs/install-flows.md`](install-flows.md#uninstall-flow) for the uninstall
sequence (and the `webhook-cleanup` hook) and
[`docs/kata.md`](kata.md#uninstalling) for the host sweep in full.

## Chart-managed CDS

The supported deployment is chart-managed CDS running inside the intended CVM
trust boundary.

The chart installs a CDS Deployment, Service, ServiceAccount, and either an
`emptyDir` allowlist DB or a PVC when `cds.persistence.enabled=true`. The
operator injects pods with the chart-managed CDS Service URL. Allowlist
writes (`POST`, `PUT`, `DELETE /allowlist`) are authorized by an operator key:
the caller presents a short-lived token signed by an operator EC private key
whose public half is pinned in `cds.operatorKeys`. The `c8s allowlist` CLI mints
that token (see the README, "Operator allowlist credentials"). Without
`cds.operatorKeys` set, allowlist writes are rejected while reads keep serving.

CA-bundle refresh traffic uses the chart-managed cluster Service. Trust for
those flows comes from EAR validation, measurement allowlists, and CA
continuity checks rather than WebPKI on the Service hop.

CDS verifies EAR JWTs against its own in-process signer; there is no JWKS
fetch to a separate component. The chart does not render a CA private key into
a Kubernetes Secret. CDS generates its mesh CA key inside the process, keeps it
in memory, and persists only the public CA bundle in the configured
public-bundle PVC.

Minimal allowlist-write values (pin operator public keys):

```yaml
cds:
  operatorKeys: |
    -----BEGIN PUBLIC KEY-----
    ...operator EC public key...
    -----END PUBLIC KEY-----
```

Prefer `c8s install --operator-keys operator.pub`, which reads the file and
sets this value for you. In a GitOps flow, `c8s render-values --operator-keys
operator.pub` embeds the content into the emitted values.

The value is the PEM **content**, never a file path — a path from the machine
that rendered the values is meaningless in-cluster, and the chart fails the
render when the value doesn't look like PEM.

### Operational warning: CDS is a singleton until handoff is enabled

By default, CDS runs as a single replica with the in-memory mesh CA
key, and **any restart is a full re-bootstrap event**: the replacement pod
generates a fresh CA whose public key is not signed by anything ratls-mesh
already trusts. `pkg/ratls/cdsclient`'s continuity check then refuses the
new CA on the next `/ca` poll, CDS keeps signing leaves with the
new key, no workload trusts them, and the mesh degrades as old leaves
expire. Recovery is to restart every workload so its get-cert init container
re-runs the CDS provisioning flow.

There is **no scheduled in-process CA rotation today** — no cds flag or
loop drives it, so every CA fingerprint change is a restart-shaped
re-bootstrap. (An unwired rotator exists at `internal/issuer.CARotator`:
it signs a successor CA with the still-live current CA's key, so the
continuity check would accept it and workloads would pick it up on their
next `/ca` refresh, without re-bootstrap. Wiring it into `c8s cds` is
future work.)

To remove this restriction, enable in-process handoff by setting
`cds.handoff.enabled=true` in values and pinning `cds.measurements` to CDS's
launch digest; the same flat allowlist authorises `/handoff`, and enabling
handoff without measurements fails chart render. With that flag set, CDS
generates an ECDSA handoff signer key in process at startup and
self-provisions its handoff EAR via its own EAR issuer (no external service to
dial). No operator key file or Kubernetes Secret is rendered — the alternative
would put CA-adjacent material into etcd, which the chart-managed CVM design
forbids.

Until handoff is enabled:

- run CDS with `replicas: 1` and `strategy: Recreate` (default in
  this chart);
- guard the CDS Deployment with a PodDisruptionBudget that blocks
  voluntary disruptions;
- treat any CDS restart as a planned maintenance event with workload
  churn;
- watch CDS startup logs for the active CA fingerprint — any fingerprint
  change means a restart happened and workload re-provisioning is needed.

After enabling handoff, verify the bootstrap succeeded by checking
CDS logs for `attested CA handoff enabled` and
`handoff EAR refreshed` lines. Failures will be logged at warn-level
without crashing the binary; the handoff handler stays unregistered and the
restart-fragility window above applies until the operator fixes the
underlying issue.

## Verifying attestation after install

`c8s verify` (and `c8s cds verify`, shorthand for `c8s verify --kind cds`) fetches
a component's TEE attestation evidence — AMD SEV-SNP or Intel TDX — and verifies it
against the hardware signature chain plus a pinned launch measurement. Use it to
confirm CDS — or the load balancer — is a genuine TEE running the expected code
after install.

It verifies **in-process** with `attestation-go` — the Go port of the same
attestation-rs engine the cluster runs. That engine auto-detects the platform and
AMD product, including Zen4c (Siena/Bergamo) which stock `go-sev-guest` cannot
classify. The only requirement on the machine running `c8s verify` is outbound
HTTPS to AMD KDS (`kdsintf.amd.com`), which it uses to fetch the VCEK for a bare
report; no container runtime is needed.

```bash
# CDS's RA-TLS endpoint is reachable by unattested clients, but it runs as a
# locked kata guest: `kubectl port-forward` / `exec` are denied by the guest
# policy (only the --debug guest image enables them), so localhost forwarding
# won't work. Dial the pod IP directly from somewhere with cluster-network reach
# (a node, or over a VPN). c8s-cds is a headless Service, so read its endpoint:
CDS_IP=$(kubectl get endpoints c8s-cds -n c8s-system -o jsonpath='{.subsets[0].addresses[0].ip}')

c8s cds verify "https://$CDS_IP:8443" --measurements <sha384-launch-digest>

# JSON + exit codes for CI:
c8s cds verify "https://$CDS_IP:8443" --measurements-file digests.txt -o json
```

PKI/SAN mismatch when dialing the IP is fine — `verify` trusts the attestation
embedded in the serving cert, not the certificate chain.

The launch digest(s) to pin are the same values discussed under measurement
pinning (kata guest digest via `sev-snp-measure`, or the node CVM digest). They
are enforced client-side against the report's launch measurement; with no
`--measurements` the command still runs but prints an UNSAFE warning — any
genuine TEE is accepted.

Exit codes are a CI contract: `0` verified, `2` verification/policy failed
(e.g. wrong measurement), `3` evidence unavailable (unreachable/unparseable).

Caveats the output surfaces:

- **Freshness.** Verifying an RA-TLS serving cert binds REPORTDATA to the
  certificate key, not a per-request nonce, so it proves "this key was born in a
  TEE with this measurement" but not "freshly now" (`fresh: false`).
- **Reachability under kata.** Reach each component on its public/host address,
  not the in-cluster ClusterIP — the ClusterIP path goes through the mesh and
  demands an attested client cert (`tls: certificate required`). CDS's RA-TLS
  endpoint and the tls-lb's nginx serving port both answer unattested clients on
  their public address (the tls-lb serves `/v1/discovery` there with no client
  cert), so `c8s cds verify` and `c8s verify <lb>` work without any mesh changes.

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

`confidential.ai/cw` is required. The certificate SAN is derived from it: an
id that names the operator-managed headless Service gets that Service's
in-cluster DNS name (`c8s-<id>.<namespace>.svc`, which CDS's default
`--dns-san-pattern` signs); an id that cannot name a Service (dots, length
over 59) is used as the SAN verbatim and must match a CDS pattern itself.
A workload adopted into c8s whose clients already dial an existing Service
name can set `confidential.ai/c8s-san` to that name instead; the annotation
value is used as the requested SAN verbatim and must match a CDS pattern.
Injection does not require a CR lookup.

For opted-in pods, the webhook:

- adds an in-memory `emptyDir` volume named `c8s-certs`;
- mounts that volume read-only into application containers at
  `/etc/c8s/certs`;
- prepends a `c8s-cert` native sidecar (init container with
  `restartPolicy: Always`) that fetches the first cert before application
  containers start and then renews `tls.crt` every
  `webhook.getCert.renewInterval`;
- stamps `confidential.ai/c8s-injected=true` to make reinvocation a no-op.

The sidecar runs:

```bash
get-cert \
  --cds-url=https://<release>-cds.<namespace>.svc:8443 \
  --attestation-api-url=<release-attestation-api-url> \
  --san=<derived from confidential.ai/cw, e.g. c8s-api.default.svc> \
  --out=/etc/c8s/certs/tls.crt \
  --key-out=/etc/c8s/certs/tls.key \
  --key-mode=<webhook.certVolume.keyMode> \
  --renew-interval=<webhook.getCert.renewInterval> \
  --reload-nginx=<from annotation> \
  --continue-on-initial-error
```

`--key-out` is idempotent: on a kubelet restart of the sidecar it reuses the
key that's already on disk, so the previously-issued cert chain stays valid.
A `startupProbe` (`/c8s probe-file /etc/c8s/certs/tls.crt`) gates the
application containers on the initial cert being written. Renewals rewrite
the file on disk; application-level TLS reload remains the workload's
responsibility unless the pod opts into one of the c8s reload annotations.

The sidecar is long-lived rather than a run-once init container because under
kata it doubles as the pidns anchor for `shareProcessNamespace` — see
`docs/kata.md` for the underlying constraint.

Platform-owned workloads can specialize the same webhook behavior with typed
c8s annotations for the cert volume, cert/key filenames, renewal interval,
nginx reload, Secret watch paths, discovery output, and get-cert UID/GID. The
tls-lb chart uses those annotations to keep its PKI volumes and nginx config in
the chart while dogfooding the webhook-injected get-cert containers. The
webhook rejects incomplete reload-watch or discovery annotation sets during pod
admission instead of admitting a pod that cannot serve its configured
certificate/discovery path.

## Engine upstream preset

tls-lb proxies its catch-all route to one upstream, `tlsLb.upstream.address`,
an opaque `host:port` the chart never interprets. For a workload run as the
operator-managed headless Service (annotated `confidential.ai/cw`, see
[Injection contract](#injection-contract)), that upstream must be the headless
Service's own DNS name and container port,
`c8s-<workloadId>.<namespace>.svc.cluster.local:<port>`. Headless DNS resolves
to pod IPs, which the node mesh intercepts to wrap the hop in attested mTLS; a
regular Service VIP it cannot intercept, so dialing one leaves the hop in
plaintext. Dialing the pod IP also bypasses the Service's port remapping, which
is why the explicit container port is required.

The `engine` preset derives that string for known inference engines so you do
not hand-write it or look up the port:

```yaml
engine:
  name: sglang        # "" | vllm | sglang
  workloadId: infer   # the confidential.ai/cw id on the engine pod
  namespace: ""       # where the engine runs; empty = release namespace
```

`engine.presets` maps each engine to its default server port and is the single
source of truth (both the resolver and validation read it); adding an engine is
one edit there:

```yaml
engine:
  presets:
    vllm: "8000"
    sglang: "30000"
```

With `engine.name=sglang` and `engine.workloadId=infer` in namespace
`c8s-system`, tls-lb's upstream resolves to
`c8s-infer.c8s-system.svc.cluster.local:30000` (`c8s install` plumbs these as
`--engine sglang --engine-workload-id infer`, plus `--engine-namespace` when
the workload runs elsewhere). Leaving `engine.name` empty preserves
`tlsLb.upstream.address` verbatim, so an upstream that is not a c8s-managed
workload (an existing Service, an external address) is set directly, but the
chart cannot verify such an upstream resolves to pod IPs the mesh intercepts,
so a manual address must be `protocol: https` with `tls.verify: true`: an
upstream that terminates and authenticates TLS itself (app-TLS). There is no
plaintext-to-unattested escape hatch and no default upstream.

Leaving both unset is legal: tls-lb installs and serves its cert, discovery,
and any explicit routes with **no catch-all** `location /` until an upstream is
wired. This is the install-then-attach flow: `c8s install` stands up the front
door, and the operator attaches inference later by setting the engine preset
(or a verified-https address). An unmatched request gets nginx's default 404
until then.

```bash
helm template c8s internal/helmchart/c8s \
  --set-string engine.name=sglang \
  --set-string engine.workloadId=infer \
  ...
```

The chart rejects, at render time, with stable `kind=` markers (the same the
chart tests assert on):

- `tlslb_unsecured_upstream`: `tlsLb.upstream.address` is set to a plaintext
  http backend, or https without `tls.verify=true`. Only a verified-https
  (app-TLS) manual address is admitted; there is no acknowledgment to override
  this. To reach a confidential workload, use `engine.name` +
  `engine.workloadId` instead: pointing the address at a Service VIP fronting
  cw pods is unmeshed, and the always-on cw guard drops it, so the hop fails
  closed rather than running plaintext.
- `engine_upstream_conflict`: both `engine.name` and a custom
  `tlsLb.upstream.address` are set. They are two ways to say the same thing;
  set one.
- `engine_https_upstream`: `engine.name` is set with
  `tlsLb.upstream.protocol=https`. The derived headless-Service hop is
  plaintext at the app layer (the mesh wraps it in attested mTLS), so an https
  protocol could only fail at runtime.
- `engine_missing_workload_id`: `engine.name` is set but `engine.workloadId` is
  empty.
- `engine_invalid_workload_id`: `c8s-<workloadId>` is not a DNS-1035 label
  (start with a letter, then `[a-z0-9-]`, end alphanumeric; the `c8s-` prefix
  caps `workloadId` at 59 chars), so the operator would refuse to mint the
  Service and tls-lb would dial a name that resolves to nothing. The rule
  mirrors `webhook.WorkloadServiceName`.
- `unknown_engine`: `engine.name` is not a key of `engine.presets`.

The same secured-backend rule applies to every `tlsLb.routes[].backend`: it
must use `protocol: https` with `tls.verify: true` (app-TLS). A plaintext http
or unverified-https route backend fails the render (`tlslb_unsecured_route`);
there is no acknowledgment to override it. Routes have no default backend, so
this only affects routes you configure. A confidential workload is reached via
the engine preset, not a route.

The engine path's mesh guarantee holds only when `engine.workloadId` names a
real cw workload: the chart validates the id is a DNS-1035 label but cannot
confirm, at render time, that `c8s-<workloadId>` fronts attested cw pods. A
wrong id derives a headless Service that resolves to nothing (tls-lb has no
backend) rather than a plaintext leak; the runtime boundary that a peer is a
genuine cw pod is the mesh's always-on cw inbound guard, not this render guard.

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

Validate the chart with `helm template` (use it, not `helm lint`: lint's
standalone YAML parse chokes on the nri-image-policy installer's embedded
host-config heredoc, while `helm template` — the path CI and the chart tests
use — renders it correctly).

The chart ships no default image tag, so a bare `helm template` must set one.
`c8s install` injects this for you; `main` here is the same fallback tag it
uses for a non-release build. The simplest validation renders with the
image-policy component disabled, so only image tags are required:

```bash
helm template c8s internal/helmchart/c8s \
  --namespace c8s-system \
  --set image.tag=main \
  --set attestationApi.image.tag=main \
  --set cds.image.tag=main \
  --set ratlsMesh.image.tag=main \
  --set nriImagePolicy.enabled=false >/dev/null && echo OK
```

To render the full default shape (image policy enabled), the chart requires the
nri-image-policy installer image and the CDS image to be digest-pinned. The CDS
node selector defaults to `role: cds`; override it if your CDS node uses a
different label. `c8s install` fills these digests from the registry by default
(via `crane`); for a manual render the values below are placeholders:

```bash
helm template c8s internal/helmchart/c8s \
  --namespace c8s-system \
  --set image.tag=main \
  --set attestationApi.image.tag=main \
  --set cds.image.tag=main \
  --set ratlsMesh.image.tag=main \
  --set nriImagePolicy.image.tag=main \
  --set nriImagePolicy.image.digest=sha256:0000000000000000000000000000000000000000000000000000000000000000 \
  --set cds.image.digest=sha256:0000000000000000000000000000000000000000000000000000000000000000 >/dev/null && echo OK
```

Append `--set-file cds.operatorKeys=operator.pub` to either command to render
the operator-keys ConfigMap and the CDS `--operator-keys` flag that gate
allowlist writes.

The rendered manifests should include:

- a CDS Deployment, Service, and ServiceAccount;
- the operator arg `--cds-url=https://c8s-cds.c8s-system.svc:8443`;
- no CDS admin-password Secret and no attestation-api API-key Secret;
- `confidential.ai/trust-root-mode: inMemory` annotations on the chart-managed
  CDS resources.
