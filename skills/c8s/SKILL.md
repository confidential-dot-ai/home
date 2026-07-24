---
name: c8s
description: |
  Build, install, and operate c8s — confidential Kubernetes: TEE attestation,
  RA-TLS mesh certificates, image-digest policy, and confidential-VM
  enforcement for workloads on AMD SEV-SNP or Intel TDX hardware. Covers the
  c8s CLI (install/uninstall/verify), the `--cvm-mode` deployment shapes
  (pod / node / gke / aks) and the orthogonal `--hardware-platform`
  (sev-snp / tdx), the operator and embedded Helm chart, the
  ConfidentialWorkload CRD, CDS (the attestation-gated certificate trust
  root), the kata-guest-base dm-verity guest image, confidential GPU
  passthrough, and measurement pinning. Use this skill whenever the task
  involves confidential Kubernetes, Kata containers, CVM pods, kata-qemu-snp
  or kata-qemu-tdx, SEV-SNP or TDX nodes, confidential containers,
  confidential GPU passthrough (VFIO, nvidia.com resources),
  attestation-gated scheduling or certificate issuance, RA-TLS,
  launch-measurement verification, or running TEE workloads (including
  confidential inference stacks) on Kubernetes.
---

# c8s — confidential Kubernetes

## Overview

c8s turns a Kubernetes cluster into a confidential-computing platform: workload
identity is granted by hardware attestation (AMD SEV-SNP or Intel TDX),
certificates are issued only to attested TEEs, and container images are
admitted by digest allowlist. It is a Go monorepo
(`github.com/confidential-dot-ai/c8s`) that ships one multi-mode binary (`c8s`)
plus an embedded Helm chart.

Every install answers two **orthogonal** questions. Get this pair right first;
most confusion downstream comes from conflating them:

**1. `--cvm-mode` — what is the confidential VM?** REQUIRED; no default. Pick
one at install time and keep it fixed:

| Mode | The CVM is | Notes |
|---|---|---|
| `pod` | each opted-in pod, via the Kata runtime | host-side ratls-mesh/attestation-api/nri-image-policy are disabled — the in-guest counterparts serve them. *Enforcing*: the webhook injects kata RuntimeClasses and a ValidatingAdmissionPolicy rejects non-kata classes. No kata-without-enforcement shape exists |
| `node` | the node itself (node-as-CVM) | pods run as ordinary processes; attestation-api + nri are baked into the node image. The shape for GPU inference at node scale |
| `gke` | GKE-managed confidential VMs | |
| `aks` | Azure CVMs | evidence comes from the vTPM `/dev/tpm0`; `--hardware-platform` selects `az-snp` vs `az-tdx` |

**2. `--hardware-platform` — which CPU TEE?** `sev-snp` (default,
`/dev/sev-guest`) or `tdx` (`/dev/tdx-guest`). This is independent of the mode:
a TDX host can run `--cvm-mode=pod` just as an SNP host can.

## How it works (architecture)

| Component | Role | Runs |
|---|---|---|
| `c8s operator` | controller-manager + mutating admission webhook | host pod (always webhook-exempt) |
| CDS (`cmd/cds`) | trust root: verifies TEE evidence, issues EAR tokens, signs workload CSRs with an in-memory mesh CA, serves the image allowlist | runc pod under `node`/`gke`/`aks`; a kata CVM under `pod` |
| `get-cert` | injected init container + renewal sidecar; writes `tls.crt`/`tls.key` to `/etc/c8s/certs` | inside each opted-in pod |
| `ratls-mesh` | transparent L4 proxy wrapping traffic in hardware-attested mTLS | host DaemonSet, except `pod` mode where it is in-guest |
| attestation-api | fetches/serves TEE evidence | host DaemonSet, except `pod` mode: in-guest on loopback `:8400` |
| `nri-image-policy` / `policy-monitor` | image-digest allowlist enforcement | host NRI plugin; in-guest `policy-monitor` under `pod` |
| kata-deploy + kata-image-puller | install the Kata 3.30 runtime and stage the guest image on every node | privileged host DaemonSets (`--cvm-mode=pod` only) |
| sandbox device plugin + GPU image puller | advertise VFIO-bound GPUs as `nvidia.com/<MODEL>`, stage the `-nvidia` guest image | host DaemonSets (`--cvm-mode=pod`, GPU stack) |

Key mechanics:

- **Opt-in is a pod annotation**, not a CRD: `confidential.ai/cw: <workload-id>`
  on the pod template triggers get-cert injection, and under `--cvm-mode=pod`
  promotes the pod to the platform's confidential RuntimeClass.
- **The `ConfidentialWorkload` CRD is advisory** (`confidential.ai/v1alpha2`,
  kinds Deployment/StatefulSet/DaemonSet, short name `cwl`). It only mirrors
  per-pod attestation status for `kubectl get cwl`; injection works without it.
- **RuntimeClasses under `--cvm-mode=pod`**: `kata-qemu` and `kata-clh` give VM
  isolation only — the host can still read their memory. The confidential
  classes are the platform's pair: `kata-qemu-snp` / `kata-qemu-snp-nvidia` on
  SNP, `kata-qemu-tdx` / `kata-qemu-tdx-nvidia` on TDX (`--hardware-platform`
  decides which pair renders; each carries its own node selector,
  `confidential.ai/sev-snp=true` or `confidential.ai/tdx=true`). Un-annotated
  pods default to `kata-qemu`, which is *not* confidential.
- **GPU implies confidential.** Any pod requesting an `nvidia.com/*` extended
  resource gets the platform's `-nvidia` class injected, annotation or not —
  c8s ships no non-confidential GPU runtime. The GPU stack installs with every
  `--cvm-mode=pod`; there is no separate flag. NVIDIA only, pod-mode only.
- **Attestation chain (kata)**: the guest boots a dm-verity rootfs whose root
  hash rides in the kernel cmdline, folded into the SNP launch measurement via
  `kernel-hashes=on`. Everything baked into `kata-guest-base` (attestation
  service, in-guest mesh, policy-monitor, the OPA agent policy) is therefore
  attested transitively. vCPUs are pinned to 1 so the launch digest is stable.
- **CDS is a stateful singleton**: its mesh CA key lives only in process
  memory. A restart destroys issuance and forces a mesh re-bootstrap unless
  `cds.handoff.enabled=true` (which requires `cds.measurements` to be pinned).

## Quick agent flow

1. Read `README.md`, `docs/QUICKSTART.md`, and `docs/install-flows.md` for the
   current install contract; read `docs/pitfalls.md` before touching anything
   kata- or registry-related.
2. Build and lint: `make build && make lint && make test`.
3. Inspect what an install would apply without a cluster:
   `c8s render-values` (prints the resolved Helm values to stdout).
4. Install (`c8s install ...`), annotate a workload, verify injection, then
   verify attestation with `c8s cds verify` against a pinned measurement.
5. For any flag or target you are about to use, confirm it exists first
   (`Makefile`, `c8s <subcommand> --help`).

## Critical guidelines

- **Never invent CLI flags, make targets, or values keys.** Verify every
  command against the `Makefile`, `c8s <subcommand> --help`, and
  `internal/helmchart/c8s/values.yaml` before running or documenting it. The
  chart fails render on several invalid combinations by design (e.g. host
  components enabled alongside `kata.enabled`, handoff without measurements).
- **Confidentiality only counts on real TEE hardware.** Never write
  non-confidential "mechanics smoke tests" that fake or skip attestation —
  they prove nothing and create false confidence. Integration/e2e tests of
  confidential behavior must run against real confidential nodes: SEV-SNP
  (`/sys/module/kvm_amd/parameters/sev_snp` reads `Y`) or TDX. CDS itself
  cannot reach Ready as a runc pod on a non-TEE host: its RA-TLS cert needs
  the guest device (`/dev/sev-guest`, `/dev/tdx-guest`, or the vTPM
  `/dev/tpm0` on AKS), which only exists inside a confidential guest.
- **CI for confidential runners: keep the repo private.** Public GitHub repos
  cannot use self-hosted runners safely (GitHub restricts them, and fork PRs
  would execute on your attested hardware). Any CI repo that drives
  self-hosted confidential runners must be private.
- **Pin measurements in production.** `cds.measurements` and
  `ratls-mesh.measurements` ship empty; empty means "accept any TEE-attested
  peer", which lets any attacker with a genuine TEE stand in for CDS at
  bootstrap. Pin both to the expected SHA-384 launch digests.
- **Pin images by digest, not tag.** Every c8s image exposes an
  `image.digest` value. The kata-guest-base bootstrap allowlist binds to the
  digests that were `:main` at build time; a `:main`-everywhere deploy can
  drift into policy-monitor SIGKILLing CDS. `c8s install` resolves and pins
  digests by default (`--resolve-digests`, needs `crane` on PATH).
- **Never change `--cvm-mode` on a live cluster.** It silently moves CDS
  between a runc pod and a CVM and rewrites its trust boundary. Switching
  modes is a planned drain + reinstall, not `helm upgrade --set`.
- **`--debug` is development-only.** It selects the `<tag>-debug` guest image
  whose policy allows host exec/log streams — container I/O crosses the TEE
  boundary in plaintext. Its launch measurement differs from the locked image,
  so pinned attestation rejects debug guests; that separation is deliberate.
  It requires `--cvm-mode=pod` and is rejected elsewhere.

## Core workflows

### Build and test (requires Go 1.26.3+)

```bash
make build          # c8s multi-mode binary -> ./build/c8s (linux/amd64, CGO off)
make install        # install the c8s CLI onto PATH (go install, host platform)
make test           # go test -race ./...
make lint           # gofmt check (tracked files only) + go vet
make test-integration          # docker-compose integration test (get-cert + nginx TLS)
make test-e2e-cw-label-policy  # live-cluster CEL policy check; needs kubectl + installed chart

# Node-side / guest binaries
make build-c8s-node        # slim binary without operator/install (tag c8s_node)
make build-policy-monitor  # in-guest image-digest enforcer
make build-get-cert build-ratls-mesh build-nri-image-policy

# CRD codegen (controller-gen v0.20.1)
make manifests       # CRD YAML -> internal/helmchart/c8s/crds/ (the install vector)
make generate        # deepcopy
make check-crd-chart # CI check: committed CRDs match ./api/...
```

### Install — node-as-CVM and managed modes

`--cvm-mode` is required on every install; there is no default. Pair it with
`--hardware-platform` when the host is TDX rather than SNP.

```bash
# Label the node that runs CDS (chart default selector: role=cds), then:
kubectl label node <cds-node> role=cds
c8s install --namespace c8s-system --cvm-mode node

# The nodes are themselves CVMs on TDX hardware
c8s install --cvm-mode node --hardware-platform tdx

# Single-node / single-CVM cluster: no dedicated CDS node needed
c8s install --cvm-mode node --single-node

# Managed confidential VMs
c8s install --cvm-mode gke
c8s install --cvm-mode aks --hardware-platform tdx   # az-tdx via /dev/tpm0
```

Private registry: create the pull Secret in the release namespace *first*,
then reference it — the install fails fast if it is missing or the wrong type.

```bash
kubectl create namespace c8s-system
kubectl create secret docker-registry ghcr-secret -n c8s-system \
  --docker-server=ghcr.io --docker-username=<user> --docker-password="$TOKEN"
c8s install --namespace c8s-system --image-pull-secret ghcr-secret
```

### Install — pod-as-kata-CVM (enforcing)

Host prerequisites (a DaemonSet cannot apply these): the CPU TEE enabled in
BIOS and on the kernel cmdline. For SNP that is
`kvm_amd.sev=1 kvm_amd.sev_es=1 kvm_amd.sev_snp=1`; verify with
`cat /sys/module/kvm_amd/parameters/sev_snp` → `Y`. x86_64 only. Label nodes
with their platform (`confidential.ai/sev-snp=true` or
`confidential.ai/tdx=true`) so the RuntimeClass selectors land; do not mix
TEE and non-TEE nodes without those selectors. Kubernetes 1.30+ for the
enforcement policy.

```bash
c8s install --cvm-mode pod                          # kata-deploy DS + RuntimeClasses + enforcement + GPU stack
c8s install --cvm-mode pod --hardware-platform tdx  # renders the kata-qemu-tdx pair instead
c8s install --cvm-mode pod --debug                  # DEV ONLY: guest image variant with exec/logs
```

`--measurements` is **not valid** with `--cvm-mode=pod` — it pins this
cluster's own CVM launch digest, which only exists in the node-as-CVM shapes.

Before enforcing on a live cluster, audit non-system namespaces: CNI/CSI/
monitoring agents that are not host-namespace pods must be excluded via
`webhook.extraExcluded` or they will be forced into kata and fail to start.
Pair enforcement with a PodSecurityAdmission floor (`baseline`/`restricted`)
on tenant namespaces — otherwise `hostNetwork: true` is a tenant-accessible
enforcement bypass.

### Deploy a confidential workload

```yaml
# The security opt-in is the pod-template annotation; no CRD required.
apiVersion: apps/v1
kind: Deployment
metadata: {name: demo-nginx}
spec:
  replicas: 1
  selector: {matchLabels: {app: demo-nginx}}
  template:
    metadata:
      labels: {app: demo-nginx}
      annotations:
        confidential.ai/cw: demo-nginx
    spec:
      containers:
        - name: nginx
          image: nginx:1.27-alpine
```

```bash
kubectl apply -f samples/nginx-confidential-pod.yaml
kubectl apply -f samples/confidentialworkload.yaml   # optional status mirror
kubectl describe pod -l app=demo-nginx  # expect get-cert init + sidecar,
                                        # in-memory c8s-certs volume,
                                        # /etc/c8s/certs mounts
kubectl get cwl -A                      # attested/total counts (CRD UX)
```

Under `--cvm-mode=pod`, the annotation additionally gets the pod its platform's
confidential class — `kata-qemu-snp` on SNP, `kata-qemu-tdx` on TDX. A pod that
sets `runtimeClassName` itself but omits the annotation gets a CVM with *no*
c8s identity — the intentional bring-your-own-attestation path.

### Run a confidential GPU workload

The GPU stack ships with every `--cvm-mode=pod` install. Request the GPU as an
extended resource and the webhook injects the `-nvidia` class for the
platform; no annotation is needed to get confidentiality, though you still
want one for c8s identity:

```yaml
spec:
  containers:
    - name: infer
      image: <your-inference-image>
      resources:
        limits:
          nvidia.com/<MODEL>: 1     # per-model name from the sandbox device plugin
```

```bash
kubectl get runtimeclass                       # expect kata-qemu-snp-nvidia (or -tdx-)
kubectl get nodes -o json | jq '.items[].status.allocatable | with_entries(select(.key|startswith("nvidia.com")))'
```

The GPU must be bound to `vfio-pci` on the host for the plugin to advertise
it. Read `docs/kata-gpu.md` before deploying — it covers the cold-plug CDI
path, the device-plugin opt-out, and what remains out of scope (node-as-CVM
GPU is a separate story).

### Verify attestation (real hardware, real evidence)

```bash
# CDS runs as a locked kata guest: port-forward/exec are denied by guest
# policy, so dial the pod IP from something with cluster-network reach.
CDS_IP=$(kubectl get endpoints c8s-cds -n c8s-system \
  -o jsonpath='{.subsets[0].addresses[0].ip}')

c8s cds verify "https://$CDS_IP:8443" --measurements <sha384-launch-digest>
c8s cds verify "https://$CDS_IP:8443" --measurements-file digests.txt -o json
```

Verification runs in-process (attestation-go); the machine only needs
outbound HTTPS to `kdsintf.amd.com` for the VCEK. Without `--measurements`
the command still runs but is UNSAFE (any genuine TEE passes). Exit codes are
a CI contract: `0` verified, `2` verification/policy failed, `3` evidence
unavailable. `c8s verify <url> --kind lb` verifies the tls-lb the same way.

### Smoke-test kata enforcement (from a non-system namespace)

```bash
# Positive: webhook injects kata-qemu for a plain pod
kubectl run kata-smoketest --image=busybox:1.37 --restart=Never -- sleep 30
kubectl get pod kata-smoketest -o jsonpath='{.spec.runtimeClassName}{"\n"}'
# expect: kata-qemu

# Negative: a non-kata runtimeClassName is rejected by
# ValidatingAdmissionPolicy/c8s-kata-enforcement
```

These prove admission mechanics only. Confidentiality itself is proven by
`c8s cds verify` / per-pod SNP attestation against pinned measurements — on
real SEV-SNP nodes, never by mocked evidence.

### Build the guest image (kata-guest-base)

Needs Docker + root + loop devices (osbuilder); cannot run in a
user-namespaced dev container.

```bash
make build-c8s-node && make build-policy-monitor   # in-guest Go binaries
cd kata-guest-base
IMAGE_TAG=<c8s-release-tag> ./scripts/fetch.sh     # stage binaries + allowlist
./scripts/build.sh   # steep kernel + osbuilder rootfs + dm-verity seal
# output/: vmlinuz, kata-rootfs.img, manifest.json, kernel_verity_params
```

`KATA_VERSION` and `KATA_SRC_COMMIT` in `scripts/build.sh` must move together,
and the kata version must stay in lockstep with the chart's kata-deploy
version — host/guest agent skew breaks the ttRPC contract.

### Uninstall

```bash
c8s uninstall                    # helm uninstall + idempotent kata host sweep
c8s uninstall --host-sweep-only  # release already gone, nodes still dirty
c8s uninstall --force            # even while kata pods are running
# also: --delete-crds (deletes every ConfidentialWorkload!), --delete-namespace
```

## Configuration reference

`c8s install` flags (verified against `cmd/c8s/install.go`):

| Flag | Default | Purpose |
|---|---|---|
| `--namespace` | `c8s-system` | release namespace |
| `--release` | `c8s` | Helm release name |
| `-f, --values` | — | values files (repeatable) |
| `--install-crds` | `true` | `false` passes helm `--skip-crds`; disables status mirror |
| `--cvm-mode` | **required** | CVM shape: `pod` / `node` / `gke` / `aks`. `pod` disables host mesh/attestation/NRI in favour of the in-guest counterparts |
| `--hardware-platform` | `sev-snp` | CPU TEE, orthogonal to the mode: `sev-snp` (`/dev/sev-guest`) or `tdx` (`/dev/tdx-guest`). Under `aks` selects `az-snp`/`az-tdx` via `/dev/tpm0` |
| `--debug` | `false` | debug guest image; requires `--cvm-mode=pod`; never production |
| `--single-node` | `false` | clear the dedicated-CDS-node selector/toleration |
| `--measurements` | — | pin this cluster's CVM launch digest(s); not valid with `--cvm-mode=pod`; empty = UNSAFE |
| `--resolve-digests` | `true` | pin component digests via `crane`; `false` = supply via `-f` |
| `--attest` | `true` | tls-lb attestation sidecar serving `/.well-known/c8s/` |
| `--operator-keys` | — | PEM bundle of operator EC public keys authorizing `c8s allowlist` writes; without it writes are disabled |
| `--image-pull-secret` | — | existing dockerconfigjson Secret in the release namespace |
| `--image-tag` | build version | component tag to resolve digests at |
| `--wait` | `true` | helm `--wait` |

Chart values that matter most (`internal/helmchart/c8s/values.yaml`):

| Key | Default | Notes |
|---|---|---|
| `cds.measurements` | `[]` | SHA-384 digests allowed to attest / pull the CA via handoff. Empty = UNSAFE outside dev |
| `ratls-mesh.measurements` | `[]` | pins CDS's cert at bootstrap. Pin in production |
| `cds.node.selector` | `role: cds` | CDS is a singleton; pin it to a known node |
| `cds.handoff.enabled` | `false` | attested CA handoff for active/active; requires measurements |
| `cds.certTTL` / `webhook.getCert.renewInterval` | `24h` / `6h` | renew must be shorter than TTL |
| `webhook.extraExcluded` | `[]` | namespaces exempt from injection AND kata enforcement |
| `webhook.failurePolicy` | `Fail` | must stay `Fail` under kata (chart-enforced) |
| `kata.distro` | `k8s` | `k8s` or `rke2` (auto-detected at install); containerd config dir |
| `kata.nodeSelector` | `{}` | kata-deploy lands on every Linux node by default |
| `kata.guestImage.tag` | `main` | pin a specific tag — no `digest:` field yet (known gap) |
| `kata.guestImage.registryAuth` | `file:///run/...auth.json` | in-guest pull auth; in the launch measurement. `kbs://` = secret-free |
| `kata.guestImage.pullerAuthSecret` | `""` | host-side oras credential; NOT in the TCB |

## Troubleshooting

- **Injection didn't happen** — check the pod-template annotation
  `confidential.ai/cw` (annotation, not label), that the namespace is not
  excluded (`kube-*`, release namespace, `webhook.extraExcluded`), and that
  the pod was *created* after install (webhook fires on CREATE only).
- **`runtimeClassName` empty after a pod-mode install** — the operator is
  running without `--kata-enforce`; the release was installed without
  `--cvm-mode=pod`. Check `kubectl get deploy c8s-operator -n c8s-system -o yaml`.
- **Kata pods Pending with no node** — the RuntimeClass carries a platform node
  selector; label the TEE nodes `confidential.ai/sev-snp=true` (or
  `confidential.ai/tdx=true`) to match the install's `--hardware-platform`.
- **GPU pod scheduled but the class is wrong / no GPU advertised** — the GPU
  must be bound to `vfio-pci` for the sandbox device plugin to publish
  `nvidia.com/<MODEL>`; see `docs/kata-gpu.md`.
- **`kata-qemu-snp` pods fail to start** — host is not SNP-enabled (check
  `sev_snp` param, BIOS, kernel cmdline), node is ARM (x86_64 only), or
  `/dev/vhost-vsock` is missing (`modprobe vhost_vsock vhost_net`).
- **`failed to mount .../rootfs: ENOENT` on kata pods** — kata-deploy
  clobbered the guest-pull config; the kata-image-puller reconcile loop
  self-heals in ~30s. Do not convert the puller to a one-shot initContainer.
- **CDS never Ready under `--cvm-mode=node` on a plain host** — expected: no
  guest device outside a confidential guest. Dev-only escape:
  `cds.ratlsPlatform=""` (plaintext, HTTPS probe still fails). Real fix: run
  the supported shapes on real TEE hardware.
- **Private image 401s inside a kata guest** — guest-pull needs creds in TWO
  places: host-side (`imagePullSecrets`) *and* in-guest
  (`agent.image_registry_auth` via `kata.guestImage.registryAuth`).
- **policy-monitor SIGKILLs CDS at bootstrap** — floating-tag drift between
  `cds:main` and the baked bootstrap allowlist. Pin every c8s image by digest.
- **CDS restarted and the mesh broke** — expected for the singleton: the CA
  key died with the process. Re-bootstrap workloads, or enable
  `cds.handoff.enabled=true` with pinned measurements before scaling.
- **`kubectl exec`/`logs` fail on kata pods** — by design: the locked guest
  policy denies host exec/stream RPCs. Only the `--debug` image allows them.
- **Pods Pending right after `c8s install --cvm-mode=pod`** — the 1–2 min/node
  kata-deploy bootstrap window; pods are delayed, not lost.
- **Operator down under kata = cluster-wide pod-creation freeze** — known
  consequence of `failurePolicy: Fail` + enforcement. Recover the operator.

## Additional resources

Concepts live in `docs/`. Read the relevant one *before* changing code in that
area — each documents why the design is the way it is, which is rarely
recoverable from the code alone:

| If you are working on | Read |
|---|---|
| a first install, or the demo | `docs/QUICKSTART.md`, `docs/DEMO.md` |
| choosing a mode, admission or uninstall flow | `docs/install-flows.md` |
| kata: install, enforcement design, constraints | `docs/kata.md` |
| the guest image (build, boot, measurement) | `docs/kata-guest-base.md`, `kata-guest-base/README.md` |
| confidential GPU passthrough | `docs/kata-gpu.md` |
| in-guest digest enforcement | `docs/kata-image-policy.md` |
| RA-TLS, cert issuance, workload binding | `docs/ratls.md`, `docs/getcert-workload-binding.md` |
| the operator / webhook | `docs/operator.md` |
| trust boundaries: enforced today vs direction | `docs/THREAT_MODEL.md` |
| anything kata- or registry-related | `docs/pitfalls.md` — sharp edges, each citing code |
| code style, testing expectations | `docs/engineering-standards.md` |

Contributing: `CONTRIBUTING.md` requires Verified-signed commits and
conventional commit style (`feat(ratls-mesh): ...`, `docs: ...`), and asks that
changes touching attestation flows or trust boundaries start as an issue.
