# Kata runtime installation and enforcement

c8s can install the Kata Containers runtime onto an existing cluster and
enforce that workload pods run as Kata VMs. This makes **pod-as-kata-cvm**
— each pod its own confidential VM — a one-shot `c8s install` step instead of
a manual per-node procedure.

This document covers what the feature installs, the design decisions behind
it, the threat model, and the constraints to read before shipping it.

It implements [lunal-dev/c8s#97](https://github.com/lunal-dev/c8s/issues/97)
(privileged Kata installation) and
[lunal-dev/c8s#77](https://github.com/lunal-dev/c8s/issues/77) (RuntimeClass
injection and enforcement).

## What it installs

`c8s install --kata` makes the embedded Helm chart render, in addition to the
normal c8s components:

- **The upstream `kata-deploy` DaemonSet** (`quay.io/kata-containers/kata-deploy`,
  digest-pinned). On every selected node it installs onto the host:
  - the kata-containers runtime and the `containerd-shim-kata-v2` shim;
  - QEMU and Cloud Hypervisor — these are **bundled in the kata-static
    payload**. Kata does not use a host QEMU; "install QEMU" is satisfied by
    installing the Kata bundle. The QEMU in the bundle is the SEV-SNP-capable
    build that `kata-qemu-snp` uses;
  - the guest kernel, guest images, and OVMF firmware;
  - a containerd runtime drop-in registering the `kata-qemu`, `kata-clh`, and
    `kata-qemu-snp` runtimes.

  kata-deploy then restarts containerd (or RKE2) so the runtimes become
  usable. Running pods survive the restart — containerd shims outlive the
  daemon.

- **Three RuntimeClass objects** — `kata-qemu`, `kata-clh`, `kata-qemu-snp`.
  kata-deploy's install binary does **not** create RuntimeClasses (only its
  own Helm chart does), so the c8s chart renders them itself.

`c8s install --kata-enforce` additionally turns on **enforcement** (see
[Enforcement](#enforcement)).

| RuntimeClass | Hypervisor | Confidential? |
|---|---|---|
| `kata-qemu` | QEMU microVM | No — VM isolation from the host only |
| `kata-clh` | Cloud Hypervisor | No — VM isolation from the host only |
| `kata-qemu-snp` | QEMU + SEV-SNP | **Yes** — the pod's memory is encrypted against the host |

## Installing

```bash
# Install the Kata stack only — pods opt in with runtimeClassName.
c8s install --kata

# Install the Kata stack on an RKE2 cluster.
c8s install --kata --distro rke2

# Install the Kata stack and enforce it (see Enforcement below).
c8s install --kata-enforce
```

`--distro` selects the host containerd config layout the installers target —
it drives both kata-deploy and the nri-image-policy installer:

| `--distro` | containerd config dir | Notes |
|---|---|---|
| `k8s` (default) | `/etc/containerd` | Vanilla / kubeadm clusters |
| `rke2` | `/var/lib/rancher/rke2/agent/etc/containerd` | RKE2 |

kata-deploy auto-detects which service to restart; only the config directory
has to be told. For a distro neither value covers, set
`kata.containerdConfigDir` directly in a values file. **RKE2 and vanilla
kubeadm are the supported, tested distros for this first cut**; k3s and k0s
are likely to work (kata-deploy supports them) but are untested here.

On RKE2, kata-deploy and nri-image-policy register their runtimes with
containerd through drop-in files, which load only if the containerd config
`imports` the drop-in directory — and neither RKE2 nor kata-deploy adds that
import. The chart handles it: the kata-deploy and nri-image-policy DaemonSets
each run a `containerd-prep` initContainer that adds the import to the
rendered config **and** to the RKE2 template (so it survives RKE2
regenerating its config), keyed to the containerd config schema version
(`config-v3.toml.d` on containerd 2.x). Because it lives in the chart it runs
on every install path — `c8s install` and GitOps `HelmRelease` alike — and
needs no manual containerd-template edits.

By default the kata-deploy DaemonSet runs on **every** Linux node, including
control-plane and tainted nodes — the one-shot install posture. Scope it with
`kata.nodeSelector` in a values file.

## Design: why wrap upstream kata-deploy

The node-side installer **wraps the upstream `kata-deploy` DaemonSet** rather
than reimplementing artifact copying, shim symlinks, the containerd drop-in,
and the per-distro runtime restart inside a c8s-native installer.

- kata-deploy already does exactly this job and handles RKE2 / k3s / k0s /
  vanilla containerd detection. `bare-metal-infra-management`'s `kata` role
  has wrapped it in production since Kata 3.30.
- The c8s wrapper stays thin: the chart picks the shim set, supplies the
  containerd config path, and renders the RuntimeClasses kata-deploy does not
  create.
- Cost: one upstream image (`quay.io/kata-containers/kata-deploy`) enters the
  supply chain. It is **digest-pinned** — see [Threat model](#threat-model).

The Kata version (3.30.0) is pinned in lockstep with
`bare-metal-infra-management` and `base-images/rke2-kata`, so a cluster
installed by c8s and one provisioned by Ansible or booted from the
`rke2-kata` image run the same runtime.

## Enforcement

`--kata-enforce` turns on two cooperating pieces. It implies `--kata`:
enforcement is meaningless without the Kata stack it injects and validates.

1. **A mutating step in the c8s operator's pod webhook.** For every workload
   pod that does not already request a `runtimeClassName`, the webhook injects
   one:
   - `kata-qemu-snp` if the pod is annotated `confidential.ai/cw` — a pod that
     opts in to a c8s workload identity also gets a confidential VM;
   - `kata-qemu` otherwise.

   This rides on the existing `pods.c8s.confidential.ai` webhook, which already
   matches every pod in non-system namespaces — no new webhook, no new TLS.

2. **A `ValidatingAdmissionPolicy`** (`c8s-kata-enforcement`) that rejects a
   workload pod requesting a `runtimeClassName` that is not one of
   `kata-qemu` / `kata-clh` / `kata-qemu-snp`.

[c8s#77](https://github.com/lunal-dev/c8s/issues/77) asked for a
`ValidatingAdmissionWebhook`. A **`ValidatingAdmissionPolicy`** (built-in CEL,
no webhook server, no TLS) is the lighter equivalent, and it is what
`bare-metal-infra-management` already uses for its `kata-cc-mode` policy.
It requires **Kubernetes 1.30+** (`admissionregistration.k8s.io/v1`); the
Kata stack install itself works on 1.29+.

### Host-namespace pods are exempt

A Kata pod is a VM and cannot join the host's network, PID, or IPC namespace.
A pod that sets `hostNetwork`, `hostPID`, or `hostIPC` is therefore exempt
from both halves of enforcement: the webhook injects no class, and the policy
does not reject it. Such a pod runs as an ordinary container. This is not an
escape hatch for confidentiality — a host-namespace pod is self-evidently not
seeking isolation from the host.

### What enforcement does *not* touch

- **System namespaces.** `kube-system`, `kube-public`, `kube-node-lease`, and
  the c8s release namespace are excluded, plus anything in
  `webhook.extraExcluded`. The webhook's injection scope and the policy's
  rejection scope are kept identical by both reading the same exclusion list —
  a namespace covered by the policy but skipped by the webhook would reject
  every pod in it.
- **Pods that explicitly set a `runtimeClassName`.** An operator's explicit
  choice is honored; the policy still validates it is a Kata class. Note
  that this path *also* skips get-cert injection: a pod set to
  `kata-qemu-snp` without the `confidential.ai/cw` annotation runs as a
  confidential VM but does not receive a c8s-issued workload identity. This
  is intentional — the supported "bring-your-own attestation/identity"
  path. To get both a confidential VM *and* a c8s workload identity,
  annotate the pod with `confidential.ai/cw: <workload-id>` and let the
  webhook inject `kata-qemu-snp` for you (or set both the annotation and
  the class explicitly).
- **Already-running pods.** The webhook fires on `CREATE` only. Enabling
  enforcement does not restart or reject existing pods; it applies to pods
  created afterwards.

### Excluding infrastructure namespaces

Enforcement forces every non-system workload pod into a VM. Infrastructure
that is installed into ordinary (non-`kube-system`) namespaces — CNI agents,
CSI drivers, monitoring DaemonSets, ingress controllers — frequently mounts
host paths or uses host namespaces and **cannot run under Kata**. Host-
namespace pods are exempt automatically, but anything else of this kind must
be excluded by namespace via `webhook.extraExcluded`, or it will be forced to
Kata and fail to start. Audit the cluster's non-system namespaces before
enabling enforcement.

### Smoke-testing enforcement

Two manual checks confirm both halves of enforcement are live. Run them from
a non-system namespace (`default` is the obvious choice); the webhook and
policy both skip `c8s-system` / `kube-system` / `kube-public` /
`kube-node-lease`, so a test pod created there silently bypasses both:

```bash
kubectl config set-context --current --namespace=default
```

**Positive — mutator injects `kata-qemu` when no `runtimeClassName` is set:**

```bash
kubectl run kata-smoketest --image=busybox:1.37 --restart=Never -- sleep 30
kubectl get pod kata-smoketest -o jsonpath='{.spec.runtimeClassName}{"\n"}'
# expect: kata-qemu
```

If the field is empty, the operator is running without `--kata-enforce`
(verify with `kubectl get deploy c8s-operator -n c8s-system -o yaml | grep
kata-enforce`). The mutating webhook is wired in either way; injection is
gated on the flag.

**Negative — policy rejects a pod that asks for a non-Kata `runtimeClassName`:**

```bash
kubectl apply -f - <<'EOF'
---
# A non-Kata RuntimeClass. The handler does not need to exist on the node;
# we only need a name that is NOT in the kata-enforcement allowlist.
apiVersion: node.k8s.io/v1
kind: RuntimeClass
metadata:
  name: crun
handler: crun
---
apiVersion: v1
kind: Pod
metadata:
  name: crun-smoketest
  namespace: default
spec:
  runtimeClassName: crun
  restartPolicy: Never
  containers:
    - name: c
      image: busybox:1.37
      command: ["sh", "-c", "sleep 30"]
EOF
```

The `RuntimeClass` applies cleanly. The `Pod` apply is **rejected** by
`ValidatingAdmissionPolicy/c8s-kata-enforcement`, with a message naming the
disallowed `runtimeClassName`. If it is accepted instead, the policy or its
binding is missing — `kubectl get validatingadmissionpolicy
c8s-kata-enforcement` and `kubectl get validatingadmissionpolicybinding -A |
grep c8s-kata-enforcement` will show the gap.

Cleanup:

```bash
kubectl delete pod kata-smoketest --ignore-not-found
kubectl delete runtimeclass crun --ignore-not-found
```

## Threat model

kata-deploy is **privileged**: it runs `privileged: true` with `hostPID` and
the host root filesystem bind-mounted at `/host`, and it nsenters PID 1 to
restart the runtime. That is inherent to installing a runtime onto a host —
there is no less-privileged way to do it.

For **pod-as-kata-cvm this does not weaken the threat model**, and that is the
core reasoning of [c8s#97](https://github.com/lunal-dev/c8s/issues/97):

- The host (L0) is already outside the trust boundary. With `kata-qemu-snp`
  the trust boundary is the SEV-SNP guest, not the node.
- A malicious host that swapped the Kata shim or QEMU for a tampered binary
  would launch a guest with a **different SEV-SNP launch measurement**.
  Attestation of that pod would then fail, and clients would refuse to
  interact with it. The host cannot forge a correct measurement.

So a privileged installer on an untrusted host does not expand what an
attacker can do undetected — it can break a confidential pod, but breaking it
is detected by attestation, not silently exploited.

Supply chain: the kata-deploy image is **digest-pinned** in `values.yaml`
(`kata.image.digest`). A registry compromise or tag repoint cannot change the
binary that runs privileged on every node; a bump is an explicit digest
change. This is the same posture `bare-metal-infra-management` takes.

**RuntimeClass enforcement is a guardrail, not a security boundary.** A
cluster-admin can register a RuntimeClass with any handler, and the policy is
a `ValidatingAdmissionPolicy` an admin can delete. Enforcement makes "run as a
Kata VM" the default and the easy path; it does not make non-Kata execution
impossible for someone with cluster-admin. The actual confidentiality
boundary is the per-pod SEV-SNP attestation of each `kata-qemu-snp` pod.

## Constraints — read these before you ship

- **`kata-qemu-snp` needs a real SEV-SNP host.** kata-deploy installs the
  runtime; it does **not** enable SEV-SNP. The host needs the
  `kvm_amd.sev=1 kvm_amd.sev_es=1 kvm_amd.sev_snp=1` kernel cmdline, the AMD
  PSP firmware, and BIOS support — none of which a DaemonSet can apply (kernel
  cmdline + reboot + BIOS are out of reach). On a non-SNP host, `kata-qemu`
  and `kata-clh` work but `kata-qemu-snp` pods fail to start. Verify with
  `cat /sys/module/kvm_amd/parameters/sev_snp` (`Y`). See
  `bare-metal-infra-management/docs/host_setup/snp-cpu-bios-setup.md`.

- **x86_64 only.** The chart renders `SHIMS_X86_64` (`qemu clh qemu-snp`) and
  no AArch64 equivalent, so kata-deploy installs nothing on ARM nodes. Pods
  scheduled there will fail to start under any kata RuntimeClass. Use
  `kata.nodeSelector` to keep kata-deploy off non-x86_64 nodes if you have a
  mixed-arch cluster.

- **Confidential kata is SEV-SNP only.** TDX is intentionally out of scope in
  this release even though the c8s attestation-service and ratls-mesh both
  already handle TDX. There is no `kata-qemu-tdx` shim in `SHIMS_X86_64`, no
  `kata-qemu-tdx` RuntimeClass, and the kata-enforcement allowlist accepts
  only `kata-qemu`, `kata-clh`, and `kata-qemu-snp`. The webhook auto-promotes
  `confidential.ai/cw` pods to `kata-qemu-snp` unconditionally; the
  `--kata-confidential-runtime-class` flag could point at a different class,
  but the shim and the allowlist would also need updating. TDX support is
  future work.

- **No mixed-platform clusters.** The `kata-qemu-snp` RuntimeClass has no
  `scheduling.nodeSelector`, so the scheduler can place a confidential pod on
  any node where kata-deploy ran. Assume the cluster is uniformly SEV-SNP
  capable. Per-node platform labelling for heterogeneous clusters is tracked
  in Future work below; until then, do not enable `--kata` on a cluster that
  mixes SNP and non-SNP nodes.

- **Host kernel modules.** Kata needs `/dev/kvm`, `/dev/vhost-vsock`, and
  `/dev/vhost-net`. On standard systemd distros the `vhost_vsock` / `vhost_net`
  modules auto-load on first use via the `devname:` module alias. If Kata pods
  fail with `open /dev/vhost-vsock: no such device`, load them
  (`modprobe vhost_vsock vhost_net`) and persist via `/etc/modules-load.d/`.
  Automatic module loading by the installer is future work.

- **One-shot `--kata-enforce` has a brief bootstrap window.** `c8s install
  --kata-enforce` brings up the webhook and the policy in the same release as
  kata-deploy, but kata-deploy takes 1–2 minutes per node to install the
  runtime. Pods created in that window are mutated to a Kata RuntimeClass and
  stay `Pending` (not rejected — the RuntimeClass objects exist immediately)
  until kata-deploy finishes. On a **live** cluster, prefer two steps: run
  `c8s install --kata`, wait for `kubectl rollout status ds/c8s-kata-deploy
  -n c8s-system`, then `c8s install --kata-enforce`.

- **`failurePolicy: Fail` blast radius.** The pod webhook is `Fail` (existing
  behavior). With enforcement on, if the c8s operator is down, workload pod
  creation is blocked cluster-wide until it recovers. This is unchanged from
  the get-cert webhook today; enforcement widens what a webhook outage stops
  from "get-cert injection" to "all workload pod creation". The chart now
  refuses to render `kata.enforce.enabled=true` with `webhook.failurePolicy`
  set to anything other than `Fail` — the two halves must move together.

- **Enforcement assumes a cluster-wide PodSecurityAdmission floor on
  workload namespaces.** The webhook and the policy both exempt pods that
  use a host namespace (`hostNetwork`, `hostPID`, `hostIPC`) because Kata
  cannot launch them as VMs. The chart enforces `pod-security=privileged`
  only on its own namespace (`c8s-system`); it does **not** label tenant
  namespaces. If your cluster has no PSA floor (or sets `privileged` as the
  default), any namespace user with create-pod RBAC can opt out of kata
  enforcement by setting `hostNetwork: true`. Treat `--kata-enforce` as a
  cluster-operator gate that must be paired with PSA `restricted` or
  `baseline` on workload namespaces — without it, the host-namespace
  exemption is a tenant-accessible bypass, not just an operator carve-out.



- **kata-deploy needs a namespace that permits privileged pods.** It runs in
  the c8s release namespace, which `c8s install` labels
  `pod-security.kubernetes.io/enforce: privileged` (plus the matching `warn`
  and `audit` labels). kata-deploy — and the `nri-image-policy` installer,
  also privileged here — therefore schedule even when the cluster sets a
  restrictive PodSecurity default.

- **Installing Kata restarts containerd / RKE2 on every node.** Running pods
  survive (shims persist), but expect a brief control-plane blip on
  single-node clusters.

- **kata-deploy tolerates every taint by default.** The DaemonSet ships with
  `tolerations: [{ operator: Exists }]` and a `kubernetes.io/os: linux` node
  selector, so it lands on every Linux node — including control-plane nodes
  and nodes you have tainted to keep workloads off (quarantined,
  GPU-reserved, etc.). This is the deliberate "one-shot install" posture: a
  bare `c8s install --kata` produces a cluster where every node can run kata
  pods. If you need to exclude nodes, override `kata.tolerations` /
  `kata.nodeSelector` in your values file. Because kata-deploy runs
  privileged with the host root mounted, narrow this if your trust model
  treats some nodes as out-of-scope for c8s.

- **GPU is out of scope.** No `kata-qemu-nvidia-gpu(-snp)` RuntimeClass, no
  VFIO binding, no NVIDIA sandbox-device-plugin. Confidential-GPU support
  means porting the GPU half of the `bare-metal-infra-management` `kata` /
  `base` / `sandbox-device-plugin` roles — future work, tracked separately
  per the [c8s#77](https://github.com/lunal-dev/c8s/issues/77) discussion.

- **No node attestation.** Pod-as-host means the node is not a CVM. Only each
  `kata-qemu-snp` pod carries its own SNP attestation. There is no launch
  digest for "is this a genuine c8s Kata node". This matches the
  `base-images/rke2-kata` node-as-host model.

- **`kata-qemu` is not confidential.** Enforcement's default for an
  un-annotated pod is `kata-qemu` — VM isolation from the host, but the host
  can read the pod's memory. Only `kata-qemu-snp` (pods annotated
  `confidential.ai/cw`) is a confidential VM. "Pod-as-kata-cvm by default" is
  a posture the operator opts into with `confidential.ai/cw`, not something a
  bare `c8s install --kata-enforce` gives every pod.

## Uninstalling

`helm uninstall` (or removing `kata.enabled`) deletes the kata-deploy
DaemonSet. Its `preStop` hook runs `kata-deploy cleanup`, which removes
`/opt/kata`, the containerd drop-in, and restarts the runtime — Kata is
removed from each node cleanly. The RuntimeClass objects and the
enforcement policy are deleted with the release.

## Future work

- Automatic host kernel-module loading (`vhost_vsock`, `vhost_net`).
- GPU / confidential-GPU RuntimeClasses and the VFIO + sandbox-device-plugin
  stack.
- Node-side scheduling for mixed clusters (labelling SNP-capable nodes so
  `kata-qemu-snp` pods only land where they can run).
- Tested support for k3s and k0s.

## See also

- [`docs/operator.md`](operator.md) — the c8s operator and embedded chart.
- [`docs/THREAT_MODEL.md`](THREAT_MODEL.md) — what c8s enforces today.
- `bare-metal-infra-management/docs/kata.md` and `docs/kata-cc-mode.md` — the
  Ansible-provisioned Kata stack this feature is consistent with.
- `base-images/rke2-kata` — the node-as-host image that bakes the same Kata
  3.30 runtime instead of installing it at runtime.
