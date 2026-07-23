# GPU usage with Kata (confidential GPU passthrough)

Runs a Kubernetes pod as a confidential VM (SEV-SNP or Intel TDX, per the
install's `--hardware-platform`) with an NVIDIA GPU passed through over VFIO.
**The GPU stack ships with every `c8s install --cvm-mode=pod`** — there is no separate
flag or mode. Every kata cluster can run both CPU and GPU confidential pods.
**NVIDIA only. Pod-as-CVM only** (node-as-CVM GPU is a separate story — see
"Out of scope" below).

## What ships with `--cvm-mode=pod` (the GPU stack)

`c8s install --cvm-mode=pod` renders, alongside the CPU kata stack — for the declared
platform (SNP shown; a `--hardware-platform=tdx` install gets the `-tdx`
equivalents instead):

1. **RuntimeClass `kata-qemu-snp-nvidia`** (handler `kata-qemu-nvidia-gpu-snp`)
   — or `kata-qemu-tdx-nvidia` (handler `kata-qemu-nvidia-gpu-tdx`) on TDX.
   The names follow the c8s `kata-qemu-snp` convention; the handlers are the
   upstream kata shim names kata-deploy registers. Each carries its platform's
   node label selector (`confidential.ai/sev-snp=true` via
   `kata.snpNodeSelector`, or `confidential.ai/tdx=true` via
   `kata.tdxNodeSelector`) — see `docs/kata.md`. `templates/kata.yaml`.
2. **The platform's GPU shim** (`qemu-nvidia-gpu-snp` / `qemu-nvidia-gpu-tdx`)
   added to kata-deploy's `SHIMS_X86_64`, so containerd gets the matching
   `kata-qemu-nvidia-gpu-*` runtime.
3. **Webhook injection.** The operator runs with `--kata-enforce` and the
   install's `--hardware-platform`; the pod mutator injects the platform's GPU
   class into any pod whose containers request an `nvidia.com/*` extended
   resource. **GPU implies confidential** — c8s has no non-confidential GPU
   runtime, so a GPU request alone selects the class, regardless of the
   `confidential.ai/cw` annotation (see `docs/pitfalls.md` "A GPU request
   alone forces the confidential GPU class"). The kata-enforcement allowlist
   accepts the class.
4. **The GPU image puller** (`c8s-kata-deploy-image-puller-nvidia` DaemonSet) —
   pulls the `<tag>-nvidia` kata-guest-base artifact and patches the
   platform's `configuration-qemu-nvidia-gpu-*.toml` (below).
5. **The NVIDIA sandbox device plugin** (`c8s-kata-deploy-sandbox-device-plugin`
   DaemonSet) — discovers GPUs bound to vfio-pci and advertises them as
   per-model `nvidia.com/<MODEL>` resources, writing the CDI spec kata's
   cold-plug reads. This is the one component with an opt-out
   (`kata.gpu.sandboxDevicePlugin.enabled=false`) for clusters that advertise GPU
   devices some other way — it is privileged and pulls from nvcr.io.

### Injection decision matrix

The matrix is the webhook's decision for pods that set **no**
`runtimeClassName` of their own — which is every ordinary workload pod in a
kata cluster. Nothing needs annotating to land on `kata-qemu`; it is the
injected default, and the enforcement policy means no workload pod runs
un-mutated as plain runc.

| Pod | RuntimeClass injected |
|---|---|
| plain workload | `kata-qemu` (non-confidential) |
| annotated `confidential.ai/cw` | platform CPU class (`kata-qemu-snp` / `kata-qemu-tdx`) |
| requests `nvidia.com/*` | platform GPU class (`kata-qemu-snp-nvidia` / `kata-qemu-tdx-nvidia`) |
| requests `nvidia.com/*` **and** annotated | platform GPU class (GPU wins) |

The two exceptions: host-namespace pods (`hostNetwork/hostPID/hostIPC`) are
left alone (kata cannot run them — they stay runc, exempted by the
enforcement policy), and a pod that sets `runtimeClassName` explicitly keeps
it — honored if it names one of the kata classes, rejected at admission
otherwise.

## Using it

App developers add a GPU resource limit. No `runtimeClassName` — the webhook
injects it:

```yaml
apiVersion: v1
kind: Pod
metadata: { name: cuda-vectoradd }
spec:
  containers:
    - name: cuda
      image: nvcr.io/nvidia/k8s/cuda-sample:vectoradd-cuda12.5.0
      resources:
        limits:
          nvidia.com/GB202GL_RTX_PRO_6000_BLACKWELL_SERVER_EDITION: 1
```

The sandbox device plugin advertises **per-model** names (so a heterogeneous
fleet schedules to the right card), e.g.
`nvidia.com/GB202GL_RTX_PRO_6000_BLACKWELL_SERVER_EDITION`. `kubectl describe
node <gpu-node> | grep nvidia.com` shows what a node advertises.

> **The generic `nvidia.com/gpu` name does not schedule here.** The webhook
> matches the `nvidia.com/` *prefix*, so a pod requesting plain
> `nvidia.com/gpu` still gets the confidential-GPU class injected — but the
> sandbox device plugin advertises per-model names only, so no node ever
> offers `nvidia.com/gpu` and the pod sits `Pending` on
> `Insufficient nvidia.com/gpu`. Use the per-model name the node advertises.

A pod may request **more than one GPU of the same model** (e.g. `nvidia.com/
<MODEL>: 2`) — each device cold-plugs behind its own PCIe root port, so pod
shapes up to `kata.gpu.guestImage.pcieRootPort` GPUs (default 8, a full HGX
board) work. One model per pod (the resource name selects the model); NVLink
peer-to-peer topologies inside a pod are untested here.

> **No memory limits on GPU pods.** Per the bare-metal prior art, a `memory`
> limit interacts badly with memcg + cold-plug VFIO (the guest driver's BAR
> mapping). CPU limits are fine.

### On a node with no GPU

Expected and intended: the device plugin advertises nothing, so the pod stays
`Pending`:

```
0/1 nodes are available: 1 Insufficient
nvidia.com/GB202GL_RTX_PRO_6000_BLACKWELL_SERVER_EDITION.
```

This is the success shape on a box without GPUs — the webhook injected the right
class and the scheduler correctly refuses to place a GPU pod where no GPU is
advertised.

## The GPU guest image and config patch

The GPU puller pulls `<registry>/kata-guest-base:<tag>-nvidia` (same registry +
credentials as the non-GPU `kata.guestImage`, plus a `-nvidia` tag suffix) into
`kata.gpu.guestImage.hostPath` and layers a `config.d` drop-in over the
platform's GPU shim config
(`runtimes/qemu-nvidia-gpu-<snp|tdx>/configuration-qemu-nvidia-gpu-<snp|tdx>.toml`):

| Key | Value | Why |
|---|---|---|
| `kernel`, `image` | the pulled artifact | boot the c8s guest kernel + rootfs |
| `kernel_verity_params` | from the artifact | dm-verity rootfs, folded into the SNP launch measurement |
| `shared_fs` | `none` | SNP is incompatible with virtio-fs |
| `experimental_force_guest_pull` | `true` | with no host share, the in-guest CDH pulls the workload OCI image over virtio-net |
| `pcie_root_port` | `8` (`kata.gpu.guestImage.pcieRootPort`) | **load-bearing**: cold-plug VFIO attaches each GPU behind a pcie-root-port; the stock SNP-GPU config ships `0`, which disables passthrough |
| `default_memory` | `65536` MiB (`kata.gpu.guestImage.defaultMemory`) | the in-guest NVIDIA driver's BAR-mapping path OOMs the stock guest |
| `default_vcpus` / `default_maxvcpus` | `1` | **SNP only**: pin the boot-time VMSA count so the SNP launch digest is stable (shared with the non-GPU `kata-qemu-snp` path) — see "Limitations". TDX needs no pin (its verified measurement is vCPU-invariant — see `pull-and-configure.sh`) |

> **If a non-confidential GPU handler is ever shipped:** the puller patches
> only the SNP config (`configuration-qemu-nvidia-gpu-snp.toml`) because c8s
> registers no `qemu-nvidia-gpu` shim. The stock non-SNP
> `configuration-qemu-nvidia-gpu.toml` needs the same treatment before it
> could work on Blackwell — at minimum `default_memory` (stock 8192 MiB OOMs
> the in-guest driver; the bare-metal role uses 32768 for non-CC) and
> `agent.cdi_timeout=1200` on the guest kernel cmdline.

### The `-nvidia` artifact: the c8s guest + the NVIDIA payload

The `<tag>-nvidia` artifact is the **same c8s guest rootfs** as the non-GPU
image — same osbuilder base, same in-guest stack (attestation-service,
ratls-mesh, policy-monitor), same locked kata-agent policy, same baked
bootstrap allowlist and registry auth — with the NVIDIA payload grafted in at
build time (`build.sh` Step 6): the driver kernel modules, GSP firmware,
driver libraries, and admin binaries out of kata's own
`nvidia-gpu-confidential` rootfs image (the same digest-pinned kata release
that provides the agent).

Two deliberate deltas from the non-GPU guest:

- **It boots kata's GPU kernel, not the confos one.** The NVIDIA modules must
  match the kernel they were built for, and the confos kernel has
  `CONFIG_MODULES=n`. The GPU kernel is measured and version-pinned like
  everything else; building the modules against a confos GPU kernel flavor
  (module signing + `CONFIG_MODULE_SIG_FORCE`) is the remaining hardening
  step. Until then, boot-time module loading is closed after driver load
  (`kernel.modules_disabled=1`, set by
  `nvidia-gpu-ready.service`).
- **GPU bring-up is systemd units, not NVRC.** Upstream's GPU image boots
  NVIDIA's NVRC as PID 1; the c8s guest boots systemd (the in-guest stack
  depends on it). NVRC's duties are re-expressed as three ordered units in
  `kata-guest-base/extra-nvidia/` — driver+device nodes → `nvidia-persistenced`
  → CDI spec + confidential-compute ready-state + health gate — and
  `kata-agent.service` `Requires=` the last, so a GPU that didn't come up
  clean fails the sandbox at creation (NVRC's fail-fast, in systemd).

### `--debug` and the GPU guest

`c8s install --cvm-mode=pod --debug` switches every guest image to its debug variant:
the non-GPU puller pulls `<tag>-debug` and the GPU puller pulls
`<tag>-nvidia-debug`, both published in lockstep by CI (`kata-guest-base.yml`).
The GPU pair is a real locked/debug split, identical in mechanism to the
non-GPU pair: the debug variant differs in exactly two files —
`/etc/kata-opa/default-policy.rego` (host log/exec RPCs allowed) and the
`/etc/c8s/debug-guest` marker, which relaxes `nvidia-gpu-ready`'s CC gate so
a non-CC GPU boots with a warning instead of refusing (bring-up on non-CC
parts). Its verity root hash and launch measurement differ, and
locked-reference attestation rejects it.

## CI: building the images

The `Kata guest base` workflow (`kata-guest-base.yml`) builds all four guest
artifacts in one `build` job (SEV-SNP self-hosted runner, sequenced after
Docker via `workflow_run` so the component digests bake into the measured
rootfs): `kata-guest-base:<tag>` and `<tag>-debug` from the shared c8s rootfs,
then `<tag>-nvidia` and `<tag>-nvidia-debug` from the same rootfs with the
NVIDIA payload grafted (build.sh Step 6). The graft sources — kata's stock
GPU rootfs image and GPU kernel — are staged from the sha-pinned kata-static
release by `scripts/ci/stage-kata-conf.sh` and cached per kata version; the
build does not depend on runner state. All four publish in lockstep. One job,
not four: the variants share the expensive base rootfs build, and the
self-hosted runner serializes jobs anyway.

## Limitations

- **Single vCPU per GPU pod on SNP (`default_vcpus = default_maxvcpus = 1`).**
  The guest-config patch pins both to 1 so the SNP launch digest stays stable
  across pods (the boot-time VMSA count is the one genuinely per-VM input to
  the measurement). This is inherited verbatim from the non-GPU
  `kata-qemu-snp` path, but it bites harder for GPU: a CPU-bound
  pre/post-processing stage around the GPU kernel is capped at one vCPU, and
  `maxvcpus = 1` means CPU hotplug cannot raise it at runtime. TDX installs
  are unaffected (no pin — the verified TDX measurement is vCPU-invariant).
  This is a **policy pin, not a hard limit** — see "Raising the vCPU pin"
  below — accepted as the default for now.
- **No memory limits on GPU pods** (memcg + cold-plug VFIO interaction — see
  "Using it"). CPU limits are fine.
- **One GPU model per pod, advertised per-model.** The sandbox device plugin
  names resources per model (`nvidia.com/<MODEL>`); a pod targets one model. NVLink
  multi-GPU topologies are untested here.
- **The GPU guest boots kata's GPU kernel, not the confos-hardened one** —
  see "The `-nvidia` artifact" above and "Threat-model gaps".

### Raising the vCPU pin (SNP)

The pin exists because the SNP launch digest measures one VMSA per boot-time
vCPU: any **fixed** `default_vcpus = default_maxvcpus = N` gives a stable,
predictable digest — 1 is just the default, chosen to match the non-GPU path.
Workload reality may well justify a higher N for GPU pods (CPU is cheap next
to the GPU it feeds); what you may not do is let N float per pod, which would
fragment the reference measurement per pod shape.

To raise it:

1. Pick one N for the cluster's GPU pods.
2. On every GPU node, add a drop-in that sorts **after** the puller's
   `50-c8s.toml` (kata reads `config.d/*.toml` alphabetically, last write
   wins), e.g.
   `runtimes/qemu-nvidia-gpu-snp/config.d/60-vcpus.toml`:

   ```toml
   [hypervisor.qemu]
   default_vcpus = 8
   default_maxvcpus = 8
   ```

   Ship it via host provisioning — the puller reconciles only its own file
   and leaves other drop-ins alone.
3. Re-predict the SNP launch digest for N VMSAs and add it to every
   measurement allowlist that pins the GPU guest (`c8s verify
   --measurements`, `cds.measurements` / `ratlsMesh.measurements` if set) —
   the digest for N=1 stops matching.
4. Treat a digest mismatch after this change as expected for old reference
   values, not as tampering — rotate the references, don't widen them.

Removing the pin entirely (or a hot-plug scheme that keeps the boot-time
VMSA count fixed while adding vCPUs later) remains future work.

## Out of scope (assumed already provisioned on the host)

Per the install constraints, the GPU **host** setup is not done by c8s.
Provision it with your host-provisioning system before installing c8s:

- **vfio-pci binding** of the GPUs (`vfio-pci.ids=10de:...` on the host cmdline,
  nvidia/nouveau blacklisted).
- **GPU confidential-compute (CC) mode** set in GPU firmware (`nvidia_gpu_tools.py
  --set-cc-mode=on`). A CC-mode/runtime mismatch panics the in-guest driver
  (`conf_compute.c:162` — "CPU does not support confidential compute").
- **BAR resize** on Blackwell (default → 8 GiB), before kubelet. Two mechanisms
  exist and each fails on one Blackwell part: prefer the kernel sysfs path
  (unbind → `echo 13 > resource2_resize` → rebind — the one that works on
  B200), fall back to `setpci` + remove/rescan (needed on `preserve_config`
  hosts like RTX PRO 6000, but a **silent no-op on B200**: the control
  register accepts the write while the device keeps decoding the old window —
  always verify with `lspci`).
- **Runtime PM pinned off** for every passthrough GPU
  (`echo on > /sys/bus/pci/devices/<bdf>/power/control`). An idle vfio-bound
  B200 gets runtime-PM autosuspended into D3cold and does not survive the
  resume (observed on kernel 7.0.9): BAR0 reads `0xFF`, the guest driver
  reports "GPU has fallen off the bus", NVRC panics, QEMU exits rc=0, and the
  pod sits in `ContainerCreating` with **no error surfaced anywhere**. Note
  `nvidia_gpu_tools.py` resets `power/control` to `auto` on every run, so
  host provisioning must re-apply the pin after any gpu-admin-tools
  invocation. Recovery for a bricked GPU: force D0 →
  `--reset-with-sbr` → D3→D0 power-control cycle; FLR alone is insufficient.
- `kvm_amd.sev_snp=1` and an IOMMU on the host cmdline.

**After any GPU reset/SBR, roll the sandbox device plugin.** The plugin marks
a reset device unhealthy and does not re-probe: node allocatable for the model
drops and GPU pods sit `Pending` on `Insufficient nvidia.com/<MODEL>` even
after the GPU is back. `kubectl -n <ns> rollout restart ds
c8s-kata-deploy-sandbox-device-plugin` recovers; teaching the plugin to
re-probe is a candidate improvement.

c8s does **not** install the NVIDIA GPU Operator: it assumes host-visible GPUs
and a host driver, while c8s GPUs are vfio-bound for passthrough with no host
driver at all; its containerd handling conflicts with the RKE2 config layout
c8s manages; and the host normalization c8s depends on (CC mode, BAR resize,
runtime-PM pins) must happen before kubelet starts, outside any operator's
reach.

## Threat-model gaps (read before relying on this in production)

- **The GPU guest kernel and NVIDIA payload come from the kata release, not
  the c8s build.** The rootfs, in-guest stack, policy, and measurement flow
  are the c8s ones (parity with `kata-qemu-snp`), but the kernel is kata's
  GPU kernel (`CONFIG_MODULES=y`; module loading is locked down post-boot by
  `nvidia-gpu-ready.service` rather than compiled out) and the driver
  modules/userland are grafted from kata's digest-pinned GPU rootfs. Building
  the modules signed against a confos GPU kernel flavor is the remaining
  hardening step. Everything grafted is inside the measured verity root, so it
  is attested — just not c8s-compiled.
- **GPU attestation is not wired.** The NVIDIA GPU's own attestation (SPDM /
  `nvidia-smi conf-compute`) is out of scope for this iteration — CC mode is
  assumed correct on the host. A malicious host could present a non-CC GPU
  (the driver loads fine on one); the locked guest fails closed at boot
  against that: `nvidia-gpu-ready` refuses when CC is off, powering the VM
  off before the kata-agent starts, so the sandbox fails at creation. Only
  the `-debug` guest — already rejected by locked-reference attestation —
  tolerates a non-CC GPU, with a warning. There is still no *positive* GPU
  attestation surfaced to the relying party. (The graft carries upstream's
  `libnvat` NVIDIA-attestation library, so the in-guest plumbing for this is
  staged.)
- **Host-namespace GPU pods bypass the confidential path.** A pod with
  `hostNetwork/hostPID/hostIPC: true` is exempt from kata enforcement (a VM
  cannot share host namespaces), so the webhook leaves it as an ordinary host
  container and the ValidatingAdmissionPolicy allows it. If such a pod also
  requests `nvidia.com/*`, it runs *outside* a confidential VM. This is a
  pre-existing property of kata enforcement (true for every class), but GPU
  passthrough raises the stakes because the exempted resource is now a GPU.
  Follow-up to consider: reject host-namespace pods that request `nvidia.com/*`
  rather than exempting them. (Mitigating factor today: the sandbox device
  plugin hands out *VFIO* devices via CDI, not driver-backed `/dev/nvidia*`, so
  a plain container would get an unusable VFIO handle, not a working GPU.)

- **Node-as-CVM GPU is separate.** For the node-as-CVM shape, GPU drivers are
  baked into the node guest OS image and measured into the node's launch
  digest — a different mechanism that does not use this puller/runtime.

## Uninstall

`c8s uninstall` sweeps both guest-image dirs — the non-GPU
`kata.guestImage.hostPath` and the GPU `kata.gpu.guestImage.hostPath` — along
with `/opt/kata` and the containerd drop-in. The GPU dir is read from the
`kata.gpu.guestImage` block in the release values; a pre-GPU release (no
`kata.gpu` block) has no GPU dir to sweep.

## Values reference

```yaml
kata:
  gpu:                          # no `enabled` — the GPU stack ships with --cvm-mode=pod
    guestImage:
      hostPath: /var/lib/c8s/kata-images-nvidia   # swept on uninstall
      pcieRootPort: 8           # VFIO cold-plug ports (stock ships 0)
      defaultMemory: 65536      # MiB; BAR-mapping headroom
    sandboxDevicePlugin:
      enabled: true
      image:                    # nvcr.io, digest-pinned (privileged DaemonSet)
        repository: nvcr.io/nvidia/cloud-native/nvidia-sandbox-device-plugin
        tag: "v0.0.3"
        digest: "sha256:a897db2f25b1b0ff6195726ba6c307d8567b2285f59cde5f8409683fd9bd12e5"
```

The `<tag>-nvidia` guest image reuses `kata.guestImage.{repository,insecure,
pullerAuthSecret}` — same registry and credentials as the non-GPU
image, with a `-nvidia` tag suffix. `kata.guestImage.debug` drives both
pullers: `--cvm-mode=pod --debug` switches the non-GPU image to `<tag>-debug` and the
GPU image to `<tag>-nvidia-debug` in the same install (see "`--debug` and the
GPU guest" above).
