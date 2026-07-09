#!/bin/sh
# Pull the kata-guest-base rootfs image (hardened kernel + dm-verity
# rootfs) into the host kata-images dir and rewrite the confidential
# kata runtime's config so kata-runtime boots our kernel + verity rootfs
# for every pod (measured direct-kernel boot, no IGVM).
#
# One kata-guest-base artifact serves both kata-qemu-snp (AMD SEV-SNP) and
# kata-qemu-tdx (Intel TDX): the vmlinuz has both TEE guest drivers built
# in (runtime-probed), the rootfs bytes are TEE-neutral, and the dm-verity
# root_hash is the same across shims. SHIM_NAME selects which shim's toml
# to rewrite. On the SNP shims we also pin default_vcpus=1 because the SNP
# launch digest measures per-vCPU VMSAs; the TDX shims need no pin — see
# the default_vcpus note below.
#
# The confidential-GPU shim (qemu-nvidia-gpu-snp) is driven by the same
# script from its own puller DaemonSet: TAG points at the separate
# kata-guest-base:<tag>-nvidia artifact (stock kata NVIDIA confidential
# rootfs, see docs/kata-gpu.md) and the GPU_* knobs add the VFIO
# cold-plug config on top. Same drop-in mechanism, same measured
# direct-kernel boot.
#
# Pure POSIX shell, kept as a standalone file (templated into the
# kata-image-puller ConfigMap via .Files.Get) so it gets shellcheck.
# All configuration comes from the environment, set on the puller
# initContainer from .Values.kata.guestImage.* — there is no helm
# interpolation inside this script.
#
#   REGISTRY        guest-image registry (e.g. ghcr.io/confidential-dot-ai)   [required]
#   TAG             kata-guest-base tag (e.g. main, or main-nvidia) [required]
#   HOST_IMG_DIR    /host-prefixed dir the puller writes into       [required]
#   SHIM_NAME       confidential shim to configure: qemu-snp, qemu-tdx, or
#                   qemu-nvidia-gpu-snp (confidential GPU — adds the VFIO
#                   cold-plug knobs below)
#                   [default qemu-snp — backward compat with pre-TDX chart]
#   GPU_PCIE_ROOT_PORT  `pcie_root_port = N` (VFIO cold-plug); REQUIRED for
#                   the GPU shim, ignored otherwise                 [optional]
#   GPU_DEFAULT_MEMORY  `default_memory = N` (MiB) for the GPU shim [optional]
#   KATA_DEBUG      "true" to keep debug_console_enabled + journal-to-console
#                   in the shim toml (dev only — host reads guest journal).
#                   Default false = puller strips both so a leaked hand-patch
#                   or a debug-variant install-then-normal-reinstall doesn't
#                   silently ship a guest that streams its journal to the host.
#   REGISTRY_AUTH   in-guest workload registry auth source (file://
#                   baked path or kbs:// URI); empty = anonymous    [optional]
#   ORAS_INSECURE   "true" to pull over plain HTTP (local mirror)   [optional]
set -eu

: "${REGISTRY:?REGISTRY must be set (kata.guestImage.repository)}"
: "${TAG:?TAG must be set (kata.guestImage.tag)}"
: "${HOST_IMG_DIR:?HOST_IMG_DIR must be set (/host + kata.guestImage.hostPath)}"
SHIM_NAME="${SHIM_NAME:-qemu-snp}"
case "${SHIM_NAME}" in
    qemu-snp|qemu-tdx|qemu-nvidia-gpu-snp|qemu-nvidia-gpu-tdx) ;;
    *) echo "ERROR: SHIM_NAME must be qemu-snp, qemu-tdx, qemu-nvidia-gpu-snp, or qemu-nvidia-gpu-tdx (got '${SHIM_NAME}')" >&2; exit 1 ;;
esac
KATA_DEBUG="${KATA_DEBUG:-false}"
REGISTRY_AUTH="${REGISTRY_AUTH:-}"
GPU_PCIE_ROOT_PORT="${GPU_PCIE_ROOT_PORT:-}"
GPU_DEFAULT_MEMORY="${GPU_DEFAULT_MEMORY:-}"
# pcie_root_port is load-bearing for the GPU shim: VFIO cold-plug attaches
# each passed-through GPU behind a pcie-root-port, and the stock SNP-GPU
# config ships 0 (passthrough disabled). A GPU pod boots fine with 0 but has
# NO device, surfacing only as a missing /dev/nvidia* in-guest — so an unset
# knob is a hard error, not a warning: the puller exits non-zero and stays
# NotReady (visible at rollout) rather than silently shipping a deviceless
# runtime. default_memory is a tuning knob (the in-guest NVIDIA driver's
# BAR-mapping path OOMs the stock guest during device init), not load-bearing
# for passthrough, so it stays optional.
case "${SHIM_NAME}" in
    qemu-nvidia-gpu-*)
        case "${GPU_PCIE_ROOT_PORT}" in
            ''|0)
                echo "ERROR: GPU_PCIE_ROOT_PORT must be >= 1 for SHIM_NAME=${SHIM_NAME} (kata.gpu.guestImage.pcieRootPort, also enforced at chart render) — refusing to ship a GPU runtime with VFIO cold-plug disabled" >&2
                exit 1
                ;;
        esac
        ;;
esac
# --plain-http makes oras talk to an insecure (HTTP, no TLS) registry — for
# local / in-cluster mirrors only. Empty for a normal TLS registry.
ORAS_OPTS=""
[ "${ORAS_INSECURE:-false}" = "true" ] && ORAS_OPTS="--plain-http"
HOST_KATA_DIR="${HOST_KATA_DIR:-/host/opt/kata}"
KATA_CONFIG_DIR="${HOST_KATA_DIR}/share/defaults/kata-containers"

echo "==> c8s-kata-image-puller: registry=${REGISTRY} tag=${TAG}"

mkdir -p "${HOST_IMG_DIR}" "${KATA_CONFIG_DIR}"

out_dir="${HOST_IMG_DIR}/base"
mkdir -p "${out_dir}"

echo "==> Pulling kata-guest-base:${TAG}"
# oras pull is content-addressable: re-running with the same
# digest is a no-op once the artifact is in the local cache.
# We cd into the target dir so the pulled files land there
# (oras unpacks the artifact's contents into CWD).
# shellcheck disable=SC2086  # ORAS_OPTS is a controlled single flag ("" or --plain-http)
( cd "${out_dir}" && oras pull ${ORAS_OPTS} "${REGISTRY}/kata-guest-base:${TAG}" )

# Sanity: the artifact must contain the kernel, the verity rootfs
# image, and the verity params + rootfs-type sidecars. Fail loudly —
# silently writing a config that points at a missing file (or, worse,
# one with empty verity params, which would DISABLE dm-verity and drop
# the rootfs out of the measurement) leaves the runtime broken or
# insecure in a way that only surfaces at pod start.
for required in vmlinuz kata-rootfs.img kernel_verity_params rootfs_type; do
    if [ ! -f "${out_dir}/${required}" ]; then
        echo "ERROR: ${out_dir}/${required} missing after oras pull" >&2
        exit 1
    fi
done

# Verity params + rootfs type come from the build (these sidecars
# mirror manifest.json). kernel_verity_params is load-bearing: an
# empty value would make kata boot WITHOUT dm-verity (rootfs no longer
# measured / tamper-evident), so refuse anything but a real root_hash.
KVP="$(tr -d '\n' < "${out_dir}/kernel_verity_params")"
RFT="$(tr -d '\n' < "${out_dir}/rootfs_type")"
case "${KVP}" in
    root_hash=*) ;;
    *) echo "ERROR: kernel_verity_params is not a 'root_hash=…' string: '${KVP}'" >&2; exit 1 ;;
esac
[ -n "${RFT}" ] || RFT=ext4

# Translate /host<...> back to the on-host absolute path the
# kata configuration TOML will reference. The puller pod sees
# the host root at /host; kata-runtime running on the host
# sees the same files without the prefix.
host_out_dir="${out_dir#/host}"

# c8s writes ONLY a config.d/ drop-in — never the main configuration-<shim>.toml.
#
# kata-deploy owns the main toml (`configuration-qemu-snp.toml` /
# `configuration-qemu-tdx.toml`) and rewrites it every time the DaemonSet's pod
# restarts. Editing the main file in place produces a race the puller keeps
# losing: kata-deploy restarts → clobbers our patch → next sandbox launches
# with stock kata paths → containerd stack fails at rootfs mount (SNP: stock
# vmlinuz doesn't have the c8s in-guest bits; TDX: stock vmlinuz doesn't have
# TDX guest driver either).
#
# kata-runtime's config loader (src/runtime/pkg/katautils/config.go
# decodeDropIns / updateFromDropIn) reads every *.toml in a `config.d/`
# subdirectory next to the main file in alphabetical order AFTER the main
# file, and each drop-in's set fields override the main file's values.
# kata-deploy never touches config.d/, so a drop-in survives DS restarts
# by design. This is exactly the mechanism the main-toml header comment
# points operators at ("do not modify this file; put overrides in
# config.d/").
cfg_dir="${KATA_CONFIG_DIR}/runtimes/${SHIM_NAME}"
main_cfg="${cfg_dir}/configuration-${SHIM_NAME}.toml"
if [ ! -f "${main_cfg}" ]; then
    echo "ERROR: ${main_cfg} missing — has kata-deploy finished?" >&2
    exit 1
fi

dropin_dir="${cfg_dir}/config.d"
dropin="${dropin_dir}/50-c8s.toml"
mkdir -p "${dropin_dir}"

echo "  Writing ${dropin}"
# Compose the drop-in. Fields we set:
#
#   [hypervisor.qemu]
#     kernel / image       -> our hardened vmlinuz + dm-verity rootfs
#     rootfs_type          -> ext4 (from the osbuilder rootfs_type sidecar)
#     kernel_verity_params -> the root_hash/salt/blocks matching the rootfs;
#                             kata builds the dm-verity table from these and
#                             folds the resulting hash into the launch
#                             measurement (SNP kernel-hashes / TDX RTMR[1])
#     shared_fs = "none"   -> no virtio-fs into the confidential guest
#     kernel_params        -> appended to kata-runtime's built-in defaults;
#                             carries agent.image_registry_auth for the
#                             in-guest CDH's private-registry pull (baked
#                             auth.json at /run/image-security/auth.json)
#     default_vcpus/maxvcpus = 1 -> SNP-ONLY (both SNP shims, CPU and GPU).
#                             Pins the boot-time VMSA count so the launch
#                             digest is stable across pods. No pin on the TDX
#                             shims: the one TDX register c8s pins (MRTD, the
#                             launch_digest allowlist) measures TDVF firmware
#                             pages + SEPT — vCPU init (TDH.VP.INIT) and guest
#                             RAM size never enter it. The (vCPU, memory)-
#                             sensitive register is RTMR[0] (TDVF's TD-HOB),
#                             which c8s does not verify (the CC event log is
#                             stripped — see c8s pkg/attestclient/tdx.go).
#     pcie_root_port        -> GPU shim only: VFIO cold-plug root ports
#                             (kata.gpu.pcieRootPort; validated non-empty
#                             above).
#     default_memory        -> GPU shim only, optional: guest memory floor
#                             for the NVIDIA driver's BAR mapping
#                             (kata.gpu.defaultMemoryMiB).
#     debug_console_enabled -> forced false unless KATA_DEBUG=true (the
#                             chart derives this from kata.guestImage.debug).
#
#   [runtime]
#     experimental_force_guest_pull = true -> with shared_fs="none" the
#                             kata-agent inside the VM pulls the workload
#                             OCI image over the guest network (image-rs +
#                             CDH). Without this, the shim fails at
#                             `failed to mount /run/kata-containers/shared/
#                             containers/<id>/rootfs ... ENOENT`.
tmp="${dropin}.c8s-tmp"
{
    echo '# c8s kata-image-puller drop-in — MANAGED FILE, DO NOT EDIT.'
    echo '#'
    echo '# Layered on top of the sibling configuration-'"${SHIM_NAME}"'.toml by'
    echo '# kata-runtime (see src/runtime/pkg/katautils/config.go decodeDropIns).'
    echo '# Regenerated on every c8s-kata-image-puller reconcile from the'
    echo '# published kata-guest-base:<tag> artifact under '"${host_out_dir}"'.'
    echo ''
    echo '[hypervisor.qemu]'
    printf 'kernel = "%s/vmlinuz"\n' "${host_out_dir}"
    printf 'image = "%s/kata-rootfs.img"\n' "${host_out_dir}"
    printf 'rootfs_type = "%s"\n' "${RFT}"
    printf 'kernel_verity_params = "%s"\n' "${KVP}"
    echo 'shared_fs = "none"'
    # kata's decodeDropIns REPLACES scalar keys (updateFromDropIn decodes
    # over the loaded struct), so a bare kernel_params here would clobber the
    # stock toml's load-bearing params (qemu-tdx: cgroup_no_v1=all
    # systemd.unified_cgroup_hierarchy=1; qemu-nvidia-gpu-*: cgroup_no_v1=all
    # pci=realloc pci=nocrs pci=assign-busses nvrc.smi.srs=1 — dropping
    # cgroup_no_v1 kills the NVRC-exec'd kata-agent at startup). Read the
    # base value and append ours to it. A live session once saw drop-in
    # kernel_params edits not reach the qemu -append line — unexplained; see
    # docs/pitfalls.md "Guest kernel params" — but the config semantics make
    # this preservation load-bearing whenever the drop-in IS honored, so it
    # stays.
    base_kernel_params="$(sed -n 's/^kernel_params = "\(.*\)"$/\1/p' "${main_cfg}" | head -1)"
    if [ -n "${REGISTRY_AUTH}" ]; then
        printf 'kernel_params = "%s agent.image_registry_auth=%s"\n' "${base_kernel_params}" "${REGISTRY_AUTH}"
    elif [ -n "${base_kernel_params}" ]; then
        printf 'kernel_params = "%s"\n' "${base_kernel_params}"
    fi
    case "${SHIM_NAME}" in
        *-snp)
            echo 'default_vcpus = 1'
            echo 'default_maxvcpus = 1'
            ;;
    esac
    case "${SHIM_NAME}" in
        qemu-nvidia-gpu-*)
            printf 'pcie_root_port = %s\n' "${GPU_PCIE_ROOT_PORT}"
            if [ -n "${GPU_DEFAULT_MEMORY}" ]; then
                printf 'default_memory = %s\n' "${GPU_DEFAULT_MEMORY}"
            fi
            ;;
    esac
    # debug_console_enabled is an [agent.kata] key, not [hypervisor.qemu]:
    # kata's decodeDropIns validates each drop-in key against the config
    # struct and fails the whole sandbox on a misplaced key
    # ("error applying key 'hypervisor.qemu.debug_console_enabled'").
    echo ''
    echo '[agent.kata]'
    if [ "${KATA_DEBUG}" = "true" ]; then
        echo 'debug_console_enabled = true'
    else
        echo 'debug_console_enabled = false'
    fi
    echo ''
    echo '[runtime]'
    echo 'experimental_force_guest_pull = true'
} > "${tmp}"
mv -f "${tmp}" "${dropin}"

echo "==> c8s-kata-image-puller: done (shim=${SHIM_NAME}, dropin=${dropin})"
