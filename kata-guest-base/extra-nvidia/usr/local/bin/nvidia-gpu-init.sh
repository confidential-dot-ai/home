#!/bin/sh
# nvidia-gpu-init: load the NVIDIA driver and create its device nodes.
#
# This (plus nvidia-persistenced.service and nvidia-gpu-ready.service) is the
# systemd replacement for NVRC, the PID-1 init the upstream kata
# nvidia-gpu-confidential rootfs uses. The c8s GPU guest boots systemd like
# the non-GPU guest — the whole point of the c8s image is the systemd-managed
# in-guest stack (attestation-service, ratls-mesh, policy-monitor) — so
# NVRC's GPU bring-up is re-expressed as ordered units instead:
#
#   nvidia-gpu-init.service     modprobe + /dev nodes           (this script)
#   nvidia-persistenced.service the persistence daemon
#   nvidia-gpu-ready.service    CDI spec, CC ready-state, health
#                               check, module-loading lockdown
#   kata-agent.service          Requires/After nvidia-gpu-ready
#
# Fail-fast like NVRC: any failure here fails the unit, which blocks
# kata-agent (see kata-agent.service.d/30-nvidia-gpu.conf) — the pod dies at
# sandbox creation instead of scheduling containers onto a broken GPU.
set -eu

# The GPU is VFIO COLD-plugged by kata: it is on the PCI bus before the
# kernel boots, so a missing NVIDIA function here is a real error (wrong
# runtime pairing or passthrough failure), not a timing race.
nv_present=0
for dev in /sys/bus/pci/devices/*; do
    [ "$(cat "${dev}/vendor" 2>/dev/null)" = "0x10de" ] && nv_present=1 && break
done
if [ "${nv_present}" = "0" ]; then
    echo "nvidia-gpu-init: no NVIDIA PCI function visible — this image only runs under the GPU runtime (cold-plug VFIO); refusing to continue" >&2
    exit 1
fi

modprobe nvidia
modprobe nvidia-uvm

# Device nodes. No udev rules ship with the grafted driver payload (mirroring
# upstream's chisseled image, where NVRC creates the nodes itself), so create
# them from the majors the modules registered in /proc/devices.
nvidia_major="$(awk '$2 == "nvidia" {print $1}' /proc/devices)"
uvm_major="$(awk '$2 == "nvidia-uvm" {print $1}' /proc/devices)"
[ -n "${nvidia_major}" ] || { echo "nvidia-gpu-init: nvidia major missing from /proc/devices after modprobe" >&2; exit 1; }
[ -n "${uvm_major}" ] || { echo "nvidia-gpu-init: nvidia-uvm major missing from /proc/devices after modprobe" >&2; exit 1; }

[ -e /dev/nvidiactl ] || mknod -m 666 /dev/nvidiactl c "${nvidia_major}" 255
[ -e /dev/nvidia-uvm ] || mknod -m 666 /dev/nvidia-uvm c "${uvm_major}" 0
[ -e /dev/nvidia-uvm-tools ] || mknod -m 666 /dev/nvidia-uvm-tools c "${uvm_major}" 1

# One node per GPU the driver enumerated (multi-GPU pods pass several
# functions through; /proc/driver/nvidia/gpus has one entry each).
i=0
for gpu in /proc/driver/nvidia/gpus/*; do
    [ -d "${gpu}" ] || continue
    [ -e "/dev/nvidia${i}" ] || mknod -m 666 "/dev/nvidia${i}" c "${nvidia_major}" "${i}"
    i=$((i + 1))
done
[ "${i}" -gt 0 ] || { echo "nvidia-gpu-init: driver loaded but enumerated no GPUs" >&2; exit 1; }

echo "nvidia-gpu-init: driver loaded, ${i} GPU(s), device nodes ready"
