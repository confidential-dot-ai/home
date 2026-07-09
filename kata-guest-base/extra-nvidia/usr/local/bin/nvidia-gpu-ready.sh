#!/bin/sh
# nvidia-gpu-ready: final GPU bring-up gates before the kata-agent starts.
# Runs after nvidia-gpu-init (driver + nodes) and nvidia-persistenced.
# See nvidia-gpu-init.sh for the NVRC-replacement overview.
set -eu

# In-guest CDI spec — the kata-agent injects the GPU into workload
# containers from /var/run/cdi (device nodes + the nvidia-cdi-hook that
# wires library paths), mirroring what NVRC generates in the upstream image.
mkdir -p /var/run/cdi
nvidia-ctk cdi generate --output=/var/run/cdi/nvidia.yaml

# Confidential-compute ready state. On a CC-mode GPU, CUDA refuses to run
# until the guest declares readiness (SetReadyState); upstream drives this
# via NVRC's nvrc.smi.srs=1 kernel param. The c8s GPU runtime is
# confidential-only: a GPU without CC on would hand the workload
# unprotected GPU memory, so the locked guest refuses it (unit
# FailureAction powers the VM off; the sandbox fails at creation). Only
# the -debug guest — which already crosses the TEE boundary by policy and
# fails locked-reference attestation — tolerates it, for bring-up on
# non-CC parts (/etc/c8s/debug-guest is baked by build.sh into the debug
# variants alongside the debug OPA policy).
if nvidia-smi conf-compute -f 2>/dev/null | grep -qi "cc status: on"; then
    nvidia-smi conf-compute -srs 1
    echo "nvidia-gpu-ready: confidential-compute ready-state set"
elif [ -f /etc/c8s/debug-guest ]; then
    echo "nvidia-gpu-ready: GPU not in CC mode — continuing (DEBUG guest; GPU memory is NOT protected)" >&2
else
    echo "nvidia-gpu-ready: GPU not in CC mode on the locked guest — refusing (GPU memory would be unprotected). Enable GPU CC mode on the host (nvidia_gpu_tools.py --set-cc-mode=on), or use the -debug guest for bring-up on non-CC parts" >&2
    exit 1
fi

# Health gate: the driver must actually talk to the GPU(s). This is what
# fails the boot (and therefore the pod, via kata-agent's Requires=) when
# passthrough half-worked — e.g. a BAR-starved or runtime-PM-bricked device.
nvidia-smi -L

# Lockdown, NVRC-parity: the modules we need are loaded; close the module
# loader for the rest of the guest's life. One-way until reboot. The
# non-GPU c8s guest gets the same property from CONFIG_MODULES=n; this is
# the closest a modular kernel gets.
echo 1 > /proc/sys/kernel/modules_disabled
echo "nvidia-gpu-ready: GPU ready, module loading locked"
