#!/bin/bash
# PROTOTYPE kata qemu wrapper: attach a per-VM ephemeral scratch disk so the
# in-guest confidential image store (extra/usr/local/lib/c8s/scratch-setup.sh) can
# unpack large images to encrypted disk instead of RAM.
#
# Kata has no native per-sandbox scratch-disk knob, so we intercept the qemu
# launch: set [hypervisor.qemu] path = <this script> in the kata-qemu-tdx
# config. It creates a sparse per-sandbox raw disk (keyed on the 64-hex sandbox
# id in the args so concurrent VMs don't collide) and attaches it as
# serial=confai-scratch (Steep's convention; the guest finds it via
# /sys/block/<dev>/serial). The disk carries only ciphertext (dm-crypt in the
# guest); the host cannot read it.
#
# PRODUCTION NOTE: this wrapper is a prototype. The clean version attaches the
# disk from the kata runtime (or a CDI device) rather than wrapping qemu, and
# garbage-collects the per-sandbox files on VM teardown (sparse, but currently
# left behind). Tunables via env: CONFAI_REAL_QEMU, CONFAI_SCRATCH_DIR,
# CONFAI_SCRATCH_SIZE.
set -u
QEMU="${CONFAI_REAL_QEMU:-/opt/kata/bin/qemu-system-x86_64}"
SDIR="${CONFAI_SCRATCH_DIR:-/var/lib/kata-scratch}"
SIZE="${CONFAI_SCRATCH_SIZE:-30G}"
SBID="$(printf '%s ' "$@" | grep -oE '[a-f0-9]{64}' | head -1)"; SBID="${SBID:-default}"
mkdir -p "$SDIR"
IMG="$SDIR/scratch-$SBID.img"
truncate -s "$SIZE" "$IMG" 2>/dev/null
exec "$QEMU" "$@" \
  -drive "file=$IMG,format=raw,if=none,id=confaiscratch,cache=none,file.locking=off" \
  -device virtio-blk-pci,drive=confaiscratch,serial=confai-scratch
