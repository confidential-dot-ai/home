#!/bin/bash
# PROTOTYPE kata qemu wrapper: attach a per-VM ephemeral scratch disk so the
# in-guest confidential image store (extra/usr/local/lib/c8s/scratch-setup.sh)
# can unpack large images to encrypted disk instead of RAM.
#
# Kata has no native per-sandbox scratch-disk knob, so we intercept the qemu
# launch: set [hypervisor.qemu] path = <this script> in the kata-qemu-tdx
# config. It creates a sparse per-sandbox raw disk and attaches it as
# serial=confai-scratch (the guest finds it via /sys/block/<dev>/serial). The
# disk carries only ciphertext (dm-crypt in the guest); the host cannot read it.
#
# PRODUCTION NOTE: still a prototype. The clean version attaches the disk from
# the kata runtime (or a CDI device) rather than wrapping qemu. Tunables via env:
# CONFAI_REAL_QEMU, CONFAI_SCRATCH_DIR, CONFAI_SCRATCH_SIZE, CONFAI_GC_GRACE_SECS.
set -euo pipefail

QEMU="${CONFAI_REAL_QEMU:-/opt/kata/bin/qemu-system-x86_64}"
SDIR="${CONFAI_SCRATCH_DIR:-/var/lib/kata-scratch}"
SIZE="${CONFAI_SCRATCH_SIZE:-30G}"
GRACE="${CONFAI_GC_GRACE_SECS:-120}"

# The scratch file MUST be keyed on a reliably-unique id: two VMs sharing one
# raw disk would corrupt each other. Kata passes the sandbox id in the -name
# argument ("-name sandbox-<64hex>,..."); take the id from THAT arg only (not
# "first 64-hex anywhere in argv", which could match an unrelated value). If we
# can't find it, FAIL — never fall back to a shared name.
name=""
prev=""
for a in "$@"; do
    [ "$prev" = "-name" ] && { name="$a"; break; }
    prev="$a"
done
SBID="$(printf '%s' "$name" | grep -oE '[a-f0-9]{64}' | head -1 || true)"
if [ -z "$SBID" ]; then
    echo "kata-qemu-scratch-wrapper: no sandbox id in -name ('$name'); refusing to launch with a shared scratch disk" >&2
    exit 1
fi

mkdir -p "$SDIR"

# GC scratch files from VMs that are gone: no process holds the file open AND it
# is older than the grace window. The grace window makes this safe against a
# concurrently-launching VM whose file already exists but whose qemu has not
# opened it yet — that file is fresh, so it is skipped.
for f in "$SDIR"/scratch-*.img; do
    [ -e "$f" ] || continue
    if [ -z "$(find "$f" -newermt "-${GRACE} seconds" 2>/dev/null)" ] && ! fuser "$f" >/dev/null 2>&1; then
        rm -f "$f"
    fi
done

IMG="$SDIR/scratch-$SBID.img"
truncate -s "$SIZE" "$IMG"
# file.locking left at the qemu default (on): with unique per-sandbox files a
# lock conflict now means a real bug (two launches, same id) and should fail
# loudly rather than silently share the disk.
exec "$QEMU" "$@" \
    -drive "file=$IMG,format=raw,if=none,id=confaiscratch,cache=none" \
    -device virtio-blk-pci,drive=confaiscratch,serial=confai-scratch
