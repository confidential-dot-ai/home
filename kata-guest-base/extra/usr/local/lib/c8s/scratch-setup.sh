#!/bin/bash
# c8s confidential image-store scratch disk.
#
# When the VM is launched with an ephemeral scratch disk tagged
# serial=confai-scratch (see scripts/kata-qemu-scratch-wrapper.sh), back the
# guest-pull image store with a dm-crypt-encrypted filesystem on it, so
# large workload images unpack to encrypted DISK instead of the RAM tmpfs that
# otherwise caps image size at guest memory. No such disk => no-op (guest-pull
# keeps using the default tmpfs). Matches Steep's ephemeral-encrypted-overlay
# pattern: random per-boot key, held only in (TDX-encrypted) guest RAM, never
# written to disk; the volume is reformatted every boot (pure scratch).
set -u
# libdevmapper must create the /dev/mapper nodes synchronously: udev is not up
# this early in boot, so without this cryptsetup blocks forever on a udev event.
export DM_DISABLE_UDEV=1

MOUNT=/run/kata-containers/image
MAPPER=confai-image-scratch

mountpoint -q "$MOUNT" && exit 0   # idempotent

SCRATCH=""
for s in /sys/block/*/serial; do
    if [ "$(cat "$s" 2>/dev/null)" = "confai-scratch" ]; then
        SCRATCH="/dev/$(basename "$(dirname "$s")")"; break
    fi
done
if [ -z "$SCRATCH" ]; then
    echo "scratch-setup: no confai-scratch disk; image store stays on tmpfs"; exit 0
fi

echo "scratch-setup: backing $MOUNT with dm-crypt on $SCRATCH"
# Key piped via stdin: never materialized as a file, held only in kernel RAM.
if ! head -c 64 /dev/urandom | cryptsetup open --batch-mode --type plain \
        --cipher aes-xts-plain64 --key-size 512 --key-file - "$SCRATCH" "$MAPPER"; then
    echo "scratch-setup: cryptsetup failed; image store stays on tmpfs"; exit 0
fi
if ! mkfs.ext4 -q -F -m 0 "/dev/mapper/$MAPPER"; then
    echo "scratch-setup: mkfs failed; falling back to tmpfs"; cryptsetup close "$MAPPER"; exit 0
fi
mkdir -p "$MOUNT"
mount -o noatime "/dev/mapper/$MAPPER" "$MOUNT"
echo "scratch-setup: encrypted image store mounted at $MOUNT"
