#!/usr/bin/env bash
# Build the c8s kata-guest-base: a kata-NATIVE guest rootfs for the
# kata-qemu-snp runtime class.
#
# WHY THIS LOOKS NOTHING LIKE THE OLD steep BUILD
# ------------------------------------------------
# kata-qemu does measured *direct-kernel* boot — there is no IGVM and no
# UKI on kata's path (verified against kata 3.30.0: no igvm-cfg in govmm,
# no igvm config knob; SNP uses `-object sev-snp-guest,...,kernel-hashes=on`
# over OVMF + a directly-loaded kernel). So kata wants three passive parts,
# not a self-booting image:
#
#   kernel = <vmlinuz>                 a bare bzImage  (steep's hardened kernel)
#   image  = <kata-rootfs.img>         a 2-partition image: p1=erofs rootfs,
#                                      p2=dm-verity hash tree (NO superblock)
#   kernel_verity_params = root_hash=…,salt=…,data_blocks=…,…
#
# kata builds the dm-verity table from kernel_verity_params at boot and
# pins root=/dev/vda1, hash=/dev/vda2 (qemu drops nvdimm for SNP). The
# root hash rides in the kernel cmdline, which kernel-hashes folds into
# the SNP launch measurement → the rootfs is attested transitively.
#
# steep is the wrong tool for that shape (it builds UEFI/IGVM self-booting
# disks), so we build the ROOTFS with kata's own osbuilder — which also
# installs the version-matched kata-agent for us. We keep steep ONLY for
# the hardened kernel (decoupled from the rootfs in kata).
#
# PIPELINE
#   1. steep kernel              -> hardened vmlinuz             (kernel =)
#   2. osbuilder rootfs (ubuntu) -> base rootfs + kata-agent
#   3. overlay extra/            -> c8s bins + units + policy + allowlist
#   4. osbuilder image (verity)  -> locked image  -> output/
#   5. debug re-seal             -> same rootfs with the host log/exec
#                                   RPCs allowed in the kata-agent policy
#                                   (kubectl logs/exec work) -> output-debug/
#   6. NVIDIA variants           -> same rootfs + the NVIDIA payload grafted
#                                   from kata's stock GPU image (modules,
#                                   GSP firmware, driver userland) + the
#                                   extra-nvidia/ NVRC-replacement units,
#                                   booting kata's GPU kernel; sealed locked
#                                   and debug -> output-nvidia[-debug]/
#
# Steps 1-3 (the expensive parts) are shared; only the verity seal +
# assembly runs per variant. The two variants differ in exactly one file:
# /etc/kata-opa/default-policy.rego.
#
# Output: ${IMAGE_DIR}/output/        {vmlinuz,kata-rootfs.img,manifest.json,…}
#         ${IMAGE_DIR}/output-debug/  same layout, debug-policy variant
#
# PREREQS (this CANNOT run in a user-namespaced dev container):
#   - docker running        (osbuilder builds inside Docker; needs loop devices)
#   - sudo                  (osbuilder partitions/loop-mounts the image)
#   - a steep checkout at ${WORKSPACE}/steep (built on demand)
#   - c8s binaries staged   (run scripts/fetch.sh first)
#   - kata source at KATA_VERSION (fetched via `gh` if not already present)
#
# Override knobs (env): KATA_VERSION, FS_TYPE, BUILD_VARIANT, KATA_SRC,
#   STEEP_DIR, OUTPUT_DIR, DEBUG_OUTPUT_DIR, SKIP_KERNEL=1 (reuse an
#   existing vmlinuz).
#   ROOTFS_CACHE_TAR (restore the pre-overlay base rootfs from this .tar.zst
#   when it exists, else pack the freshly built one there — the CI cache hook).
#
# NOTE (first-build validation): osbuilder's exact make-variable surface
# (ROOTFS_BUILD_DEST / IMAGES_BUILD_DEST / AGENT_POLICY wiring) is pinned
# to kata 3.30.0; if a step fails, the most likely culprit is one of the
# clearly-marked osbuilder invocations below — they're split into discrete
# steps so each is independently debuggable.

set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
IMAGE_DIR="$(cd "${HERE}/.." && pwd)"
WORKSPACE="$(cd "${IMAGE_DIR}/../.." && pwd)"

KATA_VERSION="${KATA_VERSION:-3.30.0}"
# Immutable commit that the KATA_VERSION git tag resolved to at pin time —
# used to fetch the kata source (osbuilder) below. A git tag is mutable: a
# re-pointed 3.30.0 would silently swap the osbuilder source baked into the
# dm-verity measured rootfs, and thus the SNP launch measurement. So pin the
# commit, not the tag. Keep it in lockstep with KATA_VERSION; re-resolve on a
# bump with:
#   gh api repos/kata-containers/kata-containers/git/refs/tags/<ver> --jq .object.sha
# (The kata-static release asset in stage-kata-conf.sh is separately
# sha256-pinned, so that download already can't drift.)
KATA_SRC_COMMIT="${KATA_SRC_COMMIT:-86e5975ad6a20f091ed686e492672c70496d0400}"
# ext4, not erofs: kata 3.30.0's osbuilder only implements the dm-verity /
# measured-rootfs path for ext4 (create_rootfs_image). Its erofs path
# (create_erofs_rootfs_image) loop-attaches the image before creating it
# AND never runs veritysetup — so erofs + MEASURED_ROOTFS is broken there.
# ext4 is kata's standard measured-rootfs fs. mkfs.ext4 would otherwise write
# a random UUID/hash-seed/timestamps; the reproducibility knobs below
# (SOURCE_DATE_EPOCH + mtime normalisation + fixed VERITY_SALT) pin all of it
# so the verity root_hash is bit-for-bit reproducible across builds.
FS_TYPE="${FS_TYPE:-ext4}"
BUILD_VARIANT="${BUILD_VARIANT:-c8s}"
DISTRO="${DISTRO:-ubuntu}"
# osbuilder's ubuntu rootfs requires the release codename. kata 3.30's
# agent ships from the ubuntu-noble confidential rootfs, so match it.
OS_VERSION="${OS_VERSION:-noble}"

# --- Reproducibility knobs -------------------------------------------------
# Fixed so two builds from the same inputs produce the same dm-verity
# root_hash (which rides in the launch measurement, so verifiers can recompute
# it). Three independent sources of per-build randomness are pinned:
#   SOURCE_DATE_EPOCH  mke2fs derives a deterministic FS UUID + dir-hash-seed +
#                      created-time from it (e2fsprogs >= 1.45.7); we also stamp
#                      every rootfs file's mtime to it before sealing (image_
#                      builder's `cp -a` preserves those into the ext4 inodes).
#   VERITY_SALT        veritysetup would otherwise pick a random salt, changing
#                      root_hash even for byte-identical content. Public value
#                      (rides in the cmdline and is measured) — fixed, not secret.
#   UBUNTU_REPO_URL    pins the apt archive. Empty -> osbuilder's default
#                      archive.ubuntu.com (drifts over time). Set to
#                      https://snapshot.ubuntu.com/ubuntu/<YYYYMMDDTHHMMSSZ> to
#                      time-pin the base (old snapshots also need apt
#                      Check-Valid-Until=false in osbuilder's mmdebstrap call).
export SOURCE_DATE_EPOCH="${SOURCE_DATE_EPOCH:-1704067200}"   # 2024-01-01T00:00:00Z
VERITY_SALT="${VERITY_SALT:-c8c8c8c8c8c8c8c8c8c8c8c8c8c8c8c8c8c8c8c8c8c8c8c8c8c8c8c8c8c8c8c8}"
UBUNTU_REPO_URL="${UBUNTU_REPO_URL:-}"
# mkfs.ext4 randomises the FS UUID and directory hash-seed regardless of
# SOURCE_DATE_EPOCH (which only pins timestamps), and tune2fs can only reset the
# UUID, not the hash-seed. Both live in the superblock that dm-verity hashes, so
# we inject fixed values at mkfs time (see the image_builder patch below).
FIXED_FS_UUID="${FIXED_FS_UUID:-c8c8c8c8-c8c8-c8c8-c8c8-c8c8c8c8c8c8}"
FIXED_HASH_SEED="${FIXED_HASH_SEED:-d8d8d8d8-d8d8-d8d8-d8d8-d8d8d8d8d8d8}"

STEEP_DIR="${STEEP_DIR:-${WORKSPACE}/steep}"
OUTPUT_DIR="${OUTPUT_DIR:-${IMAGE_DIR}/output}"
DEBUG_OUTPUT_DIR="${DEBUG_OUTPUT_DIR:-${IMAGE_DIR}/output-debug}"
NVIDIA_OUTPUT_DIR="${NVIDIA_OUTPUT_DIR:-${IMAGE_DIR}/output-nvidia}"
NVIDIA_DEBUG_OUTPUT_DIR="${NVIDIA_DEBUG_OUTPUT_DIR:-${IMAGE_DIR}/output-nvidia-debug}"
WORK_DIR="${WORK_DIR:-${IMAGE_DIR}/.build}"
KATA_SRC="${KATA_SRC:-${WORK_DIR}/kata-${KATA_VERSION}}"

EXTRA_DIR="${IMAGE_DIR}/extra"
EXTRA_NVIDIA_DIR="${IMAGE_DIR}/extra-nvidia"
# GPU variant (Step 6). auto = build when the stock kata NVIDIA artifacts are
# present at the paths below, skip loudly otherwise; 1 = require; 0 = skip.
# CI sets BUILD_NVIDIA=1 and points both paths at artifacts staged from the
# sha-pinned kata-static release (scripts/ci/stage-kata-conf.sh) — the build
# does not depend on runner state; the /opt/kata defaults below are a
# local-dev fallback for a box that already has kata-deploy's payload.
# The NVIDIA driver payload (kernel modules, GSP firmware, driver userland)
# is grafted from kata's own nvidia-gpu-confidential rootfs image — the SAME
# digest-pinned kata release that provides the agent — and the GPU variant
# boots kata's matching GPU kernel, NOT the steep one (the steep kernel has
# CONFIG_MODULES=n; the NVIDIA modules need the kernel they were built for).
BUILD_NVIDIA="${BUILD_NVIDIA:-auto}"
KATA_NVIDIA_CONFIDENTIAL_IMG="${KATA_NVIDIA_CONFIDENTIAL_IMG:-/opt/kata/share/kata-containers/kata-containers-nvidia-gpu-confidential.img}"
KATA_NVIDIA_VMLINUZ="${KATA_NVIDIA_VMLINUZ:-/opt/kata/share/kata-containers/vmlinuz-nvidia-gpu.container}"
# c8s's kernel config fragment, merged after steep's required + hardening
# baseline by `steep kernel --kernel-config-fragment`. steep resolves the
# merged .config and writes it to a fixed path in its own tree (the old
# --kernel-snapshot flag is gone). That snapshot is NOT a build input —
# steep regenerates it from scratch each resolve — but it is the only
# place the effect of steep's baseline (kernel version / hardening) on OUR
# guest kernel is visible. So after the kernel build Step 1 copies steep's
# snapshot into this repo (KERNEL_SNAPSHOT), committed, so any drift is
# reviewable in git. See README.md "Build" + container.config header.
KERNEL_FRAGMENT="${IMAGE_DIR}/kernel/container.config"
# Resolved-config lockfile: steep writes STEEP_SNAPSHOT during the kernel
# build; Step 1 copies it to KERNEL_SNAPSHOT (tracked in git) for drift
# detection. Not read by the build.
KERNEL_SNAPSHOT="${IMAGE_DIR}/kernel/config-x86_64.snapshot"
STEEP_SNAPSHOT="${STEEP_DIR}/kernel/config-x86_64.snapshot"

log() { printf '\n=== %s ===\n' "$*"; }
die() { echo "FATAL: $*" >&2; exit 1; }

# --- Preflight ----------------------------------------------------------
command -v docker >/dev/null 2>&1 || die "docker not found — osbuilder builds the rootfs/image inside Docker. Install docker.io and start the daemon."
command -v sudo   >/dev/null 2>&1 || die "sudo not found — osbuilder needs root for loop devices + partitioning."
command -v jq     >/dev/null 2>&1 || die "jq not found — needed to emit manifest.json. Install jq."
# osbuilder reads kata's versions.yaml (rust/go toolchain pins) with yq to
# compute the rootfs-builder Docker build-args; without it RUST_TOOLCHAIN
# comes back empty and the rustup install fails with a cryptic
# '--default-toolchain <...> required' error.
command -v yq >/dev/null 2>&1 || die "yq not found — osbuilder needs it to read kata's versions.yaml. Install mikefarah yq (pinned + checksummed; it shapes the measured guest rootfs build-args):
       sudo curl -fsSL -o /usr/local/bin/yq https://github.com/mikefarah/yq/releases/download/v4.44.6/yq_linux_amd64 && echo '0c2b24e645b57d8e7c0566d18643a6d4f5580feeea3878127354a46f2a1e4598  /usr/local/bin/yq' | sha256sum -c - && sudo chmod +x /usr/local/bin/yq"

# Guest-pull sandboxes need a pause image baked into the rootfs at
# /pause_bundle — the kata-agent unpacks it for the sandbox (pause) container
# rather than pulling it (that pull would be a chicken-and-egg: the sandbox is
# what guest-pull runs inside). Without it every guest-pull pod fails sandbox
# creation with "Pause image not present in rootfs" (src/agent/.../
# confidential_data_hub/image.rs). We build the bundle the same way kata's
# tools/packaging/static-build/pause-image/build-static-pause-image.sh does:
# skopeo copy into an OCI layout, then umoci unpack into a runtime bundle.
command -v skopeo >/dev/null 2>&1 || die "skopeo not found — needed to fetch the pause image for the guest /pause_bundle. Install: sudo apt-get install -y skopeo"
command -v umoci  >/dev/null 2>&1 || die "umoci not found — needed to unpack the pause image into an OCI runtime bundle. Install the static binary (pinned + checksummed; it feeds the measured guest root):
       sudo curl -fsSL -o /usr/local/bin/umoci https://github.com/opencontainers/umoci/releases/download/v0.6.0/umoci.linux.amd64 && echo 'b51c267ec394499e42c6fde47f240b7b7dba57ea49df0b5acd304378b82a3b71  /usr/local/bin/umoci' | sha256sum -c - && sudo chmod +x /usr/local/bin/umoci"

# The image step (Step 4) seals the rootfs into a partitioned dm-verity
# image. We run it on the HOST, not in a container: loop-device partition
# scanning (losetup -P) is unreliable inside podman/docker (it fails with
# `losetup: ... failed to set up loop device` / `p1 is not a block
# device`). That needs these host tools — the same set kata's
# image-builder Dockerfile installs.
for t in "mkfs.${FS_TYPE}" veritysetup parted qemu-img; do
    command -v "${t}" >/dev/null 2>&1 \
        || PATH="${PATH}:/usr/sbin:/sbin" command -v "${t}" >/dev/null 2>&1 \
        || die "${t} not found — needed to build the verity image on the host. Install: sudo apt-get install -y erofs-utils cryptsetup-bin parted gdisk e2fsprogs qemu-utils"
done

# image_builder uses `losetup -P` to partition the image. On hosts where
# the loop module isn't auto-loaded, losetup fails with `failed to set up
# loop device: No such file or directory`. Load it best-effort up front.
sudo modprobe loop 2>/dev/null || true

[[ -f "${KERNEL_FRAGMENT}" ]] || die "${KERNEL_FRAGMENT} missing (c8s kernel config fragment, merged after steep's required + hardening baseline) — see README."

# The overlay binaries must be staged before we build the rootfs image,
# because they end up in the dm-verity root (and thus the measurement).
for bin in ratls-mesh policy-monitor attestation-service rtmr3-measurer; do
    [[ -x "${EXTRA_DIR}/usr/local/bin/${bin}" ]] || die "${EXTRA_DIR}/usr/local/bin/${bin} missing — run scripts/fetch.sh first."
done
[[ -f "${EXTRA_DIR}/etc/c8s/bootstrap-allowlist.json" ]] || die "bootstrap-allowlist.json not staged — run scripts/fetch.sh (with IMAGE_TAG or *_DIGEST env vars) first."
[[ -f "${EXTRA_DIR}/etc/kata-opa/default-policy.rego" ]] || die "default-policy.rego missing from overlay."

# In-guest GHCR registry auth for private guest-pull. fetch.sh bakes this
# from READ_PRIVATE_GHCR_TOKEN; tmpfiles copies it to
# /run/image-security/auth.json, the file:// path the kata cmdline names
# (agent.image_registry_auth, set by the puller). If build.sh is run
# standalone without fetch.sh, bake an empty auth set so that path still
# resolves — anonymous pulls, no credential in the measured rootfs.
GHCR_AUTH_FILE="${EXTRA_DIR}/etc/c8s/ghcr-auth.json"
if [[ ! -s "${GHCR_AUTH_FILE}" ]]; then
    echo "    NOTE: ${GHCR_AUTH_FILE} not staged by fetch.sh — baking empty auths (anonymous guest-pull)." >&2
    mkdir -p "$(dirname "${GHCR_AUTH_FILE}")"
    ( umask 077; printf '{"auths":{}}\n' > "${GHCR_AUTH_FILE}" )
fi

# A prior run's images must not survive to publish time: CI pushes the output
# dirs verbatim (oras push ./*), and on a persistent runner the root-owned
# artifacts dodge actions/checkout's git clean. Wipe them up front —
# SKIP_KERNEL=1 keeps only the reusable kernel.
if [[ "${SKIP_KERNEL:-0}" == "1" && -f "${OUTPUT_DIR}/vmlinuz" ]]; then
    sudo find "${OUTPUT_DIR}" -mindepth 1 ! -name vmlinuz -exec rm -rf {} +
else
    sudo rm -rf "${OUTPUT_DIR}"
fi
sudo rm -rf "${DEBUG_OUTPUT_DIR}" "${NVIDIA_OUTPUT_DIR}" "${NVIDIA_DEBUG_OUTPUT_DIR}"
mkdir -p "${OUTPUT_DIR}" "${WORK_DIR}"

# --- Step 1/5: hardened kernel (steep) ---------------------------------
# We only use steep to compile the kernel; the rootfs is osbuilder's job.
VMLINUZ_OUT="${OUTPUT_DIR}/vmlinuz"
if [[ "${SKIP_KERNEL:-0}" == "1" && -f "${VMLINUZ_OUT}" ]]; then
    log "Step 1/5: reusing existing kernel (SKIP_KERNEL=1): ${VMLINUZ_OUT}"
else
    log "Step 1/5: building hardened kernel with steep"
    [[ -d "${STEEP_DIR}" ]] || die "steep checkout not found at ${STEEP_DIR} (set STEEP_DIR)."
    STEEP_BIN="${STEEP_BIN:-${STEEP_DIR}/target/release/steep}"
    if [[ ! -x "${STEEP_BIN}" ]]; then
        echo "    building steep (cargo build --release)"
        ( cd "${STEEP_DIR}" && cargo build --release )
    fi
    # steep writes output/kernel/vmlinuz relative to its own dir. steep
    # resolves its config snapshot internally (fixed kernel/config-x86_64.snapshot
    # in the steep tree, auto-updated each build), so we pass only the fragment —
    # the old --kernel-snapshot flag no longer exists.
    ( cd "${STEEP_DIR}" && "${STEEP_BIN}" kernel \
        --kernel-config-fragment "${KERNEL_FRAGMENT}" )
    STEEP_VMLINUZ="${STEEP_DIR}/output/kernel/vmlinuz"
    [[ -f "${STEEP_VMLINUZ}" ]] || die "steep did not produce ${STEEP_VMLINUZ}"
    install -m 0644 "${STEEP_VMLINUZ}" "${VMLINUZ_OUT}"

    # Capture the resolved-config snapshot steep just wrote (baseline +
    # our container.config, merged). steep keeps it in its own tree where
    # it gets overwritten/discarded; copy it next to the fragment in THIS
    # repo so the merged config is committed and reviewable — this is how a
    # change in steep's kernel base that affects our guest kernel becomes
    # visible here. Not a build input. (SKIP_KERNEL reuses an existing
    # vmlinuz without re-resolving, so it intentionally leaves the
    # committed snapshot untouched.)
    [[ -f "${STEEP_SNAPSHOT}" ]] || die "steep did not produce ${STEEP_SNAPSHOT} — cannot capture the resolved-config snapshot."
    # Drift gate: compare the freshly-resolved config against the committed
    # lockfile BEFORE overwriting it. CHECK_SNAPSHOT=1 (set by CI on the
    # publish path) makes a mismatch fatal HERE — at Step 1, before osbuilder
    # (Steps 2-5) and the GHCR push — so a guest image whose kernel config
    # drifted from what's committed/reviewed never gets built or published.
    # Local builds leave CHECK_SNAPSHOT unset and just refresh the lockfile.
    snapshot_drift=0
    if [[ -f "${KERNEL_SNAPSHOT}" ]] && ! cmp -s "${STEEP_SNAPSHOT}" "${KERNEL_SNAPSHOT}"; then
        snapshot_drift=1
        committed_sha="$(sha256sum "${KERNEL_SNAPSHOT}" | awk '{print $1}')"
    fi
    # Copy regardless (so the uploaded artifact reflects what THIS build
    # resolved, even on a gate failure) — then enforce.
    install -m 0644 "${STEEP_SNAPSHOT}" "${KERNEL_SNAPSHOT}"
    echo "    snapshot: ${KERNEL_SNAPSHOT} (sha256 $(sha256sum "${KERNEL_SNAPSHOT}" | awk '{print $1}'))"
    if [[ "${CHECK_SNAPSHOT:-0}" == "1" && "${snapshot_drift}" == "1" ]]; then
        die "resolved kernel config drifted from the committed snapshot.
       committed ${KERNEL_SNAPSHOT}: ${committed_sha}
       resolved  (this build):       $(sha256sum "${KERNEL_SNAPSHOT}" | awk '{print $1}')
   steep's baseline (STEEP_REF) or kernel/container.config changed without
   re-committing kata-guest-base/kernel/config-x86_64.snapshot. Re-resolve and
   commit it (run the 'Kernel config snapshot' workflow, or a local build), or
   revert the change that moved it. Failing before osbuilder + the GHCR push."
    fi
fi
echo "    kernel: ${VMLINUZ_OUT}"

# --- Fetch kata source (for osbuilder) ---------------------------------
OSBUILDER="${KATA_SRC}/tools/osbuilder"
if [[ ! -d "${OSBUILDER}" ]]; then
    log "Fetching kata-containers ${KATA_VERSION} source (osbuilder) at ${KATA_SRC_COMMIT} via gh"
    command -v gh >/dev/null 2>&1 || die "gh not found — needed to fetch the kata source tarball (the repo's git remote is SSH-gated)."
    mkdir -p "${KATA_SRC}"
    # Pin the commit, not the tag: the tarball feeds the measured rootfs (see
    # KATA_SRC_COMMIT). gh api resolves a commit SHA the same as a tag ref.
    gh api "repos/kata-containers/kata-containers/tarball/${KATA_SRC_COMMIT}" \
        > "${WORK_DIR}/kata-src.tar.gz"
    tar xzf "${WORK_DIR}/kata-src.tar.gz" -C "${KATA_SRC}" --strip-components=1
    [[ -d "${OSBUILDER}" ]] || die "osbuilder not found at ${OSBUILDER} after extract — kata source layout changed?"
fi
echo "    osbuilder: ${OSBUILDER}"

# osbuilder writes the rootfs tree and the image under paths we control,
# so the overlay can be injected between the two phases.
ROOTFS_BUILD_DEST="${WORK_DIR}/rootfs"
IMAGES_BUILD_DEST="${WORK_DIR}/images"
TARGET_ROOTFS="${ROOTFS_BUILD_DEST}/${DISTRO}_rootfs"
# osbuilder bind-mounts GOPATH into the rootfs-builder container (it uses
# yq there). Under sudo, GOPATH defaults to ${HOME}/go = /root/go, which
# doesn't exist -> the container run dies with `statfs /root/go: no such
# file or directory`. Point it at a dir under the build tree instead.
GO_PATH_DIR="${WORK_DIR}/go"
mkdir -p "${ROOTFS_BUILD_DEST}" "${IMAGES_BUILD_DEST}" "${GO_PATH_DIR}"

# --- Step 2/5: base rootfs (osbuilder) ---------------------------------
# AGENT_INIT=no  -> systemd-based rootfs (our services run as units).
# AGENT_POLICY=yes -> build kata-agent WITH the OPA/regorus policy engine
#   so the baked /etc/kata-opa/default-policy.rego is actually enforced
#   (the load-bearing `SetPolicyRequest := false` rule). osbuilder drops
#   its default allow-all policy here; Step 3 overlays OUR policy on top.
# EXTRA_PKGS: the in-guest attestation-service binary is dynamically linked
# against the TPM2-TSS runtime (libtss2-esys/-mu/-sys/-tctildr) — even on SNP,
# where it reads /dev/sev-guest — so without these libs it fails to load with
# "libtss2-esys.so.0: cannot open shared object file" and ratls-mesh's
# Requires=attestation-service.service then blocks c8s-ready.target. osbuilder's
# ubuntu rootfs_lib feeds EXTRA_PKGS to debootstrap --include. Names are the
# ubuntu-noble (t64) package names.
# ca-certificates: attestation-service's background cert-cache warm-up and the
# verifier path fetch AMD KDS / Intel PCS collateral over HTTPS and need the CA
# bundle to validate those TLS connections (osbuilder's `required`-variant
# rootfs ships none). The boot path (/attest) is network-free, so a missing
# bundle would only degrade verification — but it is cheap and in `main`.
# cryptsetup-bin: scratch-setup.service opens the ephemeral image-store scratch
# disk under dm-crypt (see extra/usr/local/lib/c8s/scratch-setup.sh). In noble main.
# Only `main`-component packages are installable (osbuilder sets
# REPO_COMPONENTS=main); universe packages (e.g. traceroute, mtr-tiny) fail the
# rootfs build with "no installation candidate".
# kmod: modprobe for the GPU variant's nvidia-gpu-init.sh (nvidia +
# nvidia-uvm load; udev's builtin libkmod only auto-loads nvidia via PCI
# modalias — nvidia-uvm has no modalias). Without it the unit exits 127,
# kata-agent never starts, and every GPU pod hangs in ContainerCreating.
KATA_EXTRA_PKGS="libtss2-esys-3.0.2-0t64 libtss2-mu-4.0.1-0t64 libtss2-sys1t64 libtss2-tctildr0t64 ca-certificates kmod cryptsetup-bin"
# --- Step 1b/5: stage the confidential guest-components ------------------------
# confidential-data-hub (CDH), attestation-agent (AA), api-server-rest. The
# kata-agent SPAWNS these at boot (its guest_components_procs default is
# ApiServerRest, which implies CDH + AA) and performs in-guest image guest-pull
# by delegating to CDH over /run/confidential-containers/cdh.sock. WITHOUT them
# the agent's pull_image blocks on that never-created socket and EVERY workload
# CreateContainer times out at 60s — no network, no rootfs (the original
# broker-boot blocker). osbuilder only installs them when handed
# COCO_GUEST_COMPONENTS_TARBALL, so we stage the version-matched binaries into
# the extra/ overlay (Step 3 rsyncs them to /usr/local/bin, sealed into the
# verity root). Source: kata's own confidential rootfs image — the SAME kata
# release that provides the agent, so the agent<->CDH ttRPC versions match.
# Override KATA_CONFIDENTIAL_IMG (or pre-stage the three binaries in
# extra/usr/local/bin/) in a build env without kata-deploy's /opt/kata.
GC_BIN_DIR="${EXTRA_DIR}/usr/local/bin"
GUEST_COMPONENTS=(confidential-data-hub attestation-agent api-server-rest)
need_gc=0
for gc in "${GUEST_COMPONENTS[@]}"; do [[ -x "${GC_BIN_DIR}/${gc}" ]] || need_gc=1; done
if [[ "${need_gc}" == "1" ]]; then
    KATA_CONFIDENTIAL_IMG="${KATA_CONFIDENTIAL_IMG:-/opt/kata/share/kata-containers/kata-ubuntu-noble-confidential.image}"
    [[ -f "${KATA_CONFIDENTIAL_IMG}" ]] || die "confidential guest-components missing from ${GC_BIN_DIR} and KATA_CONFIDENTIAL_IMG=${KATA_CONFIDENTIAL_IMG} not found. Stage confidential-data-hub/attestation-agent/api-server-rest there, or point KATA_CONFIDENTIAL_IMG at a kata confidential rootfs image, or set COCO_GUEST_COMPONENTS_TARBALL."
    log "Step 1b/5: staging confidential guest-components from ${KATA_CONFIDENTIAL_IMG}"
    gc_loop="$(sudo losetup -fP --show "${KATA_CONFIDENTIAL_IMG}")"
    gc_mnt="$(mktemp -d)"
    sudo mount -o ro "${gc_loop}p1" "${gc_mnt}"
    for gc in "${GUEST_COMPONENTS[@]}"; do
        sudo install -m 0755 "${gc_mnt}/usr/local/bin/${gc}" "${GC_BIN_DIR}/${gc}"
        sudo chown "$(id -u):$(id -g)" "${GC_BIN_DIR}/${gc}"
    done
    sudo umount "${gc_mnt}"; sudo losetup -d "${gc_loop}"; rmdir "${gc_mnt}"
else
    log "Step 1b/5: confidential guest-components already staged in ${GC_BIN_DIR}"
fi
for gc in "${GUEST_COMPONENTS[@]}"; do log "  guest-component: ${gc} ($(stat -c%s "${GC_BIN_DIR}/${gc}") bytes)"; done

# CI cache hook (kata-guest-base.yml "Restore base rootfs"): the Step 2 output
# is fully determined by KATA_VERSION / DISTRO / OS_VERSION / AGENT_* /
# EXTRA_PKGS — nothing commit-specific enters the rootfs until Step 3's
# overlay — so it is reusable across builds. When ROOTFS_CACHE_TAR names an
# existing tarball, unpack it instead of rebuilding (skipping the
# rootfs-builder docker build, the debootstrap against snapshot.ubuntu.com,
# and the in-container agent/libseccomp builds); when it names a missing path,
# pack the freshly built rootfs there for the workflow to save. The pack runs
# immediately after Step 2, before the later steps that historically fail, so
# even a broken build leaves a reusable base rootfs.
#
# sudo tar with --numeric-owner / --xattrs: the tree is root-owned and carries
# security.capability xattrs, all of which feed the measured verity root — a
# tar that drops them would silently corrupt the guest. (This is also why the
# workflow can't point actions/cache at the directory: its tar runs as the
# runner user and loses ownership.)
ROOTFS_TAR_FLAGS=(--zstd --numeric-owner --xattrs --xattrs-include='*')
if [[ -n "${ROOTFS_CACHE_TAR:-}" && -f "${ROOTFS_CACHE_TAR}" ]]; then
    log "Step 2/5: restoring base ${DISTRO} rootfs from ${ROOTFS_CACHE_TAR}"
    sudo rm -rf "${TARGET_ROOTFS}"
    sudo mkdir -p "${TARGET_ROOTFS}"
    sudo tar "${ROOTFS_TAR_FLAGS[@]}" -xpf "${ROOTFS_CACHE_TAR}" -C "${TARGET_ROOTFS}"
else
    log "Step 2/5: building ${DISTRO} rootfs with osbuilder (kata-agent included)"
    sudo make -C "${OSBUILDER}" \
        DISTRO="${DISTRO}" \
        OS_VERSION="${OS_VERSION}" \
        GOPATH="${GO_PATH_DIR}" \
        AGENT_INIT=no \
        AGENT_POLICY=yes \
        USE_DOCKER=1 \
        EXTRA_PKGS="${KATA_EXTRA_PKGS}" \
        REPO_URL_X86_64="${UBUNTU_REPO_URL}" \
        ROOTFS_BUILD_DEST="${ROOTFS_BUILD_DEST}" \
        rootfs
    [[ -d "${TARGET_ROOTFS}" ]] || die "osbuilder did not produce a rootfs at ${TARGET_ROOTFS}"
    if [[ -n "${ROOTFS_CACHE_TAR:-}" ]]; then
        log "Packing base rootfs into ${ROOTFS_CACHE_TAR} (pre-overlay, for the CI cache)"
        sudo tar "${ROOTFS_TAR_FLAGS[@]}" -cpf "${ROOTFS_CACHE_TAR}" -C "${TARGET_ROOTFS}" .
        sudo chown "$(id -u):$(id -g)" "${ROOTFS_CACHE_TAR}"
    fi
fi
[[ -d "${TARGET_ROOTFS}" ]] || die "base rootfs missing at ${TARGET_ROOTFS}"

# --- Step 3/5: overlay the c8s layer -----------------------------------
# Drop our binaries, systemd units, OPA policy (overwriting osbuilder's
# allow-all), the bootstrap allowlist, tmpfiles, and the cloud-init env
# helper into the rootfs, then enable our units offline so they come up
# at boot. We do NOT ship a kata-agent.service in the overlay — osbuilder
# already installed and enabled the version-matched one.
log "Step 3/5: overlaying c8s layer into the rootfs"
sudo rsync -a "${EXTRA_DIR}/" "${TARGET_ROOTFS}/"

# Enable our units offline (creates the .wants symlinks in the rootfs).
# systemctl --root operates on an offline tree without booting it.
C8S_UNITS=(
    c8s-ready.target
    attestation-service.service
    ratls-mesh.service
    policy-monitor.service
    rtmr3-measurer.service
    scratch-setup.service
    c8s-cloudinit-env.service
)
# kata boots the guest with `systemd.unit=kata-containers.target` on the kernel
# cmdline, which does NOT pull in multi-user.target. Units that are only
# WantedBy=multi-user.target (our [Install] sections + 50-c8s.preset) therefore
# never start, so c8s-ready.target is never reached and the kata-agent's
# CreateContainer hook times out. `enable` below still creates the
# multi-user.target.wants links (correct for a normal boot / debug); the extra
# kata-containers.target.wants symlink is what actually starts them under kata.
KATA_WANTS_DIR="${TARGET_ROOTFS}/etc/systemd/system/kata-containers.target.wants"
sudo mkdir -p "${KATA_WANTS_DIR}"
for unit in "${C8S_UNITS[@]}"; do
    if [[ -f "${TARGET_ROOTFS}/etc/systemd/system/${unit}" ]]; then
        sudo systemctl --root="${TARGET_ROOTFS}" enable "${unit}" \
            || echo "    WARN: could not enable ${unit} offline; relying on 50-c8s.preset" >&2
        sudo ln -sf "/etc/systemd/system/${unit}" "${KATA_WANTS_DIR}/${unit}"
    fi
done

# --- Step 3b/5: bake the pause bundle for guest-pull -------------------
# The kata-agent reads /pause_bundle (config.json + rootfs) to start the
# sandbox/pause container under guest-pull; it cannot pull the pause image.
# We drop the bundle straight into the rootfs here so it's sealed into the
# verity root (covered by the launch measurement) in Step 4. Version is
# pinned from kata's own versions.yaml so the pause image tracks the kata
# release. Same skopeo+umoci flow as kata's build-static-pause-image.sh.
PAUSE_REPO="$(yq '.externals.pause.repo' "${KATA_SRC}/versions.yaml")"
PAUSE_VER="$(yq '.externals.pause.version' "${KATA_SRC}/versions.yaml")"
[[ -n "${PAUSE_REPO}" && "${PAUSE_REPO}" != "null" ]] || die "could not read externals.pause.repo from ${KATA_SRC}/versions.yaml"
[[ -n "${PAUSE_VER}" && "${PAUSE_VER}" != "null" ]] || die "could not read externals.pause.version from ${KATA_SRC}/versions.yaml"
log "Step 3b/5: baking pause bundle (${PAUSE_REPO}:${PAUSE_VER}) into the rootfs"
rm -rf "${WORK_DIR}/pause-oci" "${WORK_DIR}/pause_bundle"
skopeo copy "${PAUSE_REPO}:${PAUSE_VER}" "oci:${WORK_DIR}/pause-oci:${PAUSE_VER}"
umoci unpack --rootless --image "${WORK_DIR}/pause-oci:${PAUSE_VER}" "${WORK_DIR}/pause_bundle"
[[ -f "${WORK_DIR}/pause_bundle/config.json" ]] || die "umoci did not produce pause_bundle/config.json"
# Reproducibility: umoci emits the OCI runtime config.json with mount `options`
# arrays in Go-map (non-deterministic) order — the only field that varies
# build-to-build. Canonicalise by sorting each options array (order is
# semantically irrelevant for mount flags).
jq '(.mounts // []) |= map(if has("options") then .options |= sort else . end)' \
    "${WORK_DIR}/pause_bundle/config.json" > "${WORK_DIR}/pause_bundle/config.json.tmp"
mv "${WORK_DIR}/pause_bundle/config.json.tmp" "${WORK_DIR}/pause_bundle/config.json"
sudo rm -rf "${TARGET_ROOTFS}/pause_bundle"
sudo cp -a "${WORK_DIR}/pause_bundle" "${TARGET_ROOTFS}/pause_bundle"

# --- Reproducibility normalisation (must be the LAST rootfs mutation) ------
# 1. umoci writes a *.mtree metadata manifest into the pause bundle whose bytes
#    embed timestamps — the ONLY file that differs between two builds. It is
#    unused at runtime (kata reads config.json + rootfs/), so drop it.
# 2. Stamp every file's mtime to SOURCE_DATE_EPOCH so the sealed ext4's inode
#    timestamps are deterministic (image_builder's `cp -a` preserves them).
# Together with SOURCE_DATE_EPOCH-driven mke2fs (deterministic UUID/hash-seed/
# created-time) and the fixed VERITY_SALT in seal_and_assemble, this makes the
# dm-verity root_hash bit-for-bit reproducible.
sudo find "${TARGET_ROOTFS}/pause_bundle" -name '*.mtree' -delete
sudo find "${TARGET_ROOTFS}" -exec touch --no-dereference --date="@${SOURCE_DATE_EPOCH}" {} +

# --- Steps 4-5: seal each variant into a verity image ------------------
# seal_and_assemble <variant> <outdir>: seals the CURRENT state of
# ${TARGET_ROOTFS} into a dm-verity image and assembles the flat artifact
# layout the puller expects (vmlinuz, kata-rootfs.img, sidecars,
# manifest.json) into <outdir>. Called once per variant; the caller owns
# what is in the rootfs tree at that point.
#
# MEASURED_ROOTFS=yes makes image_builder.sh lay out p1=rootfs / p2=hash
# and run `veritysetup format --no-superblock` (exactly what kata's
# dm-mod.create expects), writing the verity params to
# root_hash_<variant>.txt.
#
# We deliberately do NOT set USE_DOCKER here — image_builder runs on the
# host so its losetup -P partition scan works (it doesn't inside a
# container). The host-tool preflight above guarantees the deps are present.
seal_and_assemble() {
    local variant="$1" outdir="$2"
    # Third arg: kernel to ship with (and hash into) this artifact. Defaults
    # to the steep kernel; the NVIDIA variants pass kata's GPU kernel, which
    # the grafted driver modules were built for.
    local kernel="${3:-${VMLINUZ_OUT}}"
    local img="${IMAGES_BUILD_DEST}/kata-rootfs-${variant}.img"
    sudo env \
        MEASURED_ROOTFS=yes \
        BUILD_VARIANT="${variant}" \
        AGENT_INIT=no \
        SOURCE_DATE_EPOCH="${SOURCE_DATE_EPOCH}" \
        "${OSBUILDER}/image-builder/image_builder.sh" \
        -o "${img}" \
        -f "${FS_TYPE}" \
        "${TARGET_ROOTFS}"
    [[ -f "${img}" ]] || die "image_builder did not produce ${img}"

    # image_builder writes the verity params next to the image it created.
    local hash_file
    hash_file="$(dirname "${img}")/root_hash_${variant}.txt"
    [[ -f "${hash_file}" ]] || die "verity params file ${hash_file} not produced — was MEASURED_ROOTFS honoured?"

    # Reproducibility: image_builder builds p1 by mounting an empty ext4 and
    # `cp -a`-ing files in, which leaves the block allocation, journal and mount
    # metadata non-deterministic (identical content, different physical layout —
    # ~114MB of the image differs build-to-build), and veritysetup then picks a
    # random salt. Re-lay p1 deterministically: extract its final content (which
    # includes image_builder's selinux/systemd setup), restamp mtimes to
    # SOURCE_DATE_EPOCH, and repopulate the SAME partition with `mkfs.ext4 -d`
    # (offline, deterministic order, no mount) with pinned UUID/hash-seed and
    # fully-initialised inode tables/journal. Then verity-seal with the fixed
    # salt. Same inputs -> identical root_hash. Reuse image_builder's block
    # geometry so data_blocks/verity layout are unchanged.
    local db dbs hbs loopdev newroot mnt tree
    db="$(grep -oE 'data_blocks=[0-9]+' "${hash_file}" | cut -d= -f2)"
    dbs="$(grep -oE 'data_block_size=[0-9]+' "${hash_file}" | cut -d= -f2)"
    hbs="$(grep -oE 'hash_block_size=[0-9]+' "${hash_file}" | cut -d= -f2)"
    loopdev="$(sudo losetup -fP --show "${img}")"
    mnt="$(mktemp -d)"; tree="$(mktemp -d)"
    sudo mount -o ro "${loopdev}p1" "${mnt}"
    sudo cp -a "${mnt}/." "${tree}/"
    sudo umount "${mnt}"; rmdir "${mnt}"
    sudo find "${tree}" -exec touch --no-dereference --date="@${SOURCE_DATE_EPOCH}" {} +
    # `sudo env SOURCE_DATE_EPOCH=...`: sudo's env_reset strips the exported
    # value, and without it mke2fs stamps the superblock + every inode
    # (crtime/ctime) with the build clock — the residual metadata difference.
    sudo env SOURCE_DATE_EPOCH="${SOURCE_DATE_EPOCH}" mkfs.ext4 -q -F -b "${dbs}" -m 0 \
        -U "${FIXED_FS_UUID}" \
        -E "hash_seed=${FIXED_HASH_SEED},lazy_itable_init=0,lazy_journal_init=0" \
        -d "${tree}" "${loopdev}p1"
    sudo rm -rf "${tree}"
    newroot="$(sudo veritysetup format --no-superblock --hash=sha256 --salt="${VERITY_SALT}" \
        --data-block-size="${dbs}" --hash-block-size="${hbs}" --data-blocks="${db}" \
        "${loopdev}p1" "${loopdev}p2" 2>&1 | grep -i 'Root hash:' | awk '{print $NF}')"
    sudo losetup -d "${loopdev}"
    [[ -n "${newroot}" ]] || die "deterministic re-seal produced no root hash for ${variant}"
    printf 'root_hash=%s,salt=%s,data_blocks=%s,data_block_size=%s,hash_block_size=%s' \
        "${newroot}" "${VERITY_SALT}" "${db}" "${dbs}" "${hbs}" | sudo tee "${hash_file}" >/dev/null

    local kvp
    kvp="$(tr -d '\n' < "${hash_file}")"
    [[ "${kvp}" == root_hash=* ]] || die "unexpected verity params: ${kvp}"

    mkdir -p "${outdir}"
    sudo install -m 0644 "${img}" "${outdir}/kata-rootfs.img"
    sudo chown "$(id -u):$(id -g)" "${outdir}/kata-rootfs.img"
    # Step 1 writes the (shared) kernel straight into ${OUTPUT_DIR}; copy it
    # for any other outdir so each artifact is self-contained.
    [[ "${outdir}/vmlinuz" -ef "${kernel}" ]] \
        || install -m 0644 "${kernel}" "${outdir}/vmlinuz"

    local vmlinuz_sha image_sha
    vmlinuz_sha="$(sha256sum "${kernel}" | awk '{print $1}')"
    image_sha="$(sha256sum "${outdir}/kata-rootfs.img" | awk '{print $1}')"

    # The manifest carries everything the c8s side needs to (a) wire the kata
    # config (kernel/image/rootfs_type/kernel_verity_params) and (b) PREDICT
    # the SNP launch digest with sev-snp-measure (OVMF + this vmlinuz + the
    # kata-generated cmdline that embeds kernel_verity_params, at a pinned
    # vcpu count). The launch digest itself is computed downstream once the
    # exact kata cmdline is captured — see docs/kata-guest-base.md.
    jq -n \
        --arg version "2" \
        --arg kata_version "${KATA_VERSION}" \
        --arg fs_type "${FS_TYPE}" \
        --arg build_variant "${variant}" \
        --arg kvp "${kvp}" \
        --arg vmlinuz_sha "${vmlinuz_sha}" \
        --arg image_sha "${image_sha}" \
        --arg built_at "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
        '{
           version: ($version|tonumber),
           boot_model: "kata-direct-kernel",
           kata_version: $kata_version,
           built_at: $built_at,
           rootfs_type: $fs_type,
           build_variant: $build_variant,
           kernel_verity_params: $kvp,
           outputs: {
             kernel:        { path: "vmlinuz",         sha256: $vmlinuz_sha },
             rootfs_image:  { path: "kata-rootfs.img", sha256: $image_sha }
           }
         }' > "${outdir}/manifest.json"

    # Plain-text sidecars so the in-cluster puller (a shell script in the
    # oras image, no jq) can read these without a JSON parser. They mirror
    # manifest.json exactly.
    printf '%s\n' "${kvp}" > "${outdir}/kernel_verity_params"
    printf '%s\n' "${FS_TYPE}" > "${outdir}/rootfs_type"

    echo "    ${variant}: ${outdir}/kata-rootfs.img (${image_sha})"
    echo "    ${variant}: ${kvp}"
}

log "Step 4/5: sealing the locked rootfs into a dm-verity image (on host)"
seal_and_assemble "${BUILD_VARIANT}" "${OUTPUT_DIR}"

# --- Step 5/5: debug variant -------------------------------------------
# Same rootfs, one delta: the kata-agent OPA policy allows the host
# Exec/ReadStream/WriteStream ttRPCs, so `kubectl logs` and `kubectl exec`
# work against kata-qemu-snp pods. That is a deliberate hole in the TEE
# boundary — container I/O becomes readable by the untrusted host — for
# debugging only. SetPolicyRequest stays denied even here. The debug
# image's verity root hash (and therefore its SNP launch measurement)
# differs from the locked image, so attestation pinned to the locked
# reference value rejects debug guests: the two cannot be confused.
#
# The debug policy is GENERATED from the canonical default-policy.rego
# (single source of truth, no second copy to drift); the greps assert the
# flips landed so a format change in the source fails the build instead of
# silently shipping a locked-policy "debug" image.
log "Step 5/5: sealing the DEBUG variant (host log/exec RPCs allowed)"
DEBUG_POLICY="${WORK_DIR}/default-policy-debug.rego"
{
    printf '# DEBUG VARIANT — generated by build.sh from default-policy.rego.\n'
    printf '# Host stream/exec RPCs are ALLOWED: container stdout/stderr and\n'
    printf '# exec sessions are readable by the (untrusted) host. Never run\n'
    printf '# production workloads on this image.\n'
    sed -E 's/^default (ExecProcessRequest|ReadStreamRequest|WriteStreamRequest) := false$/default \1 := true/' \
        "${EXTRA_DIR}/etc/kata-opa/default-policy.rego"
} > "${DEBUG_POLICY}"
for rpc in ExecProcessRequest ReadStreamRequest WriteStreamRequest; do
    grep -q "^default ${rpc} := true$" "${DEBUG_POLICY}" \
        || die "debug policy generation failed: ${rpc} not flipped — did default-policy.rego's rule format change?"
done
grep -q '^default SetPolicyRequest := false$' "${DEBUG_POLICY}" \
    || die "debug policy generation failed: SetPolicyRequest must stay denied"
# The debug-guest marker rides the same variant split as the policy:
# debug-only runtime behaviors key on it (nvidia-gpu-ready.sh tolerates a
# non-CC GPU only when it is present). Fixed bytes — deterministic seal.
DEBUG_MARKER="${WORK_DIR}/debug-guest"
printf 'debug guest variant — generated by build.sh Step 5; locked images must not carry this file.\n' > "${DEBUG_MARKER}"
sudo install -m 0644 "${DEBUG_POLICY}" "${TARGET_ROOTFS}/etc/kata-opa/default-policy.rego"
sudo install -D -m 0644 "${DEBUG_MARKER}" "${TARGET_ROOTFS}/etc/c8s/debug-guest"
seal_and_assemble "${BUILD_VARIANT}-debug" "${DEBUG_OUTPUT_DIR}"

# --- Step 6/6: NVIDIA GPU variants --------------------------------------
# The confidential-GPU guest is the SAME c8s rootfs (same base, same in-guest
# stack — attestation-service / ratls-mesh / policy-monitor — same locked
# policy, same allowlist) plus the NVIDIA payload grafted from kata's own
# nvidia-gpu-confidential rootfs image: driver kernel modules, GSP firmware,
# driver libraries, and the four admin binaries upstream's "chisseled" image
# ships — chiselled as in Canonical's cut-down distroless-style Ubuntu rootfs;
# kata spells it chisseled (tools/osbuilder/rootfs-builder/nvidia/
# nvidia_rootfs.sh chisseled_compute is the authoritative list this graft
# mirrors). Both rootfs trees are ubuntu-noble, so the copied userland shares
# our glibc.
#
# Upstream's GPU image boots NVRC as PID 1; ours boots systemd like the
# non-GPU guest (the in-guest stack is systemd-managed), so NVRC's GPU
# bring-up is re-expressed as three units in extra-nvidia/ (driver+nodes ->
# persistenced -> CDI/CC-ready/lockdown), with kata-agent Requires= the last.
#
# The variant boots kata's GPU kernel (modules must match it), not the steep
# kernel — the one hardening delta vs the non-GPU guest, recorded in
# docs/kata-gpu.md. Measured boot is identical: verity-sealed rootfs, root
# hash on the cmdline, kernel-hashes launch measurement, manifest published.
build_nvidia_variants() {
    log "Step 6/6: NVIDIA GPU variants (graft from ${KATA_NVIDIA_CONFIDENTIAL_IMG})"

    # Steps 4-5 left the DEBUG policy + marker in TARGET_ROOTFS; the locked
    # GPU variant must seal the locked state. Restore before grafting.
    sudo install -m 0644 "${EXTRA_DIR}/etc/kata-opa/default-policy.rego" \
        "${TARGET_ROOTFS}/etc/kata-opa/default-policy.rego"
    sudo rm -f "${TARGET_ROOTFS}/etc/c8s/debug-guest"

    local nv_loop nv_mnt
    nv_loop="$(sudo losetup -fP --show "${KATA_NVIDIA_CONFIDENTIAL_IMG}")"
    nv_mnt="$(mktemp -d)"
    sudo mount -o ro "${nv_loop}p1" "${nv_mnt}"
    # Best-effort cleanup if the graft dies mid-way; the happy path unmounts
    # explicitly right after the graft, before the seals.
    # shellcheck disable=SC2064  # expand now: the values are set here and final
    trap "{ sudo umount '${nv_mnt}'; sudo losetup -d '${nv_loop}'; rmdir '${nv_mnt}'; } 2>/dev/null || true" RETURN

    # Upstream's chisseled tree uses real top-level /lib and /bin; tolerate a
    # usr-merged layout too so an upstream refactor fails loudly, not weirdly.
    local src_lib src_bin
    for src_lib in "${nv_mnt}/lib/x86_64-linux-gnu" "${nv_mnt}/usr/lib/x86_64-linux-gnu" ""; do
        [[ -n "${src_lib}" && -d "${src_lib}" ]] && break
    done
    [[ -n "${src_lib}" ]] || die "no x86_64-linux-gnu libdir in ${KATA_NVIDIA_CONFIDENTIAL_IMG}"
    for src_bin in "${nv_mnt}/bin" "${nv_mnt}/usr/bin" ""; do
        [[ -n "${src_bin}" && -x "${src_bin}/nvidia-smi" ]] && break
    done
    [[ -n "${src_bin}" ]] || die "nvidia-smi not found in ${KATA_NVIDIA_CONFIDENTIAL_IMG}"

    # Kernel modules + GSP firmware: must match KATA_NVIDIA_VMLINUZ (same
    # kata-static payload, same kernel build).
    [[ -d "${nv_mnt}/lib/modules" ]] || die "no /lib/modules in the stock GPU image"
    sudo mkdir -p "${TARGET_ROOTFS}/usr/lib/modules" "${TARGET_ROOTFS}/usr/lib/firmware"
    sudo cp -a "${nv_mnt}/lib/modules/." "${TARGET_ROOTFS}/usr/lib/modules/"
    [[ -d "${nv_mnt}/lib/firmware/nvidia" ]] || die "no /lib/firmware/nvidia (GSP) in the stock GPU image"
    sudo cp -a "${nv_mnt}/lib/firmware/nvidia" "${TARGET_ROOTFS}/usr/lib/firmware/"

    # Driver libraries (libnv* covers libnvidia-* incl. -pkcs11 and libnvat).
    sudo cp -a "${src_lib}"/libnv* "${src_lib}"/libcuda.so.* \
        "${TARGET_ROOTFS}/usr/lib/x86_64-linux-gnu/"
    # Runtime deps the chisseled image carries for persistenced/NVAT that a
    # minimal noble base may lack — copy only what we don't already provide
    # (ours win: same distro release, and ours are the measured baseline).
    local dep base
    for dep in "${src_lib}"/libtirpc.so.* "${src_lib}"/libgssapi_krb5.so.* \
               "${src_lib}"/libkrb5.so.* "${src_lib}"/libkrb5support.so.* \
               "${src_lib}"/libk5crypto.so.* "${src_lib}"/libcom_err.so.* \
               "${src_lib}"/libkeyutils.so.* "${src_lib}"/libxml2.so.* \
               "${src_lib}"/libstdc++.so.* "${src_lib}"/liblzma.so.* \
               "${src_lib}"/libicuuc.so.* "${src_lib}"/libicudata.so.*; do
        [[ -e "${dep}" ]] || continue
        base="$(basename "${dep}")"
        [[ -e "${TARGET_ROOTFS}/usr/lib/x86_64-linux-gnu/${base}" ]] \
            || sudo cp -a "${dep}" "${TARGET_ROOTFS}/usr/lib/x86_64-linux-gnu/"
    done
    [[ -e "${TARGET_ROOTFS}/etc/netconfig" ]] \
        || sudo cp -a "${nv_mnt}/etc/netconfig" "${TARGET_ROOTFS}/etc/netconfig" 2>/dev/null || true

    # The four admin binaries upstream ships (chisseled_compute).
    local nvbin
    for nvbin in nvidia-persistenced nvidia-smi nvidia-ctk nvidia-cdi-hook; do
        sudo install -m 0755 "${src_bin}/${nvbin}" "${TARGET_ROOTFS}/usr/bin/${nvbin}"
    done

    # Graft complete — release the stock image before the (long) seals.
    sudo umount "${nv_mnt}"; sudo losetup -d "${nv_loop}"; rmdir "${nv_mnt}"
    trap - RETURN

    sudo ldconfig -r "${TARGET_ROOTFS}"

    # GPU overlay: the NVRC-replacement units + scripts, then enable them the
    # same way Step 3 enables the c8s units (multi-user wants + the
    # kata-containers.target.wants symlink kata's boot target needs).
    sudo rsync -a "${EXTRA_NVIDIA_DIR}/" "${TARGET_ROOTFS}/"
    local nvunit
    for nvunit in nvidia-gpu-init.service nvidia-persistenced.service nvidia-gpu-ready.service; do
        sudo systemctl --root="${TARGET_ROOTFS}" enable "${nvunit}" \
            || echo "    WARN: could not enable ${nvunit} offline" >&2
        sudo ln -sf "/etc/systemd/system/${nvunit}" \
            "${TARGET_ROOTFS}/etc/systemd/system/kata-containers.target.wants/${nvunit}"
    done

    seal_and_assemble "${BUILD_VARIANT}-nvidia" "${NVIDIA_OUTPUT_DIR}" "${KATA_NVIDIA_VMLINUZ}"

    # GPU debug variant: same two-file debug delta as Step 5 (policy +
    # debug-guest marker; the marker also relaxes nvidia-gpu-ready's CC gate).
    sudo install -m 0644 "${DEBUG_POLICY}" "${TARGET_ROOTFS}/etc/kata-opa/default-policy.rego"
    sudo install -D -m 0644 "${DEBUG_MARKER}" "${TARGET_ROOTFS}/etc/c8s/debug-guest"
    seal_and_assemble "${BUILD_VARIANT}-nvidia-debug" "${NVIDIA_DEBUG_OUTPUT_DIR}" "${KATA_NVIDIA_VMLINUZ}"
}

if [[ "${BUILD_NVIDIA}" == "0" ]]; then
    log "Step 6/6: NVIDIA GPU variants SKIPPED (BUILD_NVIDIA=0)"
elif [[ -f "${KATA_NVIDIA_CONFIDENTIAL_IMG}" && -f "${KATA_NVIDIA_VMLINUZ}" ]]; then
    build_nvidia_variants
elif [[ "${BUILD_NVIDIA}" == "1" ]]; then
    die "BUILD_NVIDIA=1 but the stock kata NVIDIA artifacts are missing (${KATA_NVIDIA_CONFIDENTIAL_IMG}, ${KATA_NVIDIA_VMLINUZ}) — install kata-deploy's payload on this host or point KATA_NVIDIA_CONFIDENTIAL_IMG / KATA_NVIDIA_VMLINUZ at them"
else
    log "Step 6/6: NVIDIA GPU variants SKIPPED (stock kata NVIDIA artifacts not found; set BUILD_NVIDIA=1 to require them)"
fi

cat <<EOF

===============================
  kata-guest-base build complete
  locked: ${OUTPUT_DIR}
  debug:  ${DEBUG_OUTPUT_DIR}   (host log/exec RPCs allowed — dev only)
  nvidia: ${NVIDIA_OUTPUT_DIR} + ${NVIDIA_DEBUG_OUTPUT_DIR}  (when built — see Step 6/6 log)
  rootfs type: ${FS_TYPE}
  Each dir: vmlinuz, kata-rootfs.img, kernel_verity_params, rootfs_type,
  manifest.json

  The puller (or a manual test) points the kata-qemu-snp config at:
    kernel               = <dir>/vmlinuz
    image                = <dir>/kata-rootfs.img
    rootfs_type          = <dir>/rootfs_type
    kernel_verity_params = <dir>/kernel_verity_params
===============================
EOF
