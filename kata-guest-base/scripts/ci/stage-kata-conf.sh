#!/usr/bin/env bash
# CI-only: stage the kata guest artifacts build.sh needs from the kata-static
# release — the confidential rootfs image (the source of the confidential
# guest-components — confidential-data-hub, attestation-agent, api-server-rest
# — that osbuilder bakes into the measured rootfs), plus the stock NVIDIA
# confidential rootfs and NVIDIA guest kernel that Step 6 grafts into the GPU
# variants. kata-deploy provides all of these at /opt/kata on a node; in CI we
# pull them from the kata-static release instead so the build doesn't depend
# on runner-host provisioning (and gets a sha-pinned payload rather than
# whatever kata-deploy last installed).
#
# Inputs (env):
#   KATA_VERSION                kata-static release to download.
#   RUNNER_TEMP                 GitHub-runner-provided temp dir.
#   KATA_STATIC_SHA256          (optional) override the pinned sha256 of the
#                               kata-static-${KATA_VERSION}-amd64.tar.zst.
#   GITHUB_ENV                  GitHub-runner env file; we append
#                               KATA_CONFIDENTIAL_IMG, KATA_NVIDIA_CONFIDENTIAL_IMG
#                               and KATA_NVIDIA_VMLINUZ for build.sh.
#
# On a cache hit (every staged artifact already lives under
# ${RUNNER_TEMP}/kata-conf/), the download is skipped entirely.

set -euo pipefail

: "${KATA_VERSION:?KATA_VERSION must be set}"
: "${RUNNER_TEMP:?RUNNER_TEMP must be set}"
: "${GITHUB_ENV:?GITHUB_ENV must be set}"

# Pinned sha256 of the kata-static tarball. The guest-components inside are
# baked into the dm-verity root and the SNP launch measurement, so an
# unverified download would undermine the measurement. Update alongside
# KATA_VERSION (compute via `sha256sum kata-static-<ver>-amd64.tar.zst`).
DEFAULT_KATA_STATIC_SHA256_3_30_0="e65aa5e5bd9f4d59bcd12a8c44a00966406e7329511dd3f756026b6eedc8ad26"
KATA_STATIC_SHA256="${KATA_STATIC_SHA256:-${DEFAULT_KATA_STATIC_SHA256_3_30_0}}"

dir="${RUNNER_TEMP}/kata-conf"
img="${dir}/kata-ubuntu-noble-confidential.image"
# kata-static ships these under versioned names (driver / kernel version in
# the filename); kata-deploy adds the stable-name symlinks build.sh's /opt/kata
# defaults point at. We stage under stable names ourselves.
nvidia_img="${dir}/kata-nvidia-gpu-confidential.image"
nvidia_vmlinuz="${dir}/vmlinuz-nvidia-gpu.container"

if [ ! -f "${img}" ] || [ ! -f "${nvidia_img}" ] || [ ! -f "${nvidia_vmlinuz}" ]; then
    echo "cache miss — fetching kata-static-${KATA_VERSION}"
    mkdir -p "${dir}"
    tarball="${RUNNER_TEMP}/kata-static.tar.zst"
    curl -fsSL -o "${tarball}" \
        "https://github.com/kata-containers/kata-containers/releases/download/${KATA_VERSION}/kata-static-${KATA_VERSION}-amd64.tar.zst"
    echo "${KATA_STATIC_SHA256}  ${tarball}" | sha256sum -c -

    tmp="$(mktemp -d)"
    # Extract as the runner user (no sudo): the artifacts are regular files,
    # and root-owned temp files would break both the cleanup below and the
    # actions/cache save, which reads the cached files as the runner.
    # Wildcards because the NVIDIA artifacts carry the driver / kernel
    # version in their names (e.g. …-nvidia-gpu-confidential-595.58.03.image,
    # vmlinuz-6.18.15-192-nvidia-gpu); the symlinks kata-deploy would provide
    # (kata-containers-nvidia-gpu-confidential.img, vmlinuz-nvidia-gpu.container)
    # don't survive --wildcards member extraction dereferenced, so match the
    # real files.
    tar -I unzstd -xf "${tarball}" \
        -C "${tmp}" --wildcards --no-anchored \
        'kata-ubuntu-noble-confidential.image' \
        'kata-ubuntu-noble-nvidia-gpu-confidential-*.image' \
        'vmlinuz-*-nvidia-gpu'
    stage() { # stage <find-name-glob> <dest> <label>
        local found
        found="$(find "${tmp}" -name "$1" -type f | sort | head -1)"
        if [ -z "${found}" ]; then
            echo "::error::$3 ($1) not found in kata-static-${KATA_VERSION}"
            exit 1
        fi
        mv "${found}" "$2"
    }
    stage 'kata-ubuntu-noble-confidential.image' "${img}" "CoCo confidential image"
    stage 'kata-ubuntu-noble-nvidia-gpu-confidential-*.image' "${nvidia_img}" "NVIDIA confidential image"
    stage 'vmlinuz-*-nvidia-gpu' "${nvidia_vmlinuz}" "NVIDIA guest kernel"
    rm -rf "${tarball}" "${tmp}"
else
    echo "cache hit — reusing artifacts under ${dir}"
fi

{
    echo "KATA_CONFIDENTIAL_IMG=${img}"
    echo "KATA_NVIDIA_CONFIDENTIAL_IMG=${nvidia_img}"
    echo "KATA_NVIDIA_VMLINUZ=${nvidia_vmlinuz}"
} >> "${GITHUB_ENV}"
echo "confidential guest-components source: ${img}"
echo "NVIDIA graft sources: ${nvidia_img}, ${nvidia_vmlinuz}"
