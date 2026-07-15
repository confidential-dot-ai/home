#!/usr/bin/env bash
# Populate ../extra/usr/local/bin/ with the binaries baked into the
# kata-guest-base image.
#
# Binary paths in the rootfs:
#   /usr/local/bin/ratls-mesh           — Go, built from /workspace/c8s
#   /usr/local/bin/policy-monitor       — Go, built from /workspace/c8s
#   /usr/local/bin/attestation-service  — Rust attestation-api bin from
#                                         /workspace/attestation-rs, staged
#                                         under the attestation-service role name
#
# kata-agent is NOT staged here. The guest rootfs is built by kata's
# osbuilder (scripts/build.sh), which installs the version-matched
# kata-agent (and its systemd unit) for us — so the old kata-static
# initrd extraction is gone. This is the whole reason we moved off the
# confos image build: osbuilder gives us a kata-native rootfs with the
# correct agent, and we only overlay our c8s binaries/services on top.
#
# ratls-mesh + policy-monitor are produced by this c8s repo's
# `make build-c8s-node` / `make build-policy-monitor`; the in-guest
# attester is the `attestation-api` bin from the sibling
# confidential-dot-ai/attestation-rs repo's default (glibc) build (the former
# standalone attestation-service was folded into that repo). The CI
# workflow (.github/workflows/kata-guest-base.yml) runs the canonical
# build steps for each before invoking this script.
#
# This script also materialises /etc/c8s/bootstrap-allowlist.json — the
# in-VM policy-monitor's image-digest allowlist — from the template at
# extra/etc/c8s/bootstrap-allowlist.json.template by substituting the
# SHA-256 digests of three container images: the c8s-repo images cds,
# get-cert and c8s-operator (resolved at IMAGE_TAG, this commit's short
# SHA). The digests are resolved against GHCR via
# `oras manifest fetch`; a missing/unfetchable image is fatal — we never
# proceed with an empty or placeholder-bearing allowlist, because that
# would silently lock kata-qemu-snp pods out of every CDS bootstrap
# image at the next boot.
#
# Locally:
#   cd /workspace/c8s            && make build-c8s-node
#   cd /workspace/c8s            && make build-policy-monitor
#   cd /workspace/attestation-rs && cargo build --release -p attestation-api --bin attestation-api
#     (build needs the TPM2-TSS dev headers: apt-get install -y libtss2-dev)
#   IMAGE_TAG=<c8s-release-tag> /workspace/c8s/kata-guest-base/scripts/fetch.sh
#
# Re-runs are idempotent: existing binaries with the same mtime are
# skipped.

set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
IMAGE_DIR="$(cd "${HERE}/.." && pwd)"
WORKSPACE="$(cd "${IMAGE_DIR}/../.." && pwd)"
EXTRA_DIR="${IMAGE_DIR}/extra"
BIN_DIR="${EXTRA_DIR}/usr/local/bin"

mkdir -p "${BIN_DIR}"

# Source locations. Overridable so a CI matrix job can point at an
# already-fetched artifact (e.g. a Docker buildx-exported binary) without
# re-cloning the c8s repo.
C8S_DIR="${C8S_DIR:-${WORKSPACE}/c8s}"
ATTESTATION_DIR="${ATTESTATION_DIR:-${WORKSPACE}/attestation-rs}"

# ratls-mesh: the canonical build produces /workspace/c8s/build/c8s (the
# multi-mode binary) or /workspace/c8s/build/c8s-node (slim variant). In
# the guest we want the slim binary — no helm/operator code shipped into
# a TEE. The binary's "ratls-mesh" subcommand is what the systemd unit
# invokes via `ratls-mesh in-guest`.
#
# Strategy: copy the slim binary as `ratls-mesh` so the systemd unit's
# ExecStart=/usr/local/bin/ratls-mesh works without aliasing. S4 will
# expose `in-guest` and `readiness-check` subcommands from the same
# multi-mode binary; the file on disk is named ratls-mesh either way
# because the unit pins that path.
C8S_NODE_BIN="${C8S_NODE_BIN:-${C8S_DIR}/build/c8s-node}"
if [[ ! -x "${C8S_NODE_BIN}" ]]; then
    echo "FATAL: ${C8S_NODE_BIN} missing" >&2
    echo "       Build first:" >&2
    echo "         cd ${C8S_DIR} && make build-c8s-node" >&2
    exit 1
fi
install -m 0755 "${C8S_NODE_BIN}" "${BIN_DIR}/ratls-mesh"
echo "==> ratls-mesh: ${BIN_DIR}/ratls-mesh ($(stat -c '%s' "${BIN_DIR}/ratls-mesh") bytes)"

# policy-monitor: in-VM container-digest enforcement daemon. Watches
# /run/kata-containers via inotify, SIGKILLs containers whose digest
# isn't on the baked allowlist. Source lives at
# /workspace/c8s/cmd/policy-monitor. Built by
# `make build-policy-monitor` -> ${C8S_DIR}/build/policy-monitor.
POLICY_MONITOR_BIN="${POLICY_MONITOR_BIN:-${C8S_DIR}/build/policy-monitor}"
if [[ ! -x "${POLICY_MONITOR_BIN}" ]]; then
    echo "FATAL: ${POLICY_MONITOR_BIN} missing" >&2
    echo "       Build first:" >&2
    echo "         cd ${C8S_DIR} && make build-policy-monitor" >&2
    exit 1
fi
install -m 0755 "${POLICY_MONITOR_BIN}" "${BIN_DIR}/policy-monitor"
echo "==> policy-monitor: ${BIN_DIR}/policy-monitor ($(stat -c '%s' "${BIN_DIR}/policy-monitor") bytes)"

# rtmr3-measurer: in-VM per-workload RTMR[3] measurer. Scans
# /run/kata-containers and extends TDX RTMR[3] with each workload's image
# digest. Source at /workspace/c8s/cmd/rtmr3-measurer. Built by
# `make build-rtmr3-measurer` -> ${C8S_DIR}/build/rtmr3-measurer.
RTMR3_MEASURER_BIN="${RTMR3_MEASURER_BIN:-${C8S_DIR}/build/rtmr3-measurer}"
if [[ ! -x "${RTMR3_MEASURER_BIN}" ]]; then
    echo "FATAL: ${RTMR3_MEASURER_BIN} missing" >&2
    echo "       Build first:" >&2
    echo "         cd ${C8S_DIR} && make build-rtmr3-measurer" >&2
    exit 1
fi
install -m 0755 "${RTMR3_MEASURER_BIN}" "${BIN_DIR}/rtmr3-measurer"
echo "==> rtmr3-measurer: ${BIN_DIR}/rtmr3-measurer ($(stat -c '%s' "${BIN_DIR}/rtmr3-measurer") bytes)"

# In-guest attester: the `attestation-api` bin from attestation-rs, built for
# the default (glibc) target. Staged under the attestation-service role name
# (the in-guest unit, the C8S_ATTESTATION_SERVICE_URL contract, and the
# 127.0.0.1:8400 role are unchanged — only the source repo/bin moved). The
# guest rootfs is ubuntu-noble (glibc), so a glibc binary drops in fine; we no
# longer build static-musl (musl can't resolve tss2-sys via pkg-config).
ATTESTATION_BIN="${ATTESTATION_BIN:-${ATTESTATION_DIR}/target/release/attestation-api}"
if [[ ! -x "${ATTESTATION_BIN}" ]]; then
    echo "FATAL: ${ATTESTATION_BIN} missing" >&2
    echo "       Build first:" >&2
    echo "         cd ${ATTESTATION_DIR} && cargo build --release -p attestation-api --bin attestation-api" >&2
    exit 1
fi
install -m 0755 "${ATTESTATION_BIN}" "${BIN_DIR}/attestation-service"
echo "==> attestation-service: ${BIN_DIR}/attestation-service ($(stat -c '%s' "${BIN_DIR}/attestation-service") bytes)"

# The systemd unit (extra/etc/systemd/system/attestation-service.service)
# and the localhost-only config (extra/etc/c8s/attestation-service.toml)
# are owned by this recipe — they are c8s in-guest deployment artifacts,
# not something attestation-rs ships. (They used to be copied from the
# standalone attestation-service repo; that repo is gone, so the in-tree
# copies under extra/ are now the source of truth and are baked as-is.)

# KATA_VERSION is kept only to stamp the bake marker below. The
# authoritative kata pin for the build lives in scripts/build.sh (the
# osbuilder source tag) and must stay in lockstep with
# internal/helmchart/c8s/values.yaml (the kata-deploy version) — a
# host/guest version skew turns every kata RPC into a compatibility
# gamble.
KATA_VERSION="${KATA_VERSION:-3.30.0}"

# Drop a marker so we know which inputs produced this baked overlay.
mkdir -p "${EXTRA_DIR}/usr/local/share/c8s"
{
    printf 'kata-guest-base overlay staged at: %s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
    printf 'c8s_node_bin: %s\n' "${C8S_NODE_BIN}"
    printf 'policy_monitor_bin: %s\n' "${POLICY_MONITOR_BIN}"
    printf 'attestation_api_bin: %s\n' "${ATTESTATION_BIN}"
    printf 'kata_version: %s\n' "${KATA_VERSION}"
} > "${EXTRA_DIR}/usr/local/share/c8s/.kata-guest-base-baked"

# --- Bootstrap image-digest allowlist ----------------------------------
#
# The in-VM policy-monitor.service reads /etc/c8s/bootstrap-allowlist.json
# at boot. The file is the operator-pinned list of c8s container image
# digests that are allowed to start inside a kata-qemu-snp pod (without
# a digest match, policy-monitor SIGKILLs the container's init PID).
#
# We materialise the file here, BEFORE the rootfs is built, so its bytes
# are part of the dm-verity root and therefore covered by the SNP launch
# measurement (the verity root hash is pinned in the kata kernel cmdline,
# which kernel-hashes folds into the launch digest). Two consequences:
#
#   1. Updating the allowlist requires rebuilding the image and rolling
#      kata-qemu-snp pods to the new tag. Operators accept this by
#      pinning kata.guestImage.tag — pinning the tag is also pinning
#      the allowed image set.
#
#   2. The digests we resolve here MUST match the c8s container images
#      the chart deploys. The IMAGE_TAG variable below is the
#      c8s release tag whose ghcr.io/confidential-dot-ai/{cds,get-cert}:<tag>
#      images are pinned. CI passes this as an env
#      var (.github/workflows/kata-guest-base.yml); locally the
#      developer must set it explicitly — defaulting to "latest"
#      would silently produce a different measurement on every
#      run, which is the opposite of what we want.

IMAGE_TAG="${IMAGE_TAG:-}"
IMAGE_REGISTRY="${IMAGE_REGISTRY:-ghcr.io/confidential-dot-ai}"
ALLOWLIST_TEMPLATE="${EXTRA_DIR}/etc/c8s/bootstrap-allowlist.json.template"
ALLOWLIST_DST="${EXTRA_DIR}/etc/c8s/bootstrap-allowlist.json"

if [[ ! -f "${ALLOWLIST_TEMPLATE}" ]]; then
    echo "FATAL: ${ALLOWLIST_TEMPLATE} missing — template was renamed or removed?" >&2
    exit 1
fi

# IMAGE_TAG is only needed if we have to actually resolve digests via
# `oras manifest fetch`. Local builds and dev iterations often want to
# supply digests directly (or use placeholder digests for a smoke
# test); allow that path by gating the IMAGE_TAG requirement on
# "are any digests still missing after the env-var overrides?".
#
# Pre-supplied env vars for the IMAGE_TAG-resolved c8s-repo images (set any
# subset):
#   CDS_DIGEST=sha256:...
#   GET_CERT_DIGEST=sha256:...
#   C8S_OPERATOR_DIGEST=sha256:...
#
# If all three are set, no IMAGE_TAG-based oras lookup happens and IMAGE_TAG is
# unused. If any is missing, IMAGE_TAG is required so the remaining ones can be
# resolved against the registry.
if [[ -z "${CDS_DIGEST:-}" || -z "${GET_CERT_DIGEST:-}" || -z "${C8S_OPERATOR_DIGEST:-}" ]]; then
    if [[ -z "${IMAGE_TAG}" ]]; then
        echo "FATAL: IMAGE_TAG is required to resolve the bootstrap allowlist." >&2
        echo "       Either:" >&2
        echo "         1. Set IMAGE_TAG=<c8s-release-tag> (e.g. v0.1.0 or a short" >&2
        echo "            SHA) so the missing digests can be resolved via 'oras" >&2
        echo "            manifest fetch \${IMAGE_REGISTRY}/<image>:\${IMAGE_TAG}'," >&2
        echo "            and pin the exact digests the chart will deploy." >&2
        echo "         2. Or set CDS_DIGEST, GET_CERT_DIGEST and C8S_OPERATOR_DIGEST" >&2
        echo "            directly (useful for local builds against images that" >&2
        echo "            don't live in a registry yet)." >&2
        exit 1
    fi
fi

# resolve_digest <image> -> echoes "sha256:<hex>". Fatal on failure;
# never silently substitutes an empty digest.
#
# We use `oras manifest fetch --descriptor` because:
#   - It returns the *manifest* digest, which is what containerd's CRI
#     plugin stamps into io.kubernetes.cri.image-name when it pulls
#     by reference (and what policy-monitor compares against).
#   - oras is already a dependency of this workflow (see the
#     setup-oras step in kata-guest-base.yml) so no extra tooling.
#   - On a multi-arch image, oras returns the index digest, which is
#     still what the CRI annotation carries — kata-runtime pulls the
#     index, not a per-arch manifest, so this lines up.
#
# The `--platform` flag is intentionally omitted so we get the index
# digest rather than a per-arch sub-manifest digest. If a c8s image
# ever ships as a single-arch manifest (no index), oras transparently
# returns the manifest digest in that case too, so the same code path
# works.
resolve_digest() {
    local image="$1"
    local descriptor
    if ! descriptor="$(oras manifest fetch --descriptor "${image}" 2>&1)"; then
        echo "FATAL: oras manifest fetch ${image} failed:" >&2
        echo "${descriptor}" >&2
        exit 1
    fi
    local digest
    digest="$(echo "${descriptor}" | grep -oE 'sha256:[a-f0-9]{64}' | head -1)"
    if [[ -z "${digest}" ]]; then
        echo "FATAL: could not extract sha256 digest from oras output for ${image}:" >&2
        echo "${descriptor}" >&2
        exit 1
    fi
    echo "${digest}"
}

if [[ -n "${IMAGE_TAG}" ]]; then
    echo "==> Resolving bootstrap allowlist digests at IMAGE_TAG=${IMAGE_TAG}"
else
    echo "==> Bootstrap allowlist digests pre-supplied via env (no IMAGE_TAG resolution needed)"
fi
CDS_DIGEST="${CDS_DIGEST:-$(resolve_digest "${IMAGE_REGISTRY}/cds:${IMAGE_TAG}")}"
echo "    cds:          ${CDS_DIGEST}"
GET_CERT_DIGEST="${GET_CERT_DIGEST:-$(resolve_digest "${IMAGE_REGISTRY}/get-cert:${IMAGE_TAG}")}"
echo "    get-cert:     ${GET_CERT_DIGEST}"
C8S_OPERATOR_DIGEST="${C8S_OPERATOR_DIGEST:-$(resolve_digest "${IMAGE_REGISTRY}/c8s-operator:${IMAGE_TAG}")}"
echo "    c8s-operator: ${C8S_OPERATOR_DIGEST}"

# Substitute placeholders into the template. We use sed with explicit
# delimiters and `--` so a digest-like value can never be misparsed as
# a regex metacharacter. Atomic via temp-file + mv so the build step
# never sees a half-written allowlist.
TMP_ALLOWLIST="$(mktemp "${ALLOWLIST_DST}.XXXXXX")"
trap 'rm -f "${TMP_ALLOWLIST}"' EXIT

sed \
    -e "s|@@CDS_DIGEST@@|${CDS_DIGEST}|g" \
    -e "s|@@GET_CERT_DIGEST@@|${GET_CERT_DIGEST}|g" \
    -e "s|@@C8S_OPERATOR_DIGEST@@|${C8S_OPERATOR_DIGEST}|g" \
    "${ALLOWLIST_TEMPLATE}" > "${TMP_ALLOWLIST}"

# Belt-and-braces: refuse to ship a file that still has a placeholder.
# This catches a bug where the template grows a new @@FOO@@ field and
# someone forgets to wire it through this script.
if grep -q '@@' "${TMP_ALLOWLIST}"; then
    echo "FATAL: ${TMP_ALLOWLIST} still contains @@<placeholder>@@ tokens after substitution:" >&2
    grep -n '@@' "${TMP_ALLOWLIST}" >&2
    exit 1
fi

install -m 0644 "${TMP_ALLOWLIST}" "${ALLOWLIST_DST}"
rm -f "${TMP_ALLOWLIST}"
trap - EXIT
echo "==> bootstrap allowlist: ${ALLOWLIST_DST}"

# Record the resolved digests in the bake marker for reproducibility.
{
    printf 'allowlist_image_tag: %s\n' "${IMAGE_TAG}"
    printf 'allowlist_cds_digest: %s\n' "${CDS_DIGEST}"
    printf 'allowlist_get_cert_digest: %s\n' "${GET_CERT_DIGEST}"
    printf 'allowlist_c8s_operator_digest: %s\n' "${C8S_OPERATOR_DIGEST}"
} >> "${EXTRA_DIR}/usr/local/share/c8s/.kata-guest-base-baked"

# --- In-guest registry auth for guest-pull ------------------------------
#
# Baked at /etc/c8s/ghcr-auth.json; tmpfiles copies it to the
# /run/image-security/auth.json path the in-guest CDH reads. Empty by
# default — the c8s images are public, so anonymous guest-pull works. A
# pre-staged file (e.g. private-mirror creds) is baked as-is; it becomes
# part of the measured rootfs — see docs/pitfalls.md "ghcr-auth.json".
GHCR_AUTH_DST="${EXTRA_DIR}/etc/c8s/ghcr-auth.json"
mkdir -p "$(dirname "${GHCR_AUTH_DST}")"
if [[ -s "${GHCR_AUTH_DST}" ]]; then
    echo "==> ghcr-auth.json: keeping pre-staged ${GHCR_AUTH_DST} (baked into the measured rootfs)"
else
    ( umask 077; printf '{"auths":{}}\n' > "${GHCR_AUTH_DST}" )
    echo "==> ghcr-auth.json: baked empty auths (anonymous guest-pull)"
fi

echo "==> Done. Run scripts/build.sh next."
