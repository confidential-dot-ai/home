#!/usr/bin/env bash
# CI-only: compute the GHCR image ref + tag list for the kata-guest-base oras
# push in .github/workflows/kata-guest-base.yml. Writes `image`, `tags`, and
# `debug_tags` (comma-joined) to GITHUB_OUTPUT. `debug_tags` is every tag
# with a `-debug` suffix — the debug-policy variant (build.sh Step 5/5,
# output-debug/) publishes under it in lockstep with the locked image, so
# `kata.guestImage.debug=true` (`c8s install --cvm-mode=pod --debug`) can derive the
# debug ref from any locked tag.
#
# Always publish the immutable, commit-pinned short-SHA tag. Then add exactly one
# human-friendly pointer, scoped to the ref class:
#   - release tag push (vX) -> the release tag       (official)
#   - main                  -> main                  (official)
#   - any side branch       -> branch-<sanitized branch name>
#
# :main matches every other c8s artifact (docker.yml: cds, operator,
# ratls-mesh, …) and cmd/c8s/install.go's fallbackImageTag, so the chart's
# kata.guestImage.tag default resolves here.
#
# A side branch NEVER gets main/vX — nothing a human could mistake for a
# released, production image. The branch- prefix plus ref sanitization (any char
# outside [A-Za-z0-9_.-] -> '-') keeps it an obvious dev artifact and a valid OCI
# tag (leading 'b', <=128 chars).
#
# Inputs (env):
#   HEAD_BRANCH     source branch of the triggering Docker event: "main" for a
#                   main push, the tag name (e.g. "v0.1.0") for a tag push;
#                   github.ref_name on workflow_dispatch.
#   HEAD_SHA        commit Docker succeeded on (workflow_run head_sha), or
#                   github.sha on workflow_dispatch.
#   REGISTRY        container registry host (ghcr.io).
#   GITHUB_OUTPUT   step output file.

set -euo pipefail

: "${HEAD_BRANCH:?HEAD_BRANCH must be set}"
: "${HEAD_SHA:?HEAD_SHA must be set}"
: "${REGISTRY:?REGISTRY must be set}"
: "${GITHUB_OUTPUT:?GITHUB_OUTPUT must be set}"

SHORT_SHA="${HEAD_SHA::7}"
IMAGE="${REGISTRY}/confidential-dot-ai/kata-guest-base"

tags=("${SHORT_SHA}")
if [[ "${HEAD_BRANCH}" == v* ]]; then
  tags+=("${HEAD_BRANCH}")
elif [[ "${HEAD_BRANCH}" == "main" ]]; then
  tags+=("main")
else
  SAFE_BRANCH="$(printf '%s' "${HEAD_BRANCH}" | tr -c 'A-Za-z0-9_.-' '-')"
  tags+=("branch-${SAFE_BRANCH}")
fi

joined=$(IFS=,; echo "${tags[*]}")
debug_joined=$(IFS=,; echo "${tags[*]/%/-debug}")
echo "image=${IMAGE}" >> "$GITHUB_OUTPUT"
echo "tags=${joined}" >> "$GITHUB_OUTPUT"
echo "debug_tags=${debug_joined}" >> "$GITHUB_OUTPUT"
