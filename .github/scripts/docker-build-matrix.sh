#!/usr/bin/env bash
# Build the per-image Docker build matrix consumed by the `images` job in
# .github/workflows/docker.yml.
#
# A component image is included when ANY of:
#   - this is a tag push (refs/tags/*)   -> release tags fan out to every image
#   - this is a manual workflow_dispatch -> rebuild every image (no diff base)
#   - shared code changed (SHARED=true)  -> pkg/**, root internal/**, go.mod, …
#   - the component's own paths changed   (its <X>=true flag)
#
# The workflow_dispatch fan-out is what makes the manual rebuild work: a
# dispatch has no before/after diff, so docker.yml skips paths-filter and every
# per-component flag arrives empty here. Treat it like a tag push and build all
# of them, so the downstream Kata guest base can resolve every component's
# :<short-sha>.
#
# Components NOT included are emitted as a parallel `retag_matrix` so the
# `retag-unchanged` job in docker.yml can copy each one's current `:main`
# manifest under `:<short-sha>`. Downstream (kata-guest-base/scripts/fetch.sh)
# resolves every component by `:<short-sha>` to pin the bootstrap allowlist,
# and that lookup must succeed for every component on every push — even when
# this run's filter rebuilt only a subset.
#
# Inputs (env), each "true"/"false" from the dorny/paths-filter step:
#   SHARED             shared-core || shared-cmdsutil || shared-root
#   C8S, CDS, GET_CERT, RATLS_MESH, NRI_IMAGE_POLICY
#   GITHUB_REF         the triggering ref (for the tag-push fan-out)
#   GITHUB_EVENT_NAME  the triggering event; "workflow_dispatch" fans out to all
#                      (paths-filter is skipped on dispatch, so the flags above
#                      are empty and this is the only signal to build them)
#   GITHUB_OUTPUT      step output file; we append `matrix`, `has_images`,
#                      `retag_matrix`, and `has_retag`.
#
# Output (GITHUB_OUTPUT):
#   has_images=true|false
#   matrix={"include":[{binary,image,dockerfile}, …]}
#   has_retag=true|false
#   retag_matrix={"include":[{binary,image}, …]}

set -euo pipefail

include=()
exclude=()
maybe_add() {
  local changed="$1" binary="$2" image="$3" dockerfile="$4"
  if [[ "$GITHUB_REF" == refs/tags/* || "${GITHUB_EVENT_NAME:-}" == "workflow_dispatch" || "$SHARED" == "true" || "$changed" == "true" ]]; then
    include+=("{\"binary\":\"$binary\",\"image\":\"$image\",\"dockerfile\":\"$dockerfile\"}")
  else
    exclude+=("{\"binary\":\"$binary\",\"image\":\"$image\"}")
  fi
}

maybe_add "$C8S" c8s ghcr.io/confidential-dot-ai/c8s-operator cmd/c8s/Dockerfile
maybe_add "$CDS" cds ghcr.io/confidential-dot-ai/cds cmd/cds/Dockerfile
maybe_add "$GET_CERT" get-cert ghcr.io/confidential-dot-ai/get-cert cmd/get-cert/Dockerfile
maybe_add "$RATLS_MESH" ratls-mesh ghcr.io/confidential-dot-ai/ratls-mesh cmd/ratls-mesh/Dockerfile
maybe_add "$NRI_IMAGE_POLICY" nri-image-policy ghcr.io/confidential-dot-ai/nri-image-policy cmd/nri-image-policy/Dockerfile

if [[ ${#include[@]} -eq 0 ]]; then
  echo 'has_images=false' >> "$GITHUB_OUTPUT"
  echo 'matrix={"include":[]}' >> "$GITHUB_OUTPUT"
else
  matrix=$(IFS=,; printf '{"include":[%s]}' "${include[*]}")
  echo 'has_images=true' >> "$GITHUB_OUTPUT"
  echo "matrix=$matrix" >> "$GITHUB_OUTPUT"
fi

if [[ ${#exclude[@]} -eq 0 ]]; then
  echo 'has_retag=false' >> "$GITHUB_OUTPUT"
  echo 'retag_matrix={"include":[]}' >> "$GITHUB_OUTPUT"
else
  retag_matrix=$(IFS=,; printf '{"include":[%s]}' "${exclude[*]}")
  echo 'has_retag=true' >> "$GITHUB_OUTPUT"
  echo "retag_matrix=$retag_matrix" >> "$GITHUB_OUTPUT"
fi
