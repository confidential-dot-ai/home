# containerd-prep — run as a privileged initContainer on RKE2 nodes.
#
# The installer writes its NRI config as a containerd drop-in file, which
# loads only if the rendered config `imports` the drop-in directory. RKE2
# regenerates that config from a template on every supervisor restart and
# does not add the import. This prep adds it, to both the live config and the
# template, keyed off the containerd config schema version (version >= 3 ->
# config-v3.toml.*) — the same directory kata-deploy uses, so one import
# covers both installers.
#
# Env:
#   HOST_CONTAINERD_DIR — host containerd config directory, bind-mounted at
#                         /host<dir>
#   BASE_DIRECTIVE      — literal RKE2 `{{ template "base" . }}` include,
#                         used only when the template has to be created from
#                         scratch
set -eu

DIR="/host${HOST_CONTAINERD_DIR}"
[ -d "$DIR" ] || { echo "ERROR: $DIR is not mounted" >&2; exit 1; }
echo "==> nri-image-policy containerd-prep starting (${HOST_CONTAINERD_DIR})"

# kata-deploy and this installer each run this prep; their DaemonSet pods can
# land on a node together. Serialise on a host lock file so two preps never
# rewrite config.toml / the template at the same time.
exec 9>"$DIR/.c8s-containerd-prep.lock"
flock 9

# RKE2 always renders the active config to config.toml, whichever template it
# used. The drop-in dir and template name track the config schema version.
main_config="$DIR/config.toml"
[ -f "$main_config" ] || { echo "ERROR: $main_config not found — is this an RKE2 node?" >&2; exit 1; }
ver=$(sed -n '/^[[:space:]]*\[/q; s/#.*//; s/^[[:space:]]*version[[:space:]]*=[[:space:]]*\([0-9][0-9]*\).*/\1/p' "$main_config" | head -n1)
if [ "${ver:-0}" -ge 3 ] 2>/dev/null; then
  dropin_name="config-v3.toml.d"; tmpl_name="config-v3.toml.tmpl"
elif [ "${ver:-}" = "2" ]; then
  dropin_name="config.toml.d"; tmpl_name="config.toml.tmpl"
else
  echo "ERROR: cannot determine containerd schema version from $main_config" >&2
  exit 1
fi
tmpl="$DIR/${tmpl_name}"
glob="${HOST_CONTAINERD_DIR}/${dropin_name}/*.toml"
echo "containerd config schema version: ${ver}  drop-in dir: ${dropin_name}"

# The K3s/RKE2 base containerd template emits an `imports = [...<dropin>...]`
# line of its own since k3s-io/k3s b51167a9 (Feb 2026). On those versions
# our prep does not need to prepend anything; on earlier versions it does.
# We dispatch on how many root-level `imports = ` lines are already in the
# rendered config:
#   0 — need to add (older base / custom template without the import).
#   1 — already covered (by base, or by our template on a previous run).
#       Leave both alone — removing our template would lose the import on
#       older RKE2; re-adding the import would duplicate it on modern RKE2.
#   2+ — duplicate, the failure mode of an earlier version of this prep
#       on modern RKE2. Remove our (sentinel-marked or exact-legacy) template
#       so the next RKE2 regen produces a single-imports config again.
SENTINEL='c8s-containerd-prep:managed-template'
legacy_template_content=$(printf 'imports = ["%s"]\n\n%s\n' "$glob" "$BASE_DIRECTIVE")
# grep -c always prints the count (0 when there are no matches), but exits
# non-zero in the 0-matches case — use `|| true`, not `|| echo 0`, or the
# variable ends up as "0\n0" and the case statement falls through to `*`.
imports_count=$(grep -c '^[[:space:]]*imports[[:space:]]*=' "$main_config" 2>/dev/null || true)
imports_count=${imports_count:-0}

remove_managed_tmpl() {
  reason=$1
  [ -f "$tmpl" ] || return 0
  if grep -qF "$SENTINEL" "$tmpl"; then
    rm -f "$tmpl"
    echo "  ${tmpl_name}: removed (sentinel-marked managed template — ${reason})"
  elif [ "$(cat "$tmpl")" = "$legacy_template_content" ]; then
    rm -f "$tmpl"
    echo "  ${tmpl_name}: removed (legacy managed template — ${reason})"
  else
    echo "WARNING: ${tmpl_name} is unrecognised; not touched (${reason})" >&2
  fi
}

case "$imports_count" in
  0)
    { printf 'imports = ["%s"]\n\n' "$glob"; cat "$main_config"; } > "${main_config}.c8s-tmp"
    mv -f "${main_config}.c8s-tmp" "$main_config"
    echo "  $(basename "$main_config"): drop-in import added"
    if [ -f "$tmpl" ]; then
      if grep -qF "$dropin_name" "$tmpl" 2>/dev/null; then
        echo "  ${tmpl_name}: drop-in import already present"
      elif grep -q '^[[:space:]]*imports[[:space:]]*=' "$tmpl" 2>/dev/null; then
        echo "ERROR: $tmpl has an 'imports' line that does not cover" >&2
        echo "       '${dropin_name}'. Add \"${glob}\" and re-run." >&2
        exit 1
      else
        { printf 'imports = ["%s"]\n\n' "$glob"; cat "$tmpl"; } > "${tmpl}.c8s-tmp"
        mv -f "${tmpl}.c8s-tmp" "$tmpl"
        echo "  ${tmpl_name}: drop-in import added"
      fi
    else
      printf '{{/* %s */}}\nimports = ["%s"]\n\n%s\n' "$SENTINEL" "$glob" "$BASE_DIRECTIVE" > "$tmpl"
      echo "  ${tmpl_name}: created with drop-in import"
    fi
    ;;
  1)
    if grep -qF "$dropin_name" "$main_config" 2>/dev/null; then
      echo "  $(basename "$main_config"): drop-in import already present — no changes"
    else
      echo "ERROR: $main_config has an 'imports' line that does not cover" >&2
      echo "       '${dropin_name}'. Inspect the RKE2 containerd template." >&2
      exit 1
    fi
    ;;
  *)
    echo "  $(basename "$main_config"): ${imports_count} 'imports' lines (duplicate — containerd will reject)"
    remove_managed_tmpl "base now provides imports; this template was duplicating"
    ;;
esac

mkdir -p "$DIR/${dropin_name}"

echo "==> nri-image-policy containerd-prep done"
