# nri-image-policy installer — run as a privileged init container.
#
# Installs the host plugin binary, drops the runtime config + bootstrap
# allowlist onto the host, registers NRI with containerd (in-place patch on
# k8s, drop-in file on rke2), restarts containerd so the plugin loads, and
# blocks until the plugin's host-side unix socket reports healthy.
#
# Env (all required; chart pod spec wires them via .Values):
#   HOST_PLUGIN_PATH       — destination path of the plugin binary on host
#   HOST_BOOTSTRAP_PATH    — destination path of bootstrap.yaml on host
#   HOST_CONFIG_PATH       — destination path of the runtime config on host
#   HOST_CONTAINERD_DIR    — host containerd config directory, mounted at
#                            /host<dir>
#   CONTAINERD_CONFIG_MODE — "patch" (in-place sentinel splice) or "dropin"
#                            (standalone schema-versioned file)
#   HOST_HEALTH_SOCKET     — plugin's host-side unix socket, used for the
#                            post-install health probe
#   PLUGIN_DIR             — containerd plugin_path
#   CONFIG_DIR             — containerd plugin_config_path
#   PLUGIN_NAME            — name in default_validator.required_plugins
#   RESTART_COMMAND        — `systemctl restart …` run via nsenter into PID 1
set -eu

echo "==> nri-image-policy installer starting"

install_file() {
  src=$1; dst=$2; mode=$3
  mkdir -p "$(dirname "$dst")"
  if cmp -s "$src" "$dst" 2>/dev/null; then
    return 1
  fi
  install -m "$mode" "$src" "$dst.tmp"
  mv -f "$dst.tmp" "$dst"
  return 0
}

# 1. Plugin binary. Atomic install so containerd never sees a half-written
#    file. Image must ship the binary at this path.
binary_changed=0
if install_file /usr/local/bin/nri-image-policy "/host${HOST_PLUGIN_PATH}" 0755; then
  binary_changed=1
  echo "plugin binary updated at ${HOST_PLUGIN_PATH}"
fi

# 2. Plugin runtime config + bootstrap allowlist.
config_changed=0
if install_file /configs/bootstrap.yaml "/host${HOST_BOOTSTRAP_PATH}" 0644; then
  config_changed=1
  echo "bootstrap allowlist updated at ${HOST_BOOTSTRAP_PATH}"
fi
if install_file /configs/image-policy.yaml "/host${HOST_CONFIG_PATH}" 0644; then
  config_changed=1
  echo "plugin runtime config updated at ${HOST_CONFIG_PATH}"
fi

# 3. Containerd NRI config: patch config.toml in place (k8s) or write a
#    drop-in beside it (rke2 — RKE2 regenerates its config on restart, so an
#    in-place splice would not survive).
CONTAINERD_DIR=/host${HOST_CONTAINERD_DIR}
MARK_BEGIN='# BEGIN c8s-nri-image-policy (managed)'
MARK_END='# END c8s-nri-image-policy (managed)'

# containerd/RKE2 always render the active config to config.toml.
main_config="$CONTAINERD_DIR/config.toml"

render_nri_toml() {
  cat <<EOF
[plugins."io.containerd.nri.v1.nri"]
  disable = false
  plugin_path = "${PLUGIN_DIR}"
  plugin_config_path = "${CONFIG_DIR}"
  plugin_registration_timeout = "10s"
  plugin_request_timeout = "2s"
  socket_path = "/var/run/nri/nri.sock"
[plugins."io.containerd.nri.v1.nri.default_validator"]
  enable = true
  required_plugins = ["${PLUGIN_NAME}"]
EOF
}

read_managed_block() {
  awk -v b="$MARK_BEGIN" -v e="$MARK_END" '
    $0==b { in_block=1 }
    in_block { print }
    $0==e { in_block=0 }
  ' "$1" 2>/dev/null || true
}

containerd_changed=0
if [ "${CONTAINERD_CONFIG_MODE}" = "dropin" ]; then
  # Drop-in dir tracks the containerd config schema version
  # (version >= 3 -> config-v3.toml.d) — the same dir kata-deploy
  # writes into, so one import covers both. The containerd-prep
  # initContainer has already added that import; fail loud if it
  # is missing rather than time out at the health probe.
  ver=$(sed -n '/^[[:space:]]*\[/q; s/#.*//; s/^[[:space:]]*version[[:space:]]*=[[:space:]]*\([0-9][0-9]*\).*/\1/p' "$main_config" | head -n1)
  if [ "${ver:-0}" -ge 3 ] 2>/dev/null; then
    dropin_dir="$CONTAINERD_DIR/config-v3.toml.d"
  elif [ "${ver:-}" = "2" ]; then
    dropin_dir="$CONTAINERD_DIR/config.toml.d"
  else
    echo "ERROR: cannot determine containerd schema version from $main_config" >&2
    exit 1
  fi
  CONFIG="$dropin_dir/nri-image-policy.toml"
  if ! grep -qF "$(basename "$dropin_dir")" "$main_config" 2>/dev/null; then
    echo "ERROR: $main_config does not import the" >&2
    echo "       $(basename "$dropin_dir") drop-in dir; the nri-image-policy" >&2
    echo "       drop-in would be written but never loaded. The" >&2
    echo "       containerd-prep initContainer should have added it." >&2
    exit 1
  fi
  # Standalone file — the whole file is ours. Idempotent via cmp.
  desired=$(render_nri_toml)
  mkdir -p "$dropin_dir"
  if ! printf '%s\n' "$desired" | cmp -s - "$CONFIG" 2>/dev/null; then
    containerd_changed=1
    printf '%s\n' "$desired" > "$CONFIG.tmp"
    mv -f "$CONFIG.tmp" "$CONFIG"
    echo "containerd drop-in written: $CONFIG"
  fi
else
  # Splice a sentinel-delimited block into the shared config.
  CONFIG="$main_config"
  desired=$(printf '%s\n%s\n%s' "$MARK_BEGIN" "$(render_nri_toml)" "$MARK_END")
  if [ "$(read_managed_block "$CONFIG")" != "$desired" ]; then
    containerd_changed=1
    # Strip any prior block, then append the desired one.
    if [ -f "$CONFIG" ]; then
      awk -v b="$MARK_BEGIN" -v e="$MARK_END" '
        $0==b { skip=1; next }
        $0==e { skip=0; next }
        !skip { print }
      ' "$CONFIG" > "$CONFIG.tmp"
    else
      : > "$CONFIG.tmp"
    fi
    printf '\n%s\n' "$desired" >> "$CONFIG.tmp"
    mv -f "$CONFIG.tmp" "$CONFIG"
    echo "containerd config patched: $CONFIG"
  fi
fi

# 4. Reload. NRI does not respawn pre-registered plugins from
#    plugin_path on exit (only at containerd startup), so any
#    binary or config change requires a containerd restart.
#    A runtime config change also requires it: the plugin reads
#    its config file once at startup, so the running process
#    won't pick up updates without a fresh launch.
#    Shims survive the restart, so this pod survives too.
if [ "$containerd_changed" = "1" ] || [ "$binary_changed" = "1" ] || [ "$config_changed" = "1" ]; then
  echo "restarting containerd: ${RESTART_COMMAND}"
  # shellcheck disable=SC2086
  nsenter -t 1 -m -u -i -n -p -- sh -c "${RESTART_COMMAND}"
fi

# 5. Wait for the plugin to come up healthy. Probe the host's
#    unix socket (mounted into the pod) — no hostNetwork needed.
#    Failure here surfaces as pod failure via `kubectl get pods`.
i=0
until curl --unix-socket "/host${HOST_HEALTH_SOCKET}" --silent --fail \
    --max-time 2 http://localhost/healthz >/dev/null 2>&1; do
  i=$((i + 1))
  if [ "$i" -gt 60 ]; then
    echo "ERROR: plugin not healthy after 60s" >&2
    exit 1
  fi
  sleep 1
done
echo "==> nri-image-policy installer finished; plugin healthy"
