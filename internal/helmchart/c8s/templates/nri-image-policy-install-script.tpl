{{/*
Install shell script for the NRI plugin. Caller dict: .root, .archetype
("cds"/"worker", log only), .bootConfig (rendered image-policy.yaml).
*/}}
{{- define "nri-image-policy.installScript" -}}
{{- $root := .root -}}
set -eu

echo "==> nri-image-policy {{ .archetype }} installer starting"

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

write_file() {
  dst=$1; mode=$2
  mkdir -p "$(dirname "$dst")"
  tmp=$(mktemp "$dst.XXXXXX")
  cat > "$tmp"
  chmod "$mode" "$tmp"
  if cmp -s "$tmp" "$dst" 2>/dev/null; then
    rm -f "$tmp"
    return 1
  fi
  mv -f "$tmp" "$dst"
  return 0
}

mkdir -p "/host{{ $root.Values.nriImagePolicy.hostPaths.cacheDir }}"
mkdir -p "/host{{ $root.Values.nriImagePolicy.hostPaths.runtimeDir }}"

config_changed=0
if write_file "/host{{ include "nri-image-policy.hostConfigPath" $root }}" 0644 <<'IMAGE_POLICY_EOF'
{{ .bootConfig }}
IMAGE_POLICY_EOF
then
  config_changed=1
  echo "boot config updated"
fi

binary_changed=0
if install_file /usr/local/bin/nri-image-policy "/host{{ include "nri-image-policy.hostPluginPath" $root }}" 0755; then
  binary_changed=1
  echo "plugin binary updated"
fi

CONTAINERD_DIR=/host{{ include "nri-image-policy.containerdConfigDir" $root }}
CONTAINERD_CONFIG_MODE={{ include "nri-image-policy.containerdConfigMode" $root | quote }}
RESTART_COMMAND={{ include "nri-image-policy.restartCommand" $root | quote }}
MARK_BEGIN='# BEGIN c8s-nri-image-policy (managed)'
MARK_END='# END c8s-nri-image-policy (managed)'

# containerd/RKE2 always render the active config to config.toml.
main_config="$CONTAINERD_DIR/config.toml"

render_nri_toml() {
  cat <<EOF
[plugins."io.containerd.nri.v1.nri"]
  disable = false
  plugin_path = "{{ $root.Values.nriImagePolicy.hostPaths.pluginDir }}"
  plugin_config_path = "{{ $root.Values.nriImagePolicy.hostPaths.configDir }}"
  plugin_registration_timeout = "10s"
  plugin_request_timeout = "2s"
  socket_path = "/var/run/nri/nri.sock"
[plugins."io.containerd.nri.v1.nri.default_validator"]
  enable = true
  required_plugins = ["{{ $root.Values.nriImagePolicy.pluginName }}"]
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
if [ "$CONTAINERD_CONFIG_MODE" = "dropin" ]; then
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
    echo "ERROR: $main_config does not import $(basename "$dropin_dir"); containerd-prep should have added it" >&2
    exit 1
  fi
  desired=$(render_nri_toml)
  mkdir -p "$dropin_dir"
  if ! printf '%s\n' "$desired" | cmp -s - "$CONFIG" 2>/dev/null; then
    containerd_changed=1
    printf '%s\n' "$desired" > "$CONFIG.tmp"
    mv -f "$CONFIG.tmp" "$CONFIG"
    echo "containerd drop-in written: $CONFIG"
  fi
else
  CONFIG="$main_config"
  desired=$(printf '%s\n%s\n%s' "$MARK_BEGIN" "$(render_nri_toml)" "$MARK_END")
  if [ "$(read_managed_block "$CONFIG")" != "$desired" ]; then
    containerd_changed=1
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

# NRI does not respawn pre-registered plugins on exit. Binary, config, or
# containerd registration changes therefore require a restart. Shims survive.
if [ "$containerd_changed" = "1" ] || [ "$binary_changed" = "1" ] || [ "$config_changed" = "1" ]; then
  echo "restarting containerd: $RESTART_COMMAND"
  # shellcheck disable=SC2086
  nsenter -t 1 -m -u -i -n -p -- sh -c "$RESTART_COMMAND"
fi

i=0
until curl --unix-socket "/host{{ include "nri-image-policy.hostHealthSocket" $root }}" --silent --fail \
    --max-time 2 http://localhost/healthz >/dev/null 2>&1; do
  i=$((i + 1))
  if [ "$i" -gt 60 ]; then
    echo "ERROR: plugin not healthy after 60s" >&2
    exit 1
  fi
  sleep 1
done
echo "==> nri-image-policy {{ .archetype }} installer finished; plugin healthy"
{{- end }}

{{/*
Boot config (image-policy.yaml). Caller passes a dict with .root and .archetype
("cds" or "worker"). CDS-node activates whitelist.push; workers activate
whitelist.pull. whitelist.always_allow is identical on both and pins the
install image so chart upgrades can roll.
*/}}
{{- define "nri-image-policy.bootConfig" -}}
{{- $root := .root -}}
{{- $cds := eq .archetype "cds" -}}
{{- $attestationNodePort := int $root.Values.attestationService.service.nodePort -}}
plugin:
  health_addr: {{ printf "unix://%s" (include "nri-image-policy.hostHealthSocket" $root) | quote }}
whitelist:
{{- if $cds }}
  push:
    persist_path: {{ printf "%s/pushed.json" $root.Values.nriImagePolicy.hostPaths.cacheDir | quote }}
{{- else }}
  pull:
    url: {{ required "cds.url is required" $root.Values.nriImagePolicy.cds.url | quote }}
    interval: {{ $root.Values.nriImagePolicy.refresh.interval | quote }}
    timeout: "30s"
    attestation_service_url: {{ printf "http://localhost:%d" $attestationNodePort | quote }}
    cds_measurements:
{{- range $root.Values.cds.measurements }}
      - {{ . | quote }}
{{- else }}
      []
{{- end }}
{{- end }}
{{- /* Self-allow the installer image first (load-bearing when
       bootstrapWhitelist.deriveComponents=false, where the floor omits it), then
       add the floor — skipping the installer digest so the map has no
       duplicate key (the plugin loads this with yaml.v3, which rejects dups). */ -}}
{{- $selfDigest := required "image.digest is required (chart self-allow for installer rollouts)" $root.Values.nriImagePolicy.image.digest }}
  always_allow:
    {{ $selfDigest | quote }}: {{ printf "%s@%s" $root.Values.nriImagePolicy.image.repository $selfDigest | quote }}
{{- range $digest, $image := (include "c8s.imageWhitelist" $root | fromJson) }}
{{- if ne $digest $selfDigest }}
    {{ $digest | quote }}: {{ $image | quote }}
{{- end }}
{{- end }}
containerd:
  socket: {{ include "nri-image-policy.containerdSocket" $root | quote }}
  namespace: {{ $root.Values.nriImagePolicy.containerd.namespace | quote }}
policy:
  mode: {{ $root.Values.nriImagePolicy.policy.mode | quote }}
  enforce_existing: {{ $root.Values.nriImagePolicy.policy.enforceExisting }}
  deny_missing_annotation: {{ $root.Values.nriImagePolicy.policy.denyMissingAnnotation }}
  exempt_namespaces:
{{- range $root.Values.nriImagePolicy.policy.exemptNamespaces }}
    - {{ . | quote }}
{{- end }}
  label_rules:
{{- if $root.Values.nriImagePolicy.policy.labelRules }}
{{- toYaml $root.Values.nriImagePolicy.policy.labelRules | nindent 4 }}
{{- else }}
    []
{{- end }}
logging:
  level: {{ $root.Values.nriImagePolicy.logLevel | quote }}
{{- end }}
