{{/*
Expand the name of the chart.
*/}}
{{- define "nri-image-policy.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Create a default fully qualified app name.
*/}}
{{- define "nri-image-policy.fullname" -}}
{{- if .Values.fullnameOverride }}
{{- .Values.fullnameOverride | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- $name := default .Chart.Name .Values.nameOverride }}
{{- if contains $name .Release.Name }}
{{- .Release.Name | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- printf "%s-%s" .Release.Name $name | trunc 63 | trimSuffix "-" }}
{{- end }}
{{- end }}
{{- end }}

{{/*
Common labels
*/}}
{{- define "nri-image-policy.labels" -}}
helm.sh/chart: {{ printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" }}
{{ include "nri-image-policy.selectorLabels" . }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
app.kubernetes.io/part-of: c8s
{{- end }}

{{/*
Selector labels
*/}}
{{- define "nri-image-policy.selectorLabels" -}}
app: {{ include "nri-image-policy.fullname" . }}
app.kubernetes.io/name: {{ include "nri-image-policy.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}

{{/*
Install image reference.
*/}}
{{- define "nri-image-policy.image" -}}
{{ include "c8s-common.image" .Values.image }}
{{- end }}

{{/*
Single nodeSelector entry from cds.node.selector. The chart requires exactly
one label key/value pair so both CDS-installer affinity (matching) and
worker-installer anti-affinity (NotIn) can be derived mechanically.
*/}}
{{- define "nri-image-policy.cdsNodeKey" -}}
{{- $sel := .Values.cds.node.selector -}}
{{- if ne (len $sel) 1 -}}
{{- fail "cds.node.selector must be exactly one key/value pair (e.g. {role: cds-node})" -}}
{{- end -}}
{{- range $k, $_ := $sel }}{{ $k }}{{ end -}}
{{- end }}

{{- define "nri-image-policy.cdsNodeValue" -}}
{{- $sel := .Values.cds.node.selector -}}
{{- range $_, $v := $sel }}{{ $v }}{{ end -}}
{{- end }}

{{/*
Host paths derived from values.
*/}}
{{- define "nri-image-policy.hostPluginPath" -}}
{{ printf "%s/%s" .Values.hostPaths.pluginDir .Values.pluginFilename }}
{{- end }}

{{- define "nri-image-policy.hostConfigPath" -}}
{{ printf "%s/image-policy.yaml" .Values.hostPaths.configDir }}
{{- end }}

{{- define "nri-image-policy.hostHealthSocket" -}}
{{ printf "%s/%s" .Values.hostPaths.runtimeDir .Values.healthSocketName }}
{{- end }}

{{/*
Shared hostPath mounts and volumes used by installer DaemonSets and the
uninstall hook.
*/}}
{{- define "nri-image-policy.hostVolumeMounts" -}}
- name: host-plugin-dir
  mountPath: /host{{ .Values.hostPaths.pluginDir }}
- name: host-config-dir
  mountPath: /host{{ .Values.hostPaths.configDir }}
- name: host-containerd-config
  mountPath: /host{{ include "nri-image-policy.containerdConfigDir" . }}
- name: host-cache-dir
  mountPath: /host{{ .Values.hostPaths.cacheDir }}
- name: host-runtime-dir
  mountPath: /host{{ .Values.hostPaths.runtimeDir }}
{{- end }}

{{- define "nri-image-policy.hostVolumes" -}}
- name: host-plugin-dir
  hostPath:
    path: {{ .Values.hostPaths.pluginDir }}
    type: DirectoryOrCreate
- name: host-config-dir
  hostPath:
    path: {{ .Values.hostPaths.configDir }}
    type: DirectoryOrCreate
- name: host-containerd-config
  hostPath:
    path: {{ include "nri-image-policy.containerdConfigDir" . }}
    type: Directory
- name: host-cache-dir
  hostPath:
    path: {{ .Values.hostPaths.cacheDir }}
    type: DirectoryOrCreate
- name: host-runtime-dir
  hostPath:
    path: {{ .Values.hostPaths.runtimeDir }}
    type: DirectoryOrCreate
{{- end }}

{{/*
Host containerd config directory bind-mounted into the installer.
*/}}
{{- define "nri-image-policy.containerdConfigDir" -}}
{{- if .Values.containerd.configDir -}}
{{ .Values.containerd.configDir }}
{{- else if eq .Values.distro "rke2" -}}
/var/lib/rancher/rke2/agent/etc/containerd
{{- else if eq .Values.distro "k8s" -}}
/etc/containerd
{{- else -}}
{{ fail (printf "nri-image-policy: distro must be \"k8s\" or \"rke2\" (got %q), or set containerd.configDir explicitly" .Values.distro) }}
{{- end -}}
{{- end -}}

{{/*
patch  = splice an in-place sentinel-delimited block into config.toml.
dropin = write a standalone file the installer owns entirely.
*/}}
{{- define "nri-image-policy.containerdConfigMode" -}}
{{- if eq .Values.distro "rke2" -}}
dropin
{{- else if eq .Values.distro "k8s" -}}
patch
{{- else -}}
{{ fail (printf "nri-image-policy: distro must be \"k8s\" or \"rke2\" (got %q)" .Values.distro) }}
{{- end -}}
{{- end -}}

{{/*
Host service restart that makes containerd re-read its config.
*/}}
{{- define "nri-image-policy.restartCommand" -}}
{{- if .Values.containerd.restartCommand -}}
{{ .Values.containerd.restartCommand }}
{{- else if eq .Values.distro "rke2" -}}
systemctl restart rke2-agent
{{- else -}}
systemctl restart containerd
{{- end -}}
{{- end -}}

{{/*
Host containerd socket the plugin connects to.
*/}}
{{- define "nri-image-policy.containerdSocket" -}}
{{- if .Values.containerd.socket -}}
{{ .Values.containerd.socket }}
{{- else if eq .Values.distro "rke2" -}}
/run/k3s/containerd/containerd.sock
{{- else -}}
/run/containerd/containerd.sock
{{- end -}}
{{- end -}}
