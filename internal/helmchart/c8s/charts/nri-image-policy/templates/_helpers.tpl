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
Image reference
*/}}
{{- define "nri-image-policy.image" -}}
{{ include "c8s-common.image" .Values.image }}
{{- end }}

{{/*
Full host path of the installed plugin binary.
*/}}
{{- define "nri-image-policy.hostPluginPath" -}}
{{ printf "%s/%s" .Values.hostPaths.pluginDir .Values.pluginFilename }}
{{- end }}

{{/*
Full host path of the rendered runtime config (image-policy.yaml).
*/}}
{{- define "nri-image-policy.hostConfigPath" -}}
{{ printf "%s/image-policy.yaml" .Values.hostPaths.configDir }}
{{- end }}

{{/*
Full host path of the rendered bootstrap allowlist.
*/}}
{{- define "nri-image-policy.hostBootstrapPath" -}}
{{ printf "%s/bootstrap.yaml" .Values.hostPaths.configDir }}
{{- end }}

{{/*
Full host path of the plugin's health unix socket.
*/}}
{{- define "nri-image-policy.hostHealthSocket" -}}
{{ printf "%s/%s" .Values.hostPaths.runtimeDir .Values.healthSocket }}
{{- end }}

{{/*
  Containerd config handling differs by host distro.

  k8s (vanilla / kubeadm): the installer patches the containerd config in
  place, between sentinel markers.

  rke2: RKE2 regenerates its containerd config from a template on every
  supervisor restart, so an in-place patch does not survive. The installer
  writes a standalone drop-in file into config-v3.toml.d/ instead (the dir
  tracks the containerd config schema version); the DaemonSet's
  containerd-prep initContainer adds the matching import.
*/}}

{{/* Host containerd config directory bind-mounted into the installer. */}}
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

{{/* Host service restart that makes containerd re-read its config. */}}
{{- define "nri-image-policy.restartCommand" -}}
{{- if .Values.containerd.restartCommand -}}
{{ .Values.containerd.restartCommand }}
{{- else if eq .Values.distro "rke2" -}}
systemctl restart rke2-agent
{{- else -}}
systemctl restart containerd
{{- end -}}
{{- end -}}

{{/* Host containerd socket the plugin connects to. */}}
{{- define "nri-image-policy.containerdSocket" -}}
{{- if .Values.containerd.socket -}}
{{ .Values.containerd.socket }}
{{- else if eq .Values.distro "rke2" -}}
/run/k3s/containerd/containerd.sock
{{- else -}}
/run/containerd/containerd.sock
{{- end -}}
{{- end -}}
