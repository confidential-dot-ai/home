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
