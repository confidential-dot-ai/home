{{/*
Name of the secret-broker component.
*/}}
{{- define "secret-broker.name" -}}
{{- default "secret-broker" .Values.secretBroker.nameOverride | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Fully qualified secret-broker name (and its in-cluster Service DNS name).
*/}}
{{- define "secret-broker.fullname" -}}
{{- if .Values.secretBroker.fullnameOverride }}
{{- .Values.secretBroker.fullnameOverride | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- $name := default "secret-broker" .Values.secretBroker.nameOverride }}
{{- if contains $name .Release.Name }}
{{- .Release.Name | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- printf "%s-%s" .Release.Name $name | trunc 63 | trimSuffix "-" }}
{{- end }}
{{- end }}
{{- end }}

{{- define "secret-broker.labels" -}}
helm.sh/chart: secret-broker-0.1.0
{{ include "secret-broker.selectorLabels" . }}
app.kubernetes.io/version: ""
app.kubernetes.io/managed-by: {{ .Release.Service }}
app.kubernetes.io/part-of: c8s
{{- end }}

{{- define "secret-broker.selectorLabels" -}}
app: {{ include "secret-broker.fullname" . }}
app.kubernetes.io/name: {{ include "secret-broker.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}

{{/*
Injected OpenBao/Vault Agent image (the workload-side templating agent).
*/}}
{{- define "secret-broker.agentImage" -}}
{{ include "c8s-common.image" .Values.secretAgent.image }}
{{- end }}

{{/*
Image the webhook injects to open openbao-gated LUKS volumes. Empty repository
on .Values.luks.image falls back to the operator image (.Values.image) — the
same c8s binary exposes `c8s luks-open` as a subcommand.
*/}}
{{- define "c8s.luksOpenImage" -}}
{{- if .Values.luks.image.repository -}}
{{ include "c8s-common.image" .Values.luks.image }}
{{- else -}}
{{ include "c8s-common.image" .Values.image }}
{{- end -}}
{{- end }}
