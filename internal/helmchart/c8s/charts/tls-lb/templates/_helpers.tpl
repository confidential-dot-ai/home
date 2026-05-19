{{/*
Expand the name of the chart.
*/}}
{{- define "tls-lb.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Create a default fully qualified app name.
*/}}
{{- define "tls-lb.fullname" -}}
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
Default the CDS certificate SAN to the chart-managed Service DNS name. Public
deployments should set .Values.san to the externally routed hostname.
*/}}
{{- define "tls-lb.san" -}}
{{- default (printf "%s.%s.svc" (include "tls-lb.fullname" .) .Release.Namespace) .Values.san }}
{{- end }}

{{/*
Common labels.
*/}}
{{- define "tls-lb.labels" -}}
helm.sh/chart: {{ include "tls-lb.name" . }}-{{ .Chart.Version | replace "+" "_" }}
{{ include "tls-lb.selectorLabels" . }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end }}

{{/*
Validate that san contains only safe characters for use in nginx config.
Allows DNS hostnames and wildcards (e.g. *.example.com).
*/}}
{{- define "tls-lb.validateSan" -}}
{{- if regexMatch `[^a-zA-Z0-9.*-]` . -}}
{{- fail (printf "san contains invalid characters: %s - only alphanumeric, dots, hyphens, and wildcards are allowed" .) -}}
{{- end -}}
{{- end -}}

{{/*
Validate that the protocol used for an upstream is only http or https
*/}}
{{- define "tls-lb.validateProtocol" -}}
{{- if not (or (eq . "http") (eq . "https")) -}}
{{- fail (printf "upstream.protocol must be 'http' or 'https', got: %s" .) -}}
{{- end -}}
{{- end -}}

{{/*
Catch the umbrella chart's default tee-proxy HTTP service port when callers
switch tls-lb to HTTPS upstream mode without also moving the backend port.
*/}}
{{- define "tls-lb.validateUpstreamAddress" -}}
{{- if and (eq .protocol "https") (eq .address "c8s-tee-proxy:80") -}}
{{- fail "tls-lb.upstream.protocol=https requires tls-lb.upstream.address to point at a TLS port; for the chart-managed tee-proxy use c8s-tee-proxy:443" -}}
{{- end -}}
{{- end -}}

{{/*
Selector labels.
*/}}
{{- define "tls-lb.selectorLabels" -}}
app.kubernetes.io/name: {{ include "tls-lb.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}
