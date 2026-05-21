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

{{/*
Path to the public-TLS certificate nginx serves. Resolves to the
operator-provided publicTLS secret when set, otherwise the CDS-issued
cert under tlsMountPath.
*/}}
{{- define "tls-lb.publicCertPath" -}}
{{- if .Values.publicTLS.secretName -}}
{{- printf "%s/%s" .Values.publicTLS.mountPath .Values.publicTLS.certKey -}}
{{- else -}}
{{- printf "%s/cert.pem" .Values.tlsMountPath -}}
{{- end -}}
{{- end -}}

{{- define "tls-lb.publicKeyPath" -}}
{{- if .Values.publicTLS.secretName -}}
{{- printf "%s/%s" .Values.publicTLS.mountPath .Values.publicTLS.keyKey -}}
{{- else -}}
{{- printf "%s/key.pem" .Values.tlsMountPath -}}
{{- end -}}
{{- end -}}

{{- define "tls-lb.discoveryFilePath" -}}
{{- printf "%s/%s" .Values.discovery.mountPath .Values.discovery.fileName -}}
{{- end -}}

{{/*
c8s sidecar-injection annotations consumed by the c8s admission webhook
(internal/webhook/pod_mutator.go). Caller must nindent into the Pod template
metadata annotations.
*/}}
{{- define "tls-lb.c8s-annotations" -}}
{{- $publicTLSMode := "cds" -}}
{{- if .Values.publicTLS.secretName -}}{{- $publicTLSMode = "webpki" -}}{{- end -}}
confidential.ai/cw: {{ include "tls-lb.san" . | quote }}
confidential.ai/c8s-cert-volume: "tls-certs"
confidential.ai/c8s-cert-dir: {{ .Values.tlsMountPath | quote }}
confidential.ai/c8s-cert-file: "cert.pem"
confidential.ai/c8s-key-file: "key.pem"
confidential.ai/c8s-renew-interval: {{ .Values.certProvisioning.renewInterval | quote }}
confidential.ai/c8s-reload-nginx: "true"
confidential.ai/c8s-get-cert-run-as-user: {{ .Values.nginx.runAsUser | quote }}
confidential.ai/c8s-get-cert-run-as-group: {{ .Values.nginx.runAsGroup | quote }}
{{- /* webhook default already matches runAsNonRoot=true; emit only on override. */ -}}
{{- if not .Values.nginx.runAsNonRoot }}
confidential.ai/c8s-get-cert-run-as-non-root: "false"
{{- end }}
{{- if .Values.certProvisioning.verbose }}
confidential.ai/c8s-get-cert-verbose: "true"
{{- end }}
{{- if .Values.publicTLS.secretName }}
confidential.ai/c8s-reload-watch-volume: "public-tls"
confidential.ai/c8s-reload-watch-mount-path: {{ .Values.publicTLS.mountPath | quote }}
confidential.ai/c8s-reload-watch-paths: {{ printf "%s,%s" (include "tls-lb.publicCertPath" .) (include "tls-lb.publicKeyPath" .) | quote }}
{{- end }}
{{- if .Values.discovery.enabled }}
confidential.ai/c8s-discovery-volume: "discovery"
confidential.ai/c8s-discovery-mount-path: {{ .Values.discovery.mountPath | quote }}
confidential.ai/c8s-discovery-out: {{ include "tls-lb.discoveryFilePath" . | quote }}
confidential.ai/c8s-discovery-cds-cert-url: {{ .Values.discovery.cdsCertPath | quote }}
confidential.ai/c8s-discovery-public-tls-mode: {{ $publicTLSMode | quote }}
{{- if .Values.meshCA.expose }}
confidential.ai/c8s-discovery-mesh-ca-url: {{ .Values.discovery.meshCAPath | quote }}
{{- end }}
{{- end }}
{{- end }}
