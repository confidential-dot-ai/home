{{/*
  Common helpers. Keep these minimal — the chart is simple enough not to
  warrant the Bitnami-style helper maze.
*/}}

{{- define "c8s.fullname" -}}
{{- printf "%s" .Release.Name | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "c8s.operatorName" -}}
{{- printf "%s-operator" .Release.Name | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "c8s.attestationServiceName" -}}
{{- printf "%s-attestation-service" .Release.Name | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "c8s.assamName" -}}
{{- printf "%s-assam" .Release.Name | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "c8s.assamResourceMapName" -}}
{{- printf "%s-resource-map" (include "c8s.assamName" .) | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "c8s.certIssuerName" -}}
{{- printf "%s-cert-issuer" .Release.Name | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{/*
  Image refs prefer digest when set — floating tags silently drift the
  binary running inside the TEE and invalidate the measurement allowlist.
  The chart does not ship a default tag; the consumer (c8s install CLI
  or fleet HelmRelease) must supply either tag or digest, otherwise the
  helper fails rendering rather than producing a silently-broken manifest.
*/}}
{{- define "c8s.image" -}}
{{- if .Values.image.digest -}}
{{ .Values.image.repository }}@{{ .Values.image.digest }}
{{- else if .Values.image.tag -}}
{{ .Values.image.repository }}:{{ .Values.image.tag }}
{{- else -}}
{{ fail "image.tag or image.digest must be set" }}
{{- end -}}
{{- end -}}

{{- define "c8s.attestationServiceImage" -}}
{{- if .Values.attestationService.image.digest -}}
{{ .Values.attestationService.image.repository }}@{{ .Values.attestationService.image.digest }}
{{- else if .Values.attestationService.image.tag -}}
{{ .Values.attestationService.image.repository }}:{{ .Values.attestationService.image.tag }}
{{- else -}}
{{ fail "attestationService.image.tag or attestationService.image.digest must be set" }}
{{- end -}}
{{- end -}}

{{- define "c8s.assamImage" -}}
{{- if .Values.assam.image.digest -}}
{{ .Values.assam.image.repository }}@{{ .Values.assam.image.digest }}
{{- else if .Values.assam.image.tag -}}
{{ .Values.assam.image.repository }}:{{ .Values.assam.image.tag }}
{{- else -}}
{{ fail "assam.image.tag or assam.image.digest must be set" }}
{{- end -}}
{{- end -}}

{{- define "c8s.certIssuerImage" -}}
{{- if .Values.certIssuer.image.digest -}}
{{ .Values.certIssuer.image.repository }}@{{ .Values.certIssuer.image.digest }}
{{- else if .Values.certIssuer.image.tag -}}
{{ .Values.certIssuer.image.repository }}:{{ .Values.certIssuer.image.tag }}
{{- else -}}
{{ fail "certIssuer.image.tag or certIssuer.image.digest must be set" }}
{{- end -}}
{{- end -}}

{{- define "c8s.attestationServiceURL" -}}
http://{{ include "c8s.attestationServiceName" . }}.{{ .Release.Namespace }}.svc:{{ .Values.attestationService.port }}
{{- end -}}

{{- define "c8s.assamURL" -}}
https://{{ include "c8s.assamName" . }}.{{ .Release.Namespace }}.svc:{{ .Values.assam.port }}
{{- end -}}

{{- define "c8s.certIssuerURL" -}}
https://{{ include "c8s.certIssuerName" . }}.{{ .Release.Namespace }}.svc:{{ .Values.certIssuer.port }}
{{- end -}}

{{- define "c8s.certIssuerJWKSURL" -}}
https://{{ include "c8s.assamName" . }}.{{ .Release.Namespace }}.svc:{{ .Values.assam.port }}/.well-known/jwks.json
{{- end -}}

{{- define "c8s.certIssuerResourceMapName" -}}
{{- printf "%s-resource-map" (include "c8s.certIssuerName" .) | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "c8s.certIssuerPublicBundleClaimName" -}}
{{- default (printf "%s-public-bundle" (include "c8s.certIssuerName" .)) .Values.certIssuer.ca.publicBundlePersistence.claimName | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "c8s.attestationServiceConfig" -}}
{{- $root := .root -}}
[server]
bind = "0.0.0.0:{{ $root.Values.attestationService.port }}"
mode = "hosted"

[server.tls]
enabled = false

[attestation]
enabled = true
platforms = [{{- range $i, $p := $root.Values.attestationService.platforms -}}
  {{- if $i }}, {{ end -}}{{- $p | quote -}}
{{- end -}}]

[certs]
cache_max_entries = 1024
{{- end -}}

{{- define "c8s.commonLabels" -}}
app.kubernetes.io/name: c8s-operator
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/managed-by: Helm
{{- end -}}

{{- define "c8s.serviceAccountImagePullSecrets" -}}
{{- with .Values.serviceAccount.imagePullSecrets }}
imagePullSecrets:
{{ toYaml . }}
{{- end -}}
{{- end -}}
