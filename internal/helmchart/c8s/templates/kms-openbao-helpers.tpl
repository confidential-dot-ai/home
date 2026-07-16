{{/*
Fully qualified name of the dev-mode KMS OpenBao (and its Service DNS name).
For the default release name "c8s" this is "c8s-openbao".
*/}}
{{- define "kms.fullname" -}}
{{- printf "%s-openbao" .Release.Name | trunc 63 | trimSuffix "-" }}
{{- end }}

{{- define "kms.labels" -}}
helm.sh/chart: kms-openbao-0.1.0
{{ include "kms.selectorLabels" . }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
app.kubernetes.io/part-of: c8s
{{- end }}

{{- define "kms.selectorLabels" -}}
app: {{ include "kms.fullname" . }}
app.kubernetes.io/name: openbao
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}

{{/*
Name of the Secret carrying the dev root token the broker authenticates with.
*/}}
{{- define "kms.credSecretName" -}}
{{ include "kms.fullname" . }}-dev-cred
{{- end }}

{{/*
Effective OpenBao settings for the secret-broker: the operator's explicit
secretBroker.openbao.* values win; with kms.enabled the unset ones default to
the in-release dev store (plain-HTTP service, unattested, dev-cred token).
validations.yaml rejects kms.enabled combined with an explicit address, so
these only ever fill true gaps.
*/}}
{{- define "secret-broker.openbaoAddress" -}}
{{- $addr := .Values.secretBroker.openbao.address -}}
{{- if $addr -}}
{{- $addr -}}
{{- else if .Values.kms.enabled -}}
{{- printf "http://%s.%s.svc:%v" (include "kms.fullname" .) .Release.Namespace .Values.kms.port -}}
{{- else -}}
{{- fail "secretBroker.openbao.address is required when secretBroker.enabled (or set kms.enabled for the dev store)" -}}
{{- end -}}
{{- end }}

{{- define "secret-broker.openbaoAttested" -}}
{{- if .Values.kms.enabled -}}
false
{{- else -}}
{{- .Values.secretBroker.openbao.attested -}}
{{- end -}}
{{- end }}

{{- define "secret-broker.openbaoCredName" -}}
{{- if .Values.secretBroker.openbao.credentialSecret.name -}}
{{- .Values.secretBroker.openbao.credentialSecret.name -}}
{{- else if .Values.kms.enabled -}}
{{- include "kms.credSecretName" . -}}
{{- end -}}
{{- end }}

{{- define "secret-broker.openbaoCredKey" -}}
{{- if .Values.secretBroker.openbao.credentialSecret.name -}}
{{- .Values.secretBroker.openbao.credentialSecret.key -}}
{{- else if .Values.kms.enabled -}}
token
{{- end -}}
{{- end }}
