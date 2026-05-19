{{/*
Expand the name of the chart.
*/}}
{{- define "ratls-mesh.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Create a default fully qualified app name.
*/}}
{{- define "ratls-mesh.fullname" -}}
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
{{- define "ratls-mesh.labels" -}}
helm.sh/chart: {{ printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" }}
{{ include "ratls-mesh.selectorLabels" . }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
app.kubernetes.io/part-of: c8s
{{- end }}

{{/*
Selector labels
*/}}
{{- define "ratls-mesh.selectorLabels" -}}
app: {{ include "ratls-mesh.fullname" . }}
app.kubernetes.io/name: {{ include "ratls-mesh.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}

{{/*
Image reference
*/}}
{{- define "ratls-mesh.image" -}}
{{ include "c8s-common.image" .Values.image }}
{{- end }}

{{/*
ratls-mesh.durationSeconds — parse a Go-style duration into integer seconds.
Supports the single-unit forms (Ns, Nm, Nh) that fit chart-bound arithmetic;
compound forms ("1m30s") are intentionally rejected so the bound math stays
exact instead of silently truncating via sprig's lenient int parsing.
*/}}
{{- define "ratls-mesh.durationSeconds" -}}
{{- $d := . -}}
{{- $unit := "" -}}
{{- $num := "" -}}
{{- if hasSuffix "h" $d -}}
{{- $unit = "h" -}}
{{- $num = trimSuffix "h" $d -}}
{{- else if hasSuffix "m" $d -}}
{{- $unit = "m" -}}
{{- $num = trimSuffix "m" $d -}}
{{- else if hasSuffix "s" $d -}}
{{- $unit = "s" -}}
{{- $num = trimSuffix "s" $d -}}
{{- else -}}
{{- fail (printf "duration %q must end with h, m, or s (single unit only)" $d) -}}
{{- end -}}
{{- if not (mustRegexMatch "^[0-9]+$" $num) -}}
{{- fail (printf "duration %q must be a positive integer followed by a single unit (h, m, or s)" $d) -}}
{{- end -}}
{{- $n := $num | int -}}
{{- if eq $unit "h" -}}{{- mul 3600 $n -}}
{{- else if eq $unit "m" -}}{{- mul 60 $n -}}
{{- else -}}{{- $n -}}{{- end -}}
{{- end }}
