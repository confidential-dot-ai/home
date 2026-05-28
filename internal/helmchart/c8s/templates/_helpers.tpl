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

{{- define "c8s.cdsName" -}}
{{- printf "%s-cds" .Release.Name | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "c8s.kataName" -}}
{{- printf "%s-kata-deploy" .Release.Name | trunc 63 | trimSuffix "-" -}}
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

{{- define "c8s.cdsImage" -}}
{{- if .Values.cds.image.digest -}}
{{ .Values.cds.image.repository }}@{{ .Values.cds.image.digest }}
{{- else if .Values.cds.image.tag -}}
{{ .Values.cds.image.repository }}:{{ .Values.cds.image.tag }}
{{- else -}}
{{ fail "cds.image.tag or cds.image.digest must be set" }}
{{- end -}}
{{- end -}}

{{- define "c8s.kataDeployImage" -}}
{{- if and .Values.kata.image.digest .Values.kata.image.tag -}}
{{ fail "kata.image.tag and kata.image.digest are mutually exclusive — set one, not both (digest wins silently otherwise, which surprises operators bumping versions)" }}
{{- else if .Values.kata.image.digest -}}
{{ .Values.kata.image.repository }}@{{ .Values.kata.image.digest }}
{{- else if .Values.kata.image.tag -}}
{{ .Values.kata.image.repository }}:{{ .Values.kata.image.tag }}
{{- else -}}
{{ fail "kata.image.tag or kata.image.digest must be set" }}
{{- end -}}
{{- end -}}

{{/*
  Image used by the RKE2 containerd-prep initContainer. Pure shell — any
  POSIX-shell image works — but the container runs `privileged: true` with
  the host root mounted, so the same supply-chain rules as kata-deploy
  apply: digest-pin the image. Same precedence as kata-deploy: digest wins,
  setting both digest and tag fails the render so version bumps are loud.
*/}}
{{- define "c8s.kataContainerdPrepImage" -}}
{{- $img := .Values.kata.containerdPrep.image -}}
{{- if and $img.digest $img.tag -}}
{{ fail "kata.containerdPrep.image.tag and kata.containerdPrep.image.digest are mutually exclusive — set one, not both" }}
{{- else if $img.digest -}}
{{ $img.repository }}@{{ $img.digest }}
{{- else if $img.tag -}}
{{ $img.repository }}:{{ $img.tag }}
{{- else -}}
{{ fail "kata.containerdPrep.image.tag or kata.containerdPrep.image.digest must be set" }}
{{- end -}}
{{- end -}}

{{/*
  kata-deploy reads the host's rendered containerd config at the literal
  in-container path /etc/containerd/config.toml and writes the runtime
  drop-in beside it. The chart bind-mounts the host's real containerd config
  directory there — which differs by distro.
*/}}
{{- define "c8s.kataContainerdConfigDir" -}}
{{- if .Values.kata.containerdConfigDir -}}
{{ .Values.kata.containerdConfigDir }}
{{- else if eq .Values.kata.distro "rke2" -}}
/var/lib/rancher/rke2/agent/etc/containerd
{{- else if eq .Values.kata.distro "k8s" -}}
/etc/containerd
{{- else -}}
{{ fail (printf "kata.distro must be \"k8s\" or \"rke2\" (got %q), or set kata.containerdConfigDir explicitly" .Values.kata.distro) }}
{{- end -}}
{{- end -}}

{{- define "c8s.attestationServiceURL" -}}
http://{{ include "c8s.attestationServiceName" . }}.{{ .Release.Namespace }}.svc:{{ .Values.attestationService.port }}
{{- end -}}

{{- define "c8s.cdsURL" -}}
https://{{ include "c8s.cdsName" . }}.{{ .Release.Namespace }}.svc:{{ .Values.cds.port }}
{{- end -}}

{{/*
  c8s.trustRootURL is the URL clients (get-cert, ratls-mesh) point their single
  --cds-url at — the unified cds Service.
*/}}
{{- define "c8s.trustRootURL" -}}
{{ include "c8s.cdsURL" . }}
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
