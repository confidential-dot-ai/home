{{/*
Expand the name of the chart.
*/}}
{{- define "tls-lb.name" -}}
{{- default "tls-lb" .Values.tlsLb.nameOverride | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Create a default fully qualified app name.
*/}}
{{- define "tls-lb.fullname" -}}
{{- printf "%s-tls-lb" .Release.Name | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Default the CDS certificate SAN to the chart-managed Service DNS name. Public
deployments should set .Values.tlsLb.san to the externally routed hostname.
*/}}
{{- define "tls-lb.san" -}}
{{- default (printf "%s.%s.svc" (include "tls-lb.fullname" .) .Release.Namespace) .Values.tlsLb.san }}
{{- end }}

{{/*
Common labels.
*/}}
{{- define "tls-lb.labels" -}}
helm.sh/chart: tls-lb-0.5.0
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
{{- fail "tlsLb.upstream.protocol=https requires tlsLb.upstream.address to point at a TLS port; for the chart-managed tee-proxy use c8s-tee-proxy:443" -}}
{{- end -}}
{{- end -}}

{{/*
Derive an SNI/verification name from a host:port upstream address.
*/}}
{{- define "tls-lb.serverNameFromAddress" -}}
{{- $serverName := regexReplaceAll `^\[([^\]]+)\](?::[0-9]+)?$` . "${1}" -}}
{{- regexReplaceAll `^([^:]+)(?::[0-9]+)?$` $serverName "${1}" -}}
{{- end -}}

{{/*
Validate the proxy TLS settings for an HTTPS backend (the default upstream or a
route backend). Fails the render on values that would be silently ignored or
break out of the generated nginx directives. Args: protocol, tls (dict),
serverName, trustedCAPath, label.
*/}}
{{- define "tls-lb.validateProxyTLS" -}}
{{- $tls := default dict .tls -}}
{{- range $k := list "verify" "useCDSClientCert" -}}
{{- if and (hasKey $tls $k) (not (kindIs "bool" (index $tls $k))) -}}
{{- fail (printf "%s.tls.%s must be a boolean; do not set it via --set-string, got: %v" $.label $k (index $tls $k)) -}}
{{- end -}}
{{- end -}}
{{- if hasKey $tls "verifyDepth" -}}
{{- if not (regexMatch `^[0-9]+$` (printf "%v" $tls.verifyDepth)) -}}
{{- fail (printf "%s.tls.verifyDepth must be a non-negative integer, got: %v" $.label $tls.verifyDepth) -}}
{{- end -}}
{{- end -}}
{{- if eq $.protocol "https" -}}
{{- if not (regexMatch `^[^[:space:]{};/#]+$` $.serverName) -}}
{{- fail (printf "%s.tls.serverName must not contain whitespace, semicolons, braces, slashes, or '#', got: %s" $.label $.serverName) -}}
{{- end -}}
{{- if (default false $tls.verify) -}}
{{- if not (regexMatch `^/[^[:space:]{};]+$` $.trustedCAPath) -}}
{{- fail (printf "%s.tls.trustedCAPath must be an absolute path without whitespace, semicolons, or braces, got: %s" $.label $.trustedCAPath) -}}
{{- end -}}
{{- end -}}
{{- end -}}
{{- end -}}

{{/*
Render nginx proxy TLS directives for an HTTPS backend.
*/}}
{{- define "tls-lb.proxySSLDirectives" -}}
{{- if eq .protocol "https" -}}
{{- $tls := default dict .tls -}}
{{- if (default false $tls.useCDSClientCert) }}
proxy_ssl_certificate {{ .tlsMountPath }}/cert.pem;
proxy_ssl_certificate_key {{ .tlsMountPath }}/key.pem;
{{- end }}
proxy_ssl_server_name on;
proxy_ssl_name {{ .serverName }};
{{- if (default false $tls.verify) }}
{{- $verifyDepth := 2 }}
{{- if hasKey $tls "verifyDepth" }}{{- $verifyDepth = $tls.verifyDepth }}{{- end }}
proxy_ssl_verify on;
proxy_ssl_verify_depth {{ $verifyDepth }};
proxy_ssl_trusted_certificate {{ .trustedCAPath }};
{{- else }}
proxy_ssl_verify off;
{{- end }}
{{- end -}}
{{- end -}}

{{/*
Validate the global CORS configuration. Skips when disabled.
*/}}
{{- define "tls-lb.validateCORS" -}}
{{- $cors := default dict . -}}
{{- if hasKey $cors "enabled" -}}
{{- if not (kindIs "bool" $cors.enabled) -}}
{{- fail (printf "tlsLb.cors.enabled must be a boolean; do not set it via --set-string, got: %v" $cors.enabled) -}}
{{- end -}}
{{- end -}}
{{- if default false $cors.enabled -}}
{{- $origins := default (list) $cors.allowOrigins -}}
{{- if not $origins -}}
{{- fail "tlsLb.cors.enabled=true requires tlsLb.cors.allowOrigins to be non-empty" -}}
{{- end -}}
{{- range $o := $origins -}}
{{- if not (or (eq $o "*") (regexMatch `^https?://[A-Za-z0-9.-]+(?::[0-9]+)?$` $o)) -}}
{{- fail (printf "tlsLb.cors.allowOrigins entry %q must be \"*\" or a scheme://host[:port] URL" $o) -}}
{{- end -}}
{{- end -}}
{{- if and (default false $cors.allowCredentials) (has "*" $origins) -}}
{{- fail "tlsLb.cors.allowCredentials=true is incompatible with allowOrigins containing \"*\" (browsers reject this combination)" -}}
{{- end -}}
{{- range $field := list "allowMethods" "allowHeaders" "exposeHeaders" -}}
{{- range $v := default (list) (index $cors $field) -}}
{{- if regexMatch `[\r\n";{}\\]` $v -}}
{{- fail (printf "tlsLb.cors.%s entry %q must not contain CR, LF, quotes, semicolons, braces, or backslashes" $field $v) -}}
{{- end -}}
{{- end -}}
{{- end -}}
{{- if hasKey $cors "maxAge" -}}
{{- if not (regexMatch `^[0-9]+$` (printf "%v" $cors.maxAge)) -}}
{{- fail (printf "tlsLb.cors.maxAge must be a non-negative integer, got: %v" $cors.maxAge) -}}
{{- end -}}
{{- end -}}
{{- end -}}
{{- end -}}

{{/*
Validate a per-route CORS override. Only the `enabled` field is honored;
shared knobs live on tlsLb.cors. Args: dict { "cors": route.cors, "label": ... }.
*/}}
{{- define "tls-lb.validateRouteCORS" -}}
{{- if .cors -}}
{{- $cors := .cors -}}
{{- range $k, $_ := $cors -}}
{{- if ne $k "enabled" -}}
{{- fail (printf "%s.cors only supports the `enabled` field; remove %q (configure shared CORS knobs under tlsLb.cors)" $.label $k) -}}
{{- end -}}
{{- end -}}
{{- if hasKey $cors "enabled" -}}
{{- if not (kindIs "bool" $cors.enabled) -}}
{{- fail (printf "%s.cors.enabled must be a boolean; do not set it via --set-string, got: %v" $.label $cors.enabled) -}}
{{- end -}}
{{- end -}}
{{- end -}}
{{- end -}}

{{/*
Render the http-level CORS maps. `$cors_origin` echoes a matching request
Origin from tlsLb.cors.allowOrigins. The remaining maps implement
upstream-pass-through: when the upstream emits Access-Control-Allow-Origin
we adopt its full CORS header set verbatim (so browsers never see duplicate
headers); otherwise we fall back to tls-lb's configured values. Emitted only
when CORS is enabled. Caller nindents into the nginx `http {}` context.
*/}}
{{- define "tls-lb.corsMap" -}}
{{- $cors := default dict .Values.tlsLb.cors -}}
{{- if default false $cors.enabled -}}
{{- $origins := default (list) $cors.allowOrigins -}}
{{- $methods := join ", " (default (list "GET" "POST" "OPTIONS") $cors.allowMethods) -}}
{{- $headers := join ", " (default (list "Authorization" "Content-Type") $cors.allowHeaders) -}}
{{- $exposeHeaders := default (list) $cors.exposeHeaders -}}
{{- $credentials := ternary "true" "" (default false $cors.allowCredentials) }}
map $http_origin $cors_origin {
{{- if has "*" $origins }}
    default "*";
{{- else }}
    default "";
{{- range $o := $origins }}
    "{{ $o }}" "{{ $o }}";
{{- end }}
{{- end }}
}

map $upstream_http_access_control_allow_origin $cors_passthrough {
    default "0";
    "~.+"   "1";
}

map $cors_passthrough $cors_out_origin {
    "0" $cors_origin;
    "1" $upstream_http_access_control_allow_origin;
}

map $cors_passthrough $cors_out_methods {
    "0" "{{ $methods }}";
    "1" $upstream_http_access_control_allow_methods;
}

map $cors_passthrough $cors_out_headers {
    "0" "{{ $headers }}";
    "1" $upstream_http_access_control_allow_headers;
}

map $cors_passthrough $cors_out_credentials {
    "0" "{{ $credentials }}";
    "1" $upstream_http_access_control_allow_credentials;
}

map $cors_passthrough $cors_out_expose {
    "0" "{{ if $exposeHeaders }}{{ join ", " $exposeHeaders }}{{ end }}";
    "1" $upstream_http_access_control_expose_headers;
}
{{- end -}}
{{- end -}}

{{/*
Render per-location CORS directives. Non-preflight responses go through
$cors_out_* — either the upstream's CORS headers (passed through unchanged)
or tls-lb's configured ones, never both. proxy_hide_header drops the
upstream copies so the maps' re-emitted version is the only one on the
wire. Preflight OPTIONS short-circuits at nginx with tls-lb's configured
policy. Caller passes the effective CORS dict and guarantees CORS is
enabled. Caller nindents into a `location {}` block.
*/}}
{{- define "tls-lb.corsLocationDirectives" -}}
{{- $cors := default dict . -}}
{{- $methods := join ", " (default (list "GET" "POST" "OPTIONS") $cors.allowMethods) -}}
{{- $headers := join ", " (default (list "Authorization" "Content-Type") $cors.allowHeaders) -}}
{{- $maxAge := default 600 $cors.maxAge }}
proxy_hide_header Access-Control-Allow-Origin;
proxy_hide_header Access-Control-Allow-Methods;
proxy_hide_header Access-Control-Allow-Headers;
proxy_hide_header Access-Control-Allow-Credentials;
proxy_hide_header Access-Control-Expose-Headers;
if ($request_method = 'OPTIONS') {
    add_header Access-Control-Allow-Origin  $cors_origin always;
    add_header Access-Control-Allow-Methods "{{ $methods }}" always;
    add_header Access-Control-Allow-Headers "{{ $headers }}" always;
{{- if default false $cors.allowCredentials }}
    add_header Access-Control-Allow-Credentials "true" always;
{{- end }}
    add_header Access-Control-Max-Age       "{{ $maxAge }}" always;
    add_header Content-Length 0;
    return 204;
}
add_header Access-Control-Allow-Origin      $cors_out_origin always;
add_header Access-Control-Allow-Methods     $cors_out_methods always;
add_header Access-Control-Allow-Headers     $cors_out_headers always;
add_header Access-Control-Allow-Credentials $cors_out_credentials always;
add_header Access-Control-Expose-Headers    $cors_out_expose always;
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
{{- if .Values.tlsLb.publicTLS.secretName -}}
{{- printf "%s/%s" .Values.tlsLb.publicTLS.mountPath .Values.tlsLb.publicTLS.certKey -}}
{{- else -}}
{{- printf "%s/cert.pem" .Values.tlsLb.tlsMountPath -}}
{{- end -}}
{{- end -}}

{{- define "tls-lb.publicKeyPath" -}}
{{- if .Values.tlsLb.publicTLS.secretName -}}
{{- printf "%s/%s" .Values.tlsLb.publicTLS.mountPath .Values.tlsLb.publicTLS.keyKey -}}
{{- else -}}
{{- printf "%s/key.pem" .Values.tlsLb.tlsMountPath -}}
{{- end -}}
{{- end -}}

{{- define "tls-lb.discoveryFilePath" -}}
{{- printf "%s/%s" .Values.tlsLb.discovery.mountPath .Values.tlsLb.discovery.fileName -}}
{{- end -}}

{{/*
Discovery + verbose args shared by both get-cert containers. tls-lb owns its
own cert provisioning: the chart renders the same get-cert containers the
admission webhook would inject, driven directly by chart values instead of
round-tripping through pod annotations.
*/}}
{{- define "tls-lb.getCertCommonArgs" -}}
{{- if .Values.tlsLb.discovery.enabled }}
- --discovery-out={{ include "tls-lb.discoveryFilePath" . }}
- --discovery-cds-cert-url={{ .Values.tlsLb.discovery.cdsCertPath }}
- --discovery-public-tls-mode={{ ternary "webpki" "cds" (ne .Values.tlsLb.publicTLS.secretName "") }}
{{- if .Values.tlsLb.meshCA.expose }}
- --discovery-mesh-ca-url={{ .Values.tlsLb.discovery.meshCAPath }}
{{- end }}
{{- end }}
{{- if .Values.tlsLb.certProvisioning.verbose }}
- --verbose
{{- end }}
{{- end }}

{{/*
SecurityContext shared by the get-cert containers. Runs as nginx's UID/GID so
the shared tls-certs emptyDir is writable by both, with a locked-down posture
otherwise (no privilege escalation, read-only root, all caps dropped).
*/}}
{{- define "tls-lb.getCertSecurityContext" -}}
allowPrivilegeEscalation: false
readOnlyRootFilesystem: true
runAsNonRoot: {{ .Values.tlsLb.nginx.runAsNonRoot }}
runAsUser: {{ .Values.tlsLb.nginx.runAsUser }}
runAsGroup: {{ .Values.tlsLb.nginx.runAsGroup }}
capabilities:
  drop:
    - ALL
seccompProfile:
  type: RuntimeDefault
{{- end }}

{{/*
get-cert init + renew containers. c8s-init-cert obtains the leaf once and
exits; c8s-renew-cert runs as a native sidecar (restartPolicy: Always) that
reuses the key and SIGHUPs nginx on renewal. Caller nindents into the Pod
spec's initContainers list.
*/}}
{{- define "tls-lb.getCertContainers" -}}
{{- $certPem := printf "%s/cert.pem" .Values.tlsLb.tlsMountPath -}}
{{- $keyPem := printf "%s/key.pem" .Values.tlsLb.tlsMountPath -}}
- name: c8s-init-cert
  image: {{ include "c8s.image" . }}
  imagePullPolicy: IfNotPresent
  args:
    - get-cert
    - --cds-url={{ include "c8s.cdsURL" . }}
    - --attestation-api-url={{ include "c8s.attestationApiURL" . }}
    - --san={{ include "tls-lb.san" . }}
    - --out={{ $certPem }}
    - --key-out={{ $keyPem }}
    - --key-mode=0640
    {{- include "tls-lb.getCertCommonArgs" . | nindent 4 }}
  volumeMounts:
    {{- include "tls-lb.getCertVolumeMounts" (dict "ctx" . "reloadWatch" false) | nindent 4 }}
  securityContext:
    {{- include "tls-lb.getCertSecurityContext" . | nindent 4 }}
- name: c8s-renew-cert
  image: {{ include "c8s.image" . }}
  imagePullPolicy: IfNotPresent
  restartPolicy: Always
  args:
    - get-cert
    - --cds-url={{ include "c8s.cdsURL" . }}
    - --attestation-api-url={{ include "c8s.attestationApiURL" . }}
    - --san={{ include "tls-lb.san" . }}
    - --key={{ $keyPem }}
    - --out={{ $certPem }}
    - --renew-interval={{ .Values.tlsLb.certProvisioning.renewInterval }}
    - --reload-nginx=true
    - --continue-on-initial-error
    {{- if .Values.tlsLb.publicTLS.secretName }}
    - --reload-watch={{ include "tls-lb.publicCertPath" . }}
    - --reload-watch={{ include "tls-lb.publicKeyPath" . }}
    {{- end }}
    {{- include "tls-lb.getCertCommonArgs" . | nindent 4 }}
  volumeMounts:
    {{- include "tls-lb.getCertVolumeMounts" (dict "ctx" . "reloadWatch" true) | nindent 4 }}
  securityContext:
    {{- include "tls-lb.getCertSecurityContext" . | nindent 4 }}
{{- end }}

{{/*
Volume mounts for the get-cert containers: the shared tls-certs volume
(writable), the discovery volume when enabled, and the public-TLS volume for
the renew container's --reload-watch. dict args: ctx, reloadWatch (bool).
*/}}
{{- define "tls-lb.getCertVolumeMounts" -}}
{{- $ctx := .ctx -}}
- name: tls-certs
  mountPath: {{ $ctx.Values.tlsLb.tlsMountPath }}
{{- if $ctx.Values.tlsLb.discovery.enabled }}
- name: discovery
  mountPath: {{ $ctx.Values.tlsLb.discovery.mountPath }}
{{- end }}
{{- if and .reloadWatch $ctx.Values.tlsLb.publicTLS.secretName }}
- name: public-tls
  mountPath: {{ $ctx.Values.tlsLb.publicTLS.mountPath }}
  readOnly: true
{{- end }}
{{- end }}
