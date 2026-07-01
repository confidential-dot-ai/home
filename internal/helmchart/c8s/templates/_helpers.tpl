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

{{- define "c8s.attestationApiName" -}}
{{- printf "%s-attestation-api" .Release.Name | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "c8s.cdsName" -}}
{{- printf "%s-cds" .Release.Name | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "c8s.kataName" -}}
{{- printf "%s-kata-deploy" .Release.Name | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{/* int64 (fixes float64 -f values rendering as 7e+06) + reject non-ints so a
   bad -f can't fall open to UID 0. */}}
{{- define "c8s.int" -}}
{{- if and (not (kindIs "int" .)) (not (kindIs "float64" .)) (not (regexMatch "^-?[0-9]+$" (toString .))) -}}
{{- fail (printf "expected an integer, got %q" (toString .)) -}}
{{- end -}}
{{- int64 . -}}
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

{{- define "c8s.attestationApiImage" -}}
{{- if .Values.attestationApi.image.digest -}}
{{ .Values.attestationApi.image.repository }}@{{ .Values.attestationApi.image.digest }}
{{- else if .Values.attestationApi.image.tag -}}
{{ .Values.attestationApi.image.repository }}:{{ .Values.attestationApi.image.tag }}
{{- else -}}
{{ fail "attestationApi.image.tag or attestationApi.image.digest must be set" }}
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

{{- /*
c8s.kataGuestImageTag — the kata-guest-base artifact tag the puller fetches.
kata.guestImage.debug selects the `<tag>-debug` variant published alongside
every locked tag (same build, but the baked kata-agent policy allows the host
log/exec stream RPCs so kubectl logs/exec work — see values.yaml). The suffix
convention is fixed by kata-guest-base/scripts/ci/compute-tags.sh.
*/ -}}
{{- define "c8s.kataGuestImageTag" -}}
{{- if .Values.kata.guestImage.debug -}}
{{- printf "%s-debug" .Values.kata.guestImage.tag -}}
{{- else -}}
{{- .Values.kata.guestImage.tag -}}
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

{{- /*
c8s.attestationApiURL — the attestation-api endpoint injected into the operator
and CDS. Under kata.enabled the host attestation-api DaemonSet is typically not
rendered; the kata-guest-base image bakes an in-guest attestation-service on
loopback, and the components that consume this URL (the operator's get-cert
sidecars and CDS) run INSIDE the CVM, so they must dial 127.0.0.1, not the
(absent) host Service.
*/ -}}
{{- define "c8s.attestationApiURL" -}}
{{- if .Values.kata.enabled -}}
http://127.0.0.1:{{ .Values.attestationApi.port }}
{{- else -}}
http://{{ include "c8s.attestationApiName" . }}.{{ .Release.Namespace }}.svc:{{ .Values.attestationApi.port }}
{{- end -}}
{{- end -}}

{{- define "c8s.cdsURL" -}}
https://{{ include "c8s.cdsName" . }}.{{ .Release.Namespace }}.svc:{{ .Values.cds.port }}
{{- end -}}

{{/*
c8s.getCertContainers renders the c8s-cert native sidecar (restartPolicy:
Always) a chart-owned component uses to self-provision and renew a CDS-issued
mesh cert, instead of depending on webhook injection. Talks to CDS over RA-TLS.

Long-lived (not a run-once init) so its PID namespace can anchor
shareProcessNamespace. Under kata there is no in-guest pause container —
the agent uses the first container's pidns as the sandbox anchor
(sandbox.rs:update_shared_pidns), and pidns cannot be bind-mount-persisted
(namespace.rs explicitly rejects it). A short-lived bootstrap container
would let the anchor die before downstream containers joined it, and the
renew sidecar's /proc would never show nginx — SIGHUP-by-PID stops working.
Harmless under runc, where the pause container plays the same role.

--key-out is idempotent (load-or-generate); kubelet restarts of this
container reuse the existing key so the cert chain stays valid.

Caller passes a dict:
  root            - the root context (for c8s.image / c8s.cdsURL / c8s.attestationApiURL)
  san             - --san for the cert (the workload identity / Service DNS name)
  certOut         - --out path
  keyOut          - --key-out path
  caOut           - optional --ca-out path: write just the mesh CA bundle (the
                    issuer certs trailing the leaf in the CDS chain) so nginx can
                    serve it at the discovery endpoint without a separate ConfigMap
  volume          - name of the writable cert volume to mount
  mountPath       - where to mount it (the cert dir)
  renewInterval   - --renew-interval (Go time.Duration string, e.g. "6h", "30m", "1h30m")
  keyMode         - --key-mode (octal)
  runAsUser/runAsGroup/runAsNonRoot - securityContext (match the consumer so the
                    shared cert volume is readable by it)
  reloadNginx     - "true"/"false": SIGHUP nginx on renewal (tls-lb only)
  extraArgs       - optional list of additional get-cert args (e.g. discovery,
                    --reload-watch)
  extraMounts     - optional rendered volumeMount YAML
*/}}
{{- define "c8s.getCertContainers" -}}
{{- $root := .root -}}
- name: c8s-cert
  image: {{ include "c8s.image" $root }}
  imagePullPolicy: IfNotPresent
  restartPolicy: Always
  args:
    - get-cert
    - --cds-url={{ include "c8s.cdsURL" $root }}
    - --attestation-api-url={{ include "c8s.attestationApiURL" $root }}
    - --san={{ .san }}
    - --out={{ .certOut }}
    - --key-out={{ .keyOut }}
    - --key-mode={{ default "0640" .keyMode }}
    {{- with .caOut }}
    - --ca-out={{ . }}
    {{- end }}
    # Retry CDS in-process during a roll instead of exiting into kubelet
    # CrashLoopBackOff; still fails closed once the timeout elapses.
    - --initial-retry-timeout={{ $root.Values.certProvisioning.initialRetryTimeout }}
    - --renew-interval={{ .renewInterval }}
    - --reload-nginx={{ default "false" .reloadNginx }}
    - --continue-on-initial-error
    {{- range .extraArgs }}
    - {{ . }}
    {{- end }}
  volumeMounts:
    - name: {{ .volume }}
      mountPath: {{ .mountPath }}
    {{- with .extraMounts }}
    {{- . | nindent 4 }}
    {{- end }}
  # Gate the workload on the initial cert being written. Native sidecars
  # are considered "started" as soon as the process launches, so without
  # this probe the workload would race the initial fetch. `c8s probe-file`
  # is used because the image is gcr.io/distroless/static and has no `test`.
  #
  # The `/c8s` path is the binary location set by cmd/c8s/Dockerfile
  # (`COPY build/c8s /c8s`). If that COPY target or the ENTRYPOINT changes,
  # update this command — startupProbe.exec bypasses the ENTRYPOINT so the
  # full path must match.
  startupProbe:
    exec:
      command:
        - /c8s
        - probe-file
        - {{ .certOut }}
    periodSeconds: 1
    failureThreshold: 180
  securityContext:
    {{- include "c8s.getCertSecurityContext" . | nindent 4 }}
{{- end -}}

{{/*
SecurityContext for the get-cert containers: runs as the consumer's UID/GID so
the shared cert volume is writable, locked down otherwise. dict keys:
runAsUser, runAsGroup, runAsNonRoot.
*/}}
{{- define "c8s.getCertSecurityContext" -}}
allowPrivilegeEscalation: false
readOnlyRootFilesystem: true
runAsNonRoot: {{ .runAsNonRoot }}
runAsUser: {{ include "c8s.int" .runAsUser }}
runAsGroup: {{ include "c8s.int" .runAsGroup }}
capabilities:
  drop:
    - ALL
seccompProfile:
  type: RuntimeDefault
{{- end -}}

{{/*
  c8s.cdsDnsSanPattern is the in-cluster --dns-san-pattern the chart always
  passes to CDS: a regex matching any in-cluster Service DNS name
  (<name>.<namespace>.svc). CDS full-matches it, so workloads in any namespace
  (tls-lb, tee-proxy, ratls-mesh in the release namespace; tenant workloads in
  their own) can request a leaf for their Service name. Operators fronting a
  public domain append that hostname via cds.dnsSanPatterns, which adds further
  --dns-san-pattern args alongside this one rather than replacing it.
*/}}
{{- define "c8s.cdsDnsSanPattern" -}}
^[a-z0-9-]+[.][a-z0-9-]+[.]svc$
{{- end -}}

{{/*
  c8s.trustRootURL is the URL clients (get-cert, ratls-mesh) point their single
  --cds-url at — the unified cds Service.
*/}}
{{- define "c8s.trustRootURL" -}}
{{ include "c8s.cdsURL" . }}
{{- end -}}

{{- define "c8s.attestationApiConfig" -}}
{{- $root := .root -}}
[server]
bind = "0.0.0.0:{{ $root.Values.attestationApi.port }}"
mode = "hosted"

[server.tls]
enabled = false

[attestation]
enabled = true
platforms = [{{- range $i, $p := $root.Values.attestationApi.platforms -}}
  {{- if $i }}, {{ end -}}{{- $p | quote -}}
{{- end -}}]

[certs]
cache_max_entries = 1024
{{- end -}}

{{/*
  c8s.valueAtPath resolves a dotted path against a root dict. Call with
  (dict "root" <dict> "path" "a.b.c"); returns the value at that path (nil if
  any segment is missing). Lets c8s.components drive off the declarative
  .Values.c8sComponents paths instead of hardcoding each .Values.x.y.
*/}}
{{- define "c8s.valueAtPath" -}}
{{- $cur := .root -}}
{{- range $seg := splitList "." .path -}}
{{- if kindIs "map" $cur -}}{{- $cur = index $cur $seg -}}{{- else -}}{{- $cur = "" -}}{{- end -}}
{{- end -}}
{{- $cur | toJson -}}
{{- end -}}

{{/*
  c8s.components is the single source of truth for the c8s component image set,
  resolved from the declarative .Values.c8sComponents list. It returns a JSON
  list of {name, image, enabled, cdsExempt}, one per component, so the
  derivation (c8s.imageAllowlist) and the fail-closed coverage guard
  (validations.yaml) range over the same list — and `c8s install` reads the
  same .Values.c8sComponents via `helm show values`. Adding a component is one
  edit in values.yaml.

  - image:     the image object at valuePath (.repository/.digest)
  - enabled:   true when enabledPath is "" or resolves truthy; a disabled
               component is neither derived nor coverage-checked.
  - cdsExempt: cds is always seeded via its self-entry (independent of
               deriveComponents), so the coverage guard skips it.
*/}}
{{- define "c8s.components" -}}
{{- $root := . -}}
{{- $out := list -}}
{{- range $c := .Values.c8sComponents -}}
{{- $img := include "c8s.valueAtPath" (dict "root" $root.Values "path" $c.valuePath) | fromJson -}}
{{- $enabled := true -}}
{{- if $c.enabledPath -}}{{- $enabled = include "c8s.valueAtPath" (dict "root" $root.Values "path" $c.enabledPath) | fromJson -}}{{- end -}}
{{- $out = append $out (dict "name" $c.valuePath "image" $img "enabled" $enabled "cdsExempt" $c.cdsExempt) -}}
{{- end -}}
{{ $out | toJson }}
{{- end -}}

{{/*
  c8s.imageAllowlist returns the merged image-digest allowlist as a dict
  (sha256 -> image reference). It is the single source the NRI allowlist is
  built from — both CDS's served seed (c8s.allowlistSeedJSON) and each plugin's
  always_allow (nri-image-policy.bootConfig) render from it.

  Contents, lowest precedence first:
    1. derived c8s component images (from c8s.components) whose image.digest is
       set — only when bootstrapAllowlist.deriveComponents is true, so a
       digest-pinned `c8s install` self-allows the c8s components it deploys;
    2. the CDS image self-entry (cds.image), the same one the push-hook pins —
       always present (independent of deriveComponents) so CDS is admitted on
       its own node;
    3. operator-supplied nriImagePolicy.bootstrapAllowlist.digests, which
       override a derived entry for the same sha256 (fleet values win).
*/}}
{{- define "c8s.imageAllowlist" -}}
{{- $digests := dict -}}
{{- if .Values.nriImagePolicy.bootstrapAllowlist.deriveComponents -}}
{{- range $c := (include "c8s.components" . | fromJsonArray) -}}
{{- $img := get $c "image" -}}
{{- if and (get $c "enabled") (get $img "digest") -}}
{{- $_ := set $digests (get $img "digest") (printf "%s@%s" (get $img "repository") (get $img "digest")) -}}
{{- end -}}
{{- end -}}
{{- end -}}
{{- $cdsImg := .Values.cds.image -}}
{{- if $cdsImg.digest -}}
{{- $_ := set $digests $cdsImg.digest (printf "%s@%s" $cdsImg.repository $cdsImg.digest) -}}
{{- end -}}
{{- /* tls-lb nginx self-entry: a chart-deployed non-c8s system image. It is
       independently versioned and digest-pinned, so it is not in the
       tag-locked c8sComponents derive set (the resolver would `crane digest
       nginx:<c8s-tag>`). Seed it from its pinned digest whenever tls-lb is
       enabled — like the CDS self-entry above, independent of deriveComponents
       — so a default install admits the nginx it ships without the operator
       hand-pinning it in bootstrapAllowlist.digests. Operator-supplied digests
       below still override. */}}
{{- if .Values.tlsLb.enabled -}}
{{- $lbImg := .Values.tlsLb.nginx.image -}}
{{- if $lbImg.digest -}}
{{- $_ := set $digests $lbImg.digest (printf "%s@%s" $lbImg.repository $lbImg.digest) -}}
{{- end -}}
{{- end -}}
{{- range $digest, $image := .Values.nriImagePolicy.bootstrapAllowlist.digests -}}
{{- $_ := set $digests $digest $image -}}
{{- end -}}
{{ $digests | toJson }}
{{- end -}}

{{/*
  c8s.allowlistSeedJSON renders c8s.imageAllowlist as the JSON shape CDS's
  --allowlist-seed expects ({"version","digests"}). CDS seeds its served
  /allowlist from it so the first worker pull returns a real list rather than
  an empty set.
*/}}
{{- define "c8s.allowlistSeedJSON" -}}
{{ dict "version" "1" "digests" (include "c8s.imageAllowlist" . | fromJson) | toJson }}
{{- end -}}

{{- define "c8s.commonLabels" -}}
app.kubernetes.io/name: c8s-operator
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/managed-by: Helm
{{- end -}}

{{/* Emits an imagePullSecrets: block from .local, falling back to chart-wide
  .Values.imagePullSecrets. The install-time pull secret
  (.Values.imagePullSecret, the name of a pre-existing Secret) is appended to
  whichever list won, so it reaches every component even when a component
  overrides its local list; uniq keeps an operator's explicit reference to the
  same Secret from rendering twice. Callers place it with nindent. Call with
  (dict "root" $ "local" <list>). */}}
{{- define "c8s.imagePullSecrets" -}}
{{- $secrets := .local | default .root.Values.imagePullSecrets | default list -}}
{{- with .root.Values.imagePullSecret -}}
{{- $secrets = uniq (append $secrets (dict "name" .)) -}}
{{- end -}}
{{- with $secrets }}
imagePullSecrets:
{{ toYaml . }}
{{- end -}}
{{- end -}}

{{- define "c8s.serviceAccountImagePullSecrets" -}}
{{- include "c8s.imagePullSecrets" (dict "root" . "local" .Values.serviceAccount.imagePullSecrets) -}}
{{- end -}}

{{/*
  Image reference with digest support, inlined from the former c8s-common
  library chart. Usage: {{ include "c8s-common.image" .Values.<x>.image }}
  Renders repo@digest when .digest is set, otherwise repo:tag, and fails loudly
  if neither is provided.
*/}}
{{- define "c8s-common.image" -}}
{{- $img := . -}}
{{- if $img.digest -}}
{{ $img.repository }}@{{ $img.digest }}
{{- else -}}
{{ $img.repository }}:{{ required (printf "image.tag or image.digest is required for %s" $img.repository) $img.tag }}
{{- end -}}
{{- end }}

{{/*
  Namespace exclusions of the pod-injection webhook, as namespaceSelector
  matchExpressions. Shared by the webhook config and the admission policies
  that mirror its scope (kata enforcement, cw-label integrity): a namespace
  the webhook skips but a policy covers would fail closed on every pod in it,
  so all consumers must render the identical list.
*/}}
{{- define "c8s.webhookExcludedNamespaces" -}}
- key: kubernetes.io/metadata.name
  operator: NotIn
  values:
    - {{ .Release.Namespace }}
    - kube-system
    - kube-public
    - kube-node-lease
    {{- range .Values.webhook.extraExcluded }}
    - {{ . }}
    {{- end }}
{{- end }}
