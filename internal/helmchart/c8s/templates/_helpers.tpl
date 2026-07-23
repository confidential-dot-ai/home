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

{{/*
  RuntimeClass name to use for CDS / tls-lb control-plane pods
  when kata is enforcing. Under --kata all c8s pods run as kata VMs, and
  the RC must match the cluster's confidential-VM hardware:

    tdxGuest=true → kata-qemu-tdx (Intel TDX)
    else          → kata-qemu-snp (SEV-SNP, default)

  Single-hardware per cluster today. If both are set we prefer TDX; the
  install CLI's --hardware-platform flag makes them mutually exclusive so
  this fall-through is theoretical (a hand-crafted -f override could hit
  it, and preferring one over failing keeps the render simple).

  Keep this in sync with kata.yaml's RC blocks (kata-qemu-snp,
  kata-qemu-tdx) and kata-enforcement.yaml's admission allowlist.
*/}}
{{- define "c8s.controlPlaneKataRuntimeClass" -}}
{{- if .Values.attestationApi.teeDevices.tdxGuest -}}
kata-qemu-tdx
{{- else -}}
kata-qemu-snp
{{- end -}}
{{- end -}}

{{/*
  Shim name (kata-deploy dir name under /opt/kata/share/defaults/kata-containers/runtimes/)
  for the confidential shim to configure on this node. Mirrors
  c8s.controlPlaneKataRuntimeClass: tdxGuest=true → qemu-tdx, else qemu-snp.
  Passed as SHIM_NAME to pull-and-configure.sh; used by kata-image-puller.yaml
  to target the correct configuration-qemu-<shim>.toml file. Single-hardware
  per cluster (see the note on c8s.controlPlaneKataRuntimeClass).
*/}}
{{- define "c8s.kataShimName" -}}
{{- if .Values.attestationApi.teeDevices.tdxGuest -}}
qemu-tdx
{{- else -}}
qemu-snp
{{- end -}}
{{- end -}}

{{/*
  Confidential-GPU RuntimeClass for this cluster's TEE. Mirrors
  c8s.controlPlaneKataRuntimeClass: tdxGuest=true → kata-qemu-tdx-nvidia,
  else kata-qemu-snp-nvidia. Keep in sync with kata.yaml's GPU RC blocks and
  kata-enforcement.yaml's admission allowlist.
*/}}
{{- define "c8s.kataGpuRuntimeClass" -}}
{{- if .Values.attestationApi.teeDevices.tdxGuest -}}
kata-qemu-tdx-nvidia
{{- else -}}
kata-qemu-snp-nvidia
{{- end -}}
{{- end -}}

{{/*
  Confidential-GPU shim name (kata-deploy dir under
  /opt/kata/share/defaults/kata-containers/runtimes/) for this cluster's TEE.
  Mirrors c8s.kataShimName: tdxGuest=true → qemu-nvidia-gpu-tdx, else
  qemu-nvidia-gpu-snp. Passed as SHIM_NAME to pull-and-configure.sh by
  kata-image-puller-nvidia.yaml.
*/}}
{{- define "c8s.kataGpuShimName" -}}
{{- if .Values.attestationApi.teeDevices.tdxGuest -}}
qemu-nvidia-gpu-tdx
{{- else -}}
qemu-nvidia-gpu-snp
{{- end -}}
{{- end -}}

{{/*
  c8s.hardwarePlatform — the CPU TEE this install targets, in the install
  CLI's --hardware-platform vocabulary (sev-snp | tdx). Keys off the same
  value as every platform helper above; forwarded to the operator so webhook
  injection matches the RuntimeClasses the chart renders.
*/}}
{{- define "c8s.hardwarePlatform" -}}
{{- if .Values.attestationApi.teeDevices.tdxGuest -}}
tdx
{{- else -}}
sev-snp
{{- end -}}
{{- end -}}

{{/*
  c8s.kataConfidentialShims — the confidential shim set for this platform, as
  kata-deploy SHIMS_X86_64 tokens: the CPU shim + the NVIDIA GPU shim. Only
  the declared platform's shims are installed and only its RuntimeClasses
  render (kata.yaml) — a single cluster is one CPU TEE, so the other
  platform's classes would be unschedulable decoys at best. Keep in lockstep
  with the RuntimeClasses in kata.yaml and the kata-enforcement allowlist
  (c8s.kataAllowedRuntimeClasses).
*/}}
{{- define "c8s.kataConfidentialShims" -}}
{{- if .Values.attestationApi.teeDevices.tdxGuest -}}
qemu-tdx qemu-nvidia-gpu-tdx
{{- else -}}
qemu-snp qemu-nvidia-gpu-snp
{{- end -}}
{{- end -}}

{{/*
  c8s.kataAllowedRuntimeClasses — the RuntimeClass names kata enforcement
  accepts, as a quoted CEL list body: the two non-confidential classes plus
  this platform's confidential (CPU, GPU) pair. Single source for the
  kata-enforcement expression and its message.
*/}}
{{- define "c8s.kataAllowedRuntimeClasses" -}}
{{- if .Values.attestationApi.teeDevices.tdxGuest -}}
'kata-qemu', 'kata-clh', 'kata-qemu-tdx', 'kata-qemu-tdx-nvidia'
{{- else -}}
'kata-qemu', 'kata-clh', 'kata-qemu-snp', 'kata-qemu-snp-nvidia'
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

{{- /*
c8s.kataGuestImageNvidiaTag — the confidential-GPU guest-image tag the nvidia
puller fetches: the base tag with a `-nvidia` suffix, or `-nvidia-debug` under
kata.guestImage.debug. CI publishes both in lockstep with the non-GPU pair
(kata-guest-base.yml), so one debug toggle drives every guest image — see
docs/kata-gpu.md "`--debug` and the GPU guest".
*/ -}}
{{- define "c8s.kataGuestImageNvidiaTag" -}}
{{- if .Values.kata.guestImage.debug -}}
{{- printf "%s-nvidia-debug" .Values.kata.guestImage.tag -}}
{{- else -}}
{{- printf "%s-nvidia" .Values.kata.guestImage.tag -}}
{{- end -}}
{{- end -}}

{{- /*
c8s.kataSandboxDevicePluginImage — the NVIDIA kata sandbox device plugin image.
Digest wins; the tag is kept only for human readability (same shape as the
puller image), because the plugin runs privileged with host devices mounted and
a floating tag would be root on every GPU node — so the digest is what's used.
*/ -}}
{{- define "c8s.kataSandboxDevicePluginImage" -}}
{{- $img := .Values.kata.gpu.sandboxDevicePlugin.image -}}
{{- if $img.digest -}}
{{ $img.repository }}@{{ $img.digest }}
{{- else if $img.tag -}}
{{ $img.repository }}:{{ $img.tag }}
{{- else -}}
{{ fail "kata.gpu.sandboxDevicePlugin.image.tag or .digest must be set" }}
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
and CDS. Three shapes:

  - kata.enabled: the kata-guest-base image bakes an in-guest attestation-service
    on loopback, and the consumers (the operator's get-cert sidecars and CDS) run
    INSIDE the CVM, so they dial 127.0.0.1 — not the (absent) host Service.
  - cvmMode=node: the node image bakes a HOST attestation-api on the node's
    loopback :8400 (no in-cluster Service). Pod-netns consumers cannot reach host
    loopback, so they dial the node's own IP via the $(HOST_IP) downward-API env
    var (c8s.attestationApiHostIPEnv), which the kubelet expands per-node before
    the process sees the arg. The operator forwards this string verbatim to the
    tenant get-cert sidecars it injects, so it must stay unexpanded there (the
    operator container deliberately omits HOST_IP); each tenant pod expands it
    against its own node.
  - otherwise: the in-cluster host Service DNS.
*/ -}}
{{- define "c8s.attestationApiURL" -}}
{{- if .Values.kata.enabled -}}
http://127.0.0.1:{{ .Values.attestationApi.port }}
{{- else if eq (.Values.attestationApi.cvmMode | default "baremetal") "node" -}}
http://$(HOST_IP):{{ .Values.attestationApi.port }}
{{- else -}}
http://{{ include "c8s.attestationApiName" . }}.{{ .Release.Namespace }}.svc:{{ .Values.attestationApi.port }}
{{- end -}}
{{- end -}}

{{- /*
c8s.attestationApiHostIPEnv — the HOST_IP downward-API env var that expands the
$(HOST_IP) placeholder in c8s.attestationApiURL. Rendered only under
cvmMode=node, where pod-netns consumers reach the node-baked host attestation-api
via the node's own IP. Empty in every other mode.
*/ -}}
{{- define "c8s.attestationApiHostIPEnv" -}}
{{- if eq (.Values.attestationApi.cvmMode | default "baremetal") "node" -}}
- name: HOST_IP
  valueFrom:
    fieldRef:
      fieldPath: status.hostIP
{{- end -}}
{{- end -}}

{{- define "c8s.cdsURL" -}}
https://{{ include "c8s.cdsName" . }}.{{ .Release.Namespace }}.svc:{{ .Values.cds.port }}
{{- end -}}

{{- /*
c8s.cdsHandoffPeerURL — the effective --handoff-peer-url for CA adoption on
startup. Empty means cold start (self-generate). The sentinel "self" expands to
the CDS Service URL, so an operator enabling adoption for a self-rolling
Deployment flips one value instead of hand-typing the in-cluster address; any
other value is used verbatim (adopt from a distinct peer).
*/ -}}
{{- define "c8s.cdsHandoffPeerURL" -}}
{{- if eq .Values.cds.handoff.peerUrl "self" -}}
{{ include "c8s.cdsURL" . }}
{{- else -}}
{{ .Values.cds.handoff.peerUrl }}
{{- end -}}
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
  {{- with (include "c8s.attestationApiHostIPEnv" $root) }}
  # cvmMode=node: expands $(HOST_IP) in --attestation-api-url to the node IP so
  # this pod-netns sidecar reaches the node-baked host attestation-api.
  env:
    {{- . | nindent 4 }}
  {{- end }}
  volumeMounts:
    - name: {{ .volume }}
      mountPath: {{ .mountPath }}
    {{- with .extraMounts }}
    {{- . | nindent 4 }}
    {{- end }}
  # The workload is gated on the initial cert by the c8s-cert-wait init
  # container below, not a startupProbe here: a native sidecar is "started"
  # the moment its process launches, and an exec startupProbe is denied by the
  # locked kata-qemu-snp guest (ExecProcessRequest := false), so it could never
  # pass there and the workload would hang in Init forever.
  securityContext:
    {{- include "c8s.getCertSecurityContext" . | nindent 4 }}
# c8s-cert-wait gates the workload on the initial cert without an exec probe.
# A plain (run-once) init container that blocks on the cert file is a
# CreateContainerRequest the locked guest allows, and normal init-completion
# ordering holds the workload until the attested cert exists — fail-closed.
# The `/c8s` path is the binary location from cmd/c8s/Dockerfile; command
# bypasses the ENTRYPOINT so the full path must match.
- name: c8s-cert-wait
  image: {{ include "c8s.image" $root }}
  imagePullPolicy: IfNotPresent
  command:
    - /c8s
    - probe-file
    - --wait
    - --timeout=3m
    - {{ .certOut }}
  volumeMounts:
    - name: {{ .volume }}
      mountPath: {{ .mountPath }}
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
  (tls-lb, ratls-mesh in the release namespace; tenant workloads in
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
{{- /* String compare, not fromJson: helm's fromJson decodes into a map, so a
       bare boolean yields a truthy error-map and every enabledPath component
       would count as enabled (over-allowlisting disabled components). */ -}}
{{- if $c.enabledPath -}}{{- $enabled = eq (include "c8s.valueAtPath" (dict "root" $root.Values "path" $c.enabledPath)) "true" -}}{{- end -}}
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
    2. the CDS image self-entry (cds.image) — always present (independent of
       deriveComponents) so CDS is admitted on whichever node it lands;
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
{{- /* containerd-prep init-container images (rke2-only): the host NRI plugin
       checks every container node-wide, so its own and kata's busybox prep
       image must be in the floor or a DaemonSet re-roll self-deadlocks on
       "image not in allowlist: busybox". Only seeded when the plugin enforces. */}}
{{- if .Values.nriImagePolicy.enabled -}}
{{- if eq .Values.nriImagePolicy.distro "rke2" -}}
{{- $prep := .Values.nriImagePolicy.containerdPrep.image -}}
{{- if $prep.digest -}}
{{- $_ := set $digests $prep.digest (printf "%s@%s" $prep.repository $prep.digest) -}}
{{- end -}}
{{- end -}}
{{- if and .Values.kata.enabled (eq .Values.kata.distro "rke2") -}}
{{- $kprep := .Values.kata.containerdPrep.image -}}
{{- if $kprep.digest -}}
{{- $_ := set $digests $kprep.digest (printf "%s@%s" $kprep.repository $kprep.digest) -}}
{{- end -}}
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

{{/*
  c8s.serveAllowlistSeed is true when CDS should render the --allowlist-seed
  ConfigMap/flag/mount. Three admission shapes consume CDS's served allowlist
  and so need the seed:
    - the chart's host NRI plugin (nriImagePolicy.enabled),
    - the in-guest policy-monitor baked into the kata-guest-base image
      (kata.enabled, i.e. --cvm-mode=pod), where the host plugin is off, and
    - the BAKED host NRI plugin on a node-as-CVM (--cvm-mode=node), where the
      chart's nriImagePolicy is disabled because the node image bakes the
      plugin — but that plugin still pulls the live allowlist from CDS, so the
      seed must be served or CDS starts empty and every un-baked component
      (operator, ratls-mesh, tls-lb's nginx, adopted workloads) is denied
      until an operator hand-runs `c8s allowlist add`.
  Gating on nriImagePolicy.enabled alone dropped the seed under both pod and
  node mode.
*/}}
{{- define "c8s.serveAllowlistSeed" -}}
{{- or .Values.nriImagePolicy.enabled .Values.kata.enabled (eq .Values.attestationApi.cvmMode "node") -}}
{{- end -}}

{{/*
  c8s.tlsLb.resolver — the DNS server nginx re-resolves upstreams against.
  An explicit tlsLb.nginx.resolver wins; empty derives from the host distro
  (kata.distro / nriImagePolicy.distro, both set by `c8s install`'s kubelet
  detection and required from GitOps installs anyway for the containerd
  layout). RKE2 names its CoreDNS Service rke2-coredns-rke2-coredns, and
  nginx exits at startup on a resolver name that does not resolve — the
  wrong default is a tls-lb crash-loop, not a degraded mode.
*/}}
{{- define "c8s.tlsLb.resolver" -}}
{{- if .Values.tlsLb.nginx.resolver -}}
{{- .Values.tlsLb.nginx.resolver -}}
{{- else if or (eq .Values.kata.distro "rke2") (eq .Values.nriImagePolicy.distro "rke2") -}}
rke2-coredns-rke2-coredns.kube-system.svc.cluster.local
{{- else -}}
kube-dns.kube-system.svc.cluster.local
{{- end -}}
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
