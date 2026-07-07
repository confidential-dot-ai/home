{{/*
  Inference-engine presets. The chart treats the engine as an opaque HTTP
  upstream; the only engine-specific fact it needs is the default server port,
  read from engine.presets (the single source of truth, shared with
  validations.yaml). When engine.name is set this helper derives the
  operator-managed headless Service so the hop is mesh-intercepted (attested
  mTLS) rather than dialing a Service VIP the mesh cannot see; otherwise it
  returns tlsLb.upstream.address verbatim.

c8s.tlsLb.resolvedUpstreamAddress is tls-lb's upstream host[:port].

  engine.name == ""  -> tlsLb.upstream.address verbatim (may be empty: an
                        unset upstream renders no catch-all, a legal
                        install-then-attach state).
  engine.name set    -> c8s-<workloadId>.<namespace>.svc.cluster.local:<port>,
                        mirroring webhook.WorkloadServiceName / workloadSAN so
                        the dialed name is exactly the headless Service the
                        operator provisions and CDS signs. namespace defaults
                        to the release namespace.

validations.yaml rejects an unknown engine, a missing workloadId, and an
invalid one earlier with stable kind= markers; the index guard here only keeps
a typo'd engine.name from rendering a portless upstream if the helper is ever
reached directly.
*/}}
{{- define "c8s.tlsLb.resolvedUpstreamAddress" -}}
{{- $engine := .Values.engine -}}
{{- if not $engine.name -}}
{{ .Values.tlsLb.upstream.address }}
{{- else -}}
{{- $port := index $engine.presets $engine.name | default "" -}}
{{- if not $port -}}
{{- fail (printf "VALIDATION_ERROR kind=unknown_engine: engine.name=%q is not in engine.presets (%s)" $engine.name (join ", " (keys $engine.presets))) -}}
{{- end -}}
{{- $ns := $engine.namespace | default .Release.Namespace -}}
{{- printf "c8s-%s.%s.svc.cluster.local:%s" $engine.workloadId $ns $port -}}
{{- end -}}
{{- end -}}
