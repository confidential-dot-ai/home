#!/usr/bin/env bash
# Live-cluster verification that attested mesh-CA handoff works end to end:
# an attested probe pod (the deployed cds image running `request-handoff`)
# pulls the CA over /handoff and proves the material is the live trust root
# served on /ca. Proves on a real cluster what unit tests cannot: real TEE
# evidence, a real EAR minted by the live CDS, the real measurement gate,
# and the transfer over the cluster network.
#
# Needs: kubectl pointed at a node-as-CVM (non-kata) cluster with the c8s
# chart installed, cds.handoff.enabled=true, and a deployed cds image that
# includes the request-handoff subcommand.
#
# Env:
#   CDS_NS                 namespace of the cds deployment (default: discover)
#   PROBE_TIMEOUT_SECONDS  wait for the probe pod to finish (default 180)
set -euo pipefail
. "$(dirname "$0")/lib.sh"

probe_timeout="${PROBE_TIMEOUT_SECONDS:-180}"
cds_selector="app.kubernetes.io/name=c8s-operator,app.kubernetes.io/component=cds"

cds_ns=""
pod=""
kget_err=$(mktemp)
cleanup() {
  rm -f "$kget_err"
  if [ -n "$cds_ns" ] && [ -n "$pod" ]; then
    kubectl delete pod "$pod" -n "$cds_ns" --ignore-not-found --wait=false >/dev/null 2>&1 || true
  fi
}
# INT/TERM as well as EXIT: a Ctrl-C during the up-to-3-minute wait must not
# leave the probe pod (with the cds SA and pull rights) parked on the node.
trap cleanup EXIT INT TERM

# kget runs kubectl and, on failure, surfaces the real error instead of
# letting an empty result masquerade as "resource not found". stderr goes to
# a side file so a kubectl warning cannot corrupt the parsed output.
kget() {
  local out
  if ! out=$(kubectl "$@" 2>"$kget_err"); then
    fail "kubectl $* failed: $(cat "$kget_err")"
  fi
  printf '%s\n' "$out"
}

# --- discover the cds deployment ---------------------------------------------

ns_flag=(--all-namespaces)
[ -n "${CDS_NS:-}" ] && ns_flag=(-n "$CDS_NS")
read -r cds_ns cds_deploy < <(kget get deploy "${ns_flag[@]}" -l "$cds_selector" \
  -o jsonpath='{range .items[0]}{.metadata.namespace} {.metadata.name}{end}')
[ -n "${cds_deploy:-}" ] || fail "no cds deployment found (is the c8s chart installed? set CDS_NS to pick a namespace)"

# Wait for the deployment to be fully rolled out so any Running cds pod is the
# current generation, not a lingering old ReplicaSet pod (e.g. right after a
# `helm upgrade --set cds.handoff.enabled=true`).
kubectl rollout status deploy "$cds_deploy" -n "$cds_ns" --timeout=120s >/dev/null \
  || fail "cds deployment $cds_ns/$cds_deploy is not fully rolled out"

# The deployment's rendered args are the single source of truth for the
# probe's parameters; nothing is guessed or re-supplied by hand.
args=$(kget get deploy "$cds_deploy" -n "$cds_ns" \
  -o jsonpath='{range .spec.template.spec.containers[0].args[*]}{@}{"\n"}{end}')
arg() { sed -n "s/^--$1=//p" <<<"$args" | head -1; }

handoff_meas=$(arg handoff-measurements)
[ -n "$handoff_meas" ] || fail "cds runs without --handoff-measurements: /handoff is disabled. Enable it with: helm upgrade <release> ... --reuse-values --set cds.handoff.enabled=true (requires pinned cds.measurements). This script does not upgrade the release itself."

attest_url=$(arg attestation-api-url)
[ -n "$attest_url" ] || fail "cds args carry no --attestation-api-url"

ear_issuer=$(arg ear-issuer)
[ -n "$ear_issuer" ] || fail "cds args carry no --ear-issuer"

# Service by component + the named 'http' port, not positional indexes, so a
# prepended port or added sidecar does not shift the scrape.
read -r cds_svc cds_svc_port < <(kget get svc -n "$cds_ns" -l "$cds_selector" \
  -o jsonpath='{range .items[0]}{.metadata.name} {.spec.ports[?(@.name=="http")].port}{end}')
[ -n "${cds_svc:-}" ] || fail "no cds Service in $cds_ns"
[ -n "${cds_svc_port:-}" ] || fail "cds Service $cds_ns/$cds_svc has no port named http"
peer_url="https://${cds_svc}.${cds_ns}.svc:${cds_svc_port}"

# --- probe pod: deployed cds image, pinned to the cds node -------------------

# kubectl-only (no jq dependency, matching the sibling e2e scripts). Each
# pod field is read by name-keyed jsonpath so a sidecar cannot shift a
# positional index. One newline-joined read; sed splits the fields.
cds_pod=$(kget get pods -n "$cds_ns" -l "$cds_selector" \
  --field-selector=status.phase=Running \
  -o jsonpath='{.items[0].metadata.name}')
[ -n "${cds_pod:-}" ] || fail "no Running cds pod in $cds_ns"

# Refuse kata (in-guest attestation) by the chart's real signal, the pod's
# runtimeClassName, rather than sniffing the attestation-api URL shape.
runtime_class=$(kget get pod "$cds_pod" -n "$cds_ns" -o jsonpath='{.spec.runtimeClassName}')
case "$runtime_class" in
  *kata*) fail "cds runs under kata (runtimeClassName=$runtime_class); this probe supports node-as-CVM mode only" ;;
esac

# ServiceAccount (image pull secrets), node (measurement match), tolerations
# (NoExecute applies even to nodeName-pinned pods), the cds container image,
# and both securityContext levels ride on the live cds pod so the probe never
# drifts from the chart or trips Pod Security. cds_selector is a container-name
# jsonpath filter for the image/securityContext so a sidecar cannot shift it.
c='?(@.name=="cds")'
pod_fields=$(kget get pod "$cds_pod" -n "$cds_ns" -o jsonpath="\
{.spec.serviceAccountName}{\"\n\"}\
{.spec.nodeName}{\"\n\"}\
{.spec.containers[$c].image}{\"\n\"}\
{.spec.tolerations}{\"\n\"}\
{.spec.securityContext}{\"\n\"}\
{.spec.containers[$c].securityContext}")
cds_sa=$(sed -n 1p <<<"$pod_fields")
cds_node=$(sed -n 2p <<<"$pod_fields")
cds_image=$(sed -n 3p <<<"$pod_fields")
tolerations=$(sed -n 4p <<<"$pod_fields"); [ -n "$tolerations" ] || tolerations='[]'
pod_sec_ctx=$(sed -n 5p <<<"$pod_fields"); [ -n "$pod_sec_ctx" ] || pod_sec_ctx='{}'
ctr_sec_ctx=$(sed -n 6p <<<"$pod_fields"); [ -n "$ctr_sec_ctx" ] || ctr_sec_ctx='{}'
[ -n "$cds_image" ] || fail "cds pod $cds_ns/$cds_pod has no container named cds"

pod="ca-handoff-probe-$$"
operator_keys_cm="${cds_deploy}-operator-keys"
kubectl get configmap "$operator_keys_cm" -n "$cds_ns" >/dev/null 2>&1 ||
  fail "CDS handoff requires operator keys, but ConfigMap $cds_ns/$operator_keys_cm is missing"
echo "cds: $cds_ns/$cds_deploy on $cds_node; peer $peer_url"

# Release namespace + cds ServiceAccount: image pull secrets ride along and
# the image digest is already in the allowlist floor. nodeName pins the probe
# to cds's node so its launch measurement matches --handoff-measurements and
# the node-local attestation-api attests the right node. The probe's --timeout
# tracks PROBE_TIMEOUT_SECONDS so raising the env actually extends the in-pod
# retry window (leave the pod-watch a little longer to observe the verdict).
kubectl apply -f - >/dev/null <<EOF
apiVersion: v1
kind: Pod
metadata:
  name: $pod
  namespace: $cds_ns
spec:
  restartPolicy: Never
  nodeName: $cds_node
  serviceAccountName: $cds_sa
  automountServiceAccountToken: false
  tolerations: $tolerations
  securityContext: $pod_sec_ctx
  containers:
    - name: probe
      image: $cds_image
      args:
        - request-handoff
        - --peer-url=$peer_url
        - --attestation-api-url=$attest_url
        - --measurements=$handoff_meas
        - --operator-keys=/etc/cds-operator-keys/keys.pem
        - --expected-issuer=$ear_issuer
        - --timeout=${probe_timeout}s
      volumeMounts:
        - name: operator-keys
          mountPath: /etc/cds-operator-keys
          readOnly: true
      securityContext: $ctr_sec_ctx
  volumes:
    - name: operator-keys
      configMap:
        name: $operator_keys_cm
EOF

# --- await verdict ------------------------------------------------------------

# Watch a little past the probe's own --timeout so the pod reaches a terminal
# phase before we give up.
deadline=$((SECONDS + probe_timeout + 30))
phase=""
while :; do
  phase=$(kubectl get pod "$pod" -n "$cds_ns" -o jsonpath='{.status.phase}' 2>/dev/null || true)
  case "$phase" in Succeeded|Failed) break ;; esac
  if [ "$SECONDS" -ge "$deadline" ]; then
    kubectl describe pod "$pod" -n "$cds_ns" >&2 || true
    fail "probe did not reach a terminal phase in $((probe_timeout + 30))s (phase=${phase:-unknown})"
  fi
  sleep 3
done

kubectl logs "$pod" -n "$cds_ns" || true

# Pod phase is the verdict: Succeeded means the probe exited 0, which by
# construction requires the pulled CA to match the served trust root.
[ "$phase" = Succeeded ] || fail "handoff probe failed (see logs above)"
echo "PASS: mesh CA handoff verified end-to-end (EAR-gated transfer, served-CA match)"
