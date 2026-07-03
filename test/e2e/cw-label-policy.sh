#!/usr/bin/env bash
# Live-cluster verification of the cw-label integrity admission policy
# (chart template cw-label-integrity-policy.yaml). Proves on a real API
# server what the chart tests cannot: the CEL actually evaluates (a broken
# expression with failurePolicy=Fail would deny ALL pod writes in covered
# namespaces), out-of-band cw writes are denied, and ordinary pods are
# unaffected.
#
# Needs: kubectl pointed at a cluster with the c8s chart installed.
set -euo pipefail
. "$(dirname "$0")/lib.sh"

ns="cw-label-policy-check-$$"
pod=probe

cleanup() { kubectl delete namespace "$ns" --ignore-not-found --wait=false >/dev/null 2>&1 || true; }
trap cleanup EXIT

expect_deny() {
  local what=$1; shift
  local out
  if out=$("$@" 2>&1); then
    fail "$what was admitted; want denial by cw-label-integrity. output: $out"
  fi
  grep -q "cw-label-integrity" <<<"$out" \
    || fail "$what was denied, but not by cw-label-integrity: $out"
  echo "ok: $what denied by the policy"
}

kubectl create namespace "$ns" >/dev/null

# Ordinary pod admission must be unaffected. This is also the canary for a
# broken CEL expression: failurePolicy=Fail turns one into a deny-all.
kubectl run "$pod" --namespace "$ns" --image=registry.k8s.io/pause:3.9 \
  --restart=Never >/dev/null \
  || fail "plain pod creation was denied; the policy is misfiring (broken CEL?)"
echo "ok: plain pod admitted"

# Out-of-band writes on a running pod: the post-create mutation the
# CREATE-only injection webhook cannot see.
expect_deny "post-create cw label" \
  kubectl label pod "$pod" --namespace "$ns" confidential.ai/cw=spoof
expect_deny "post-create cw annotation" \
  kubectl annotate pod "$pod" --namespace "$ns" confidential.ai/cw=spoof

# CREATE with the label but no matching annotation. --dry-run=server still
# runs admission, and holds even when the injection webhook is down.
expect_deny "pod created with cw label but no annotation" \
  kubectl run spoof --namespace "$ns" --image=registry.k8s.io/pause:3.9 \
    --restart=Never --labels=confidential.ai/cw=spoof --dry-run=server

echo "PASS: cw-label integrity policy enforced"
