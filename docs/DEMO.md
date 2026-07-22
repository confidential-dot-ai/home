# c8s demo

This demo uses chart-managed CDS so the certificate bootstrap
path is self-contained. It is intended for review and demos, not as the final
production trust boundary.

## 1. Install c8s

This demo shows confidential-workload injection, not the public front door, so
it installs with tls-lb disabled. To also expose a workload through tls-lb, give
it an upstream instead (see [tls-lb upstream](operator.md#tls-lb-upstream)).

```sh
c8s install --namespace c8s-system -f - <<'EOF'
tlsLb:
  enabled: false
EOF
```

## 2. Apply optional CRD object

CRDs are advisory. This object is useful for status display and review:

```sh
kubectl apply -f samples/confidentialworkload.yaml
```

## 3. Deploy an annotated workload

```sh
kubectl apply -f samples/nginx-confidential-pod.yaml
```

The pod template annotation `confidential.ai/cw: demo-nginx` is the security
opt-in. The `ConfidentialWorkload` object is not required for injection.

## 4. Inspect the result

```sh
kubectl get pods
kubectl describe pod -l app=demo-nginx
kubectl get cwl -A
```

Expected injected pieces:

- an init container and renewal sidecar running `c8s get-cert`;
- an in-memory `c8s-certs` volume;
- workload containers mounting `/etc/c8s/certs`;
- no injected credential Secret references.

## Reset

```sh
kubectl delete -f samples/nginx-confidential-pod.yaml
kubectl delete -f samples/confidentialworkload.yaml
c8s uninstall
```

`c8s uninstall` wraps `helm uninstall c8s -n c8s-system`; on a `--cvm-mode=pod`
install it also sweeps the kata runtime artifacts off the nodes (see
[`kata.md`](kata.md#uninstalling)).

## Next

For the KMS stack — attestation-gated secrets via the OpenBao broker and
openbao-gated LUKS volumes — follow the dedicated runbook:
[`KMS_DEMO.md`](KMS_DEMO.md).
