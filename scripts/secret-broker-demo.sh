#!/usr/bin/env bash
# Hardware-free end-to-end demo for `c8s secret-broker`.
#
# Stands up a real OpenBao (dev mode) behind the broker and fetches a secret as
# an attested workload, using a stock curl client in place of a Vault Agent.
# It uses --peer-verify=ca (identity-gated) because the measurement-gated
# (--peer-verify=ratls) path needs SEV-SNP/TDX hardware.
#
# Requires `bao` (or set BAO=/path/to/bao), `c8s` (or set C8S=/path/to/c8s),
# plus openssl, curl, and jq on PATH.
set -euo pipefail
BAO="${BAO:-bao}"
C8S="${C8S:-c8s}"
WORK="$(mktemp -d)"
trap 'set +e; [ -n "${BAO_PID:-}" ] && kill "$BAO_PID" 2>/dev/null; [ -n "${BRK_PID:-}" ] && kill "$BRK_PID" 2>/dev/null; rm -rf "$WORK"' EXIT
cd "$WORK"

echo "### 1. TLS material (one demo CA signs the broker server cert + client certs)"
openssl ecparam -name prime256v1 -genkey -noout -out ca.key
openssl req -x509 -new -key ca.key -sha256 -days 1 -subj "/CN=demo-ca" -out ca.crt
openssl ecparam -name prime256v1 -genkey -noout -out server.key
openssl req -new -key server.key -subj "/CN=secret-broker" -out server.csr
openssl x509 -req -in server.csr -CA ca.crt -CAkey ca.key -CAcreateserial -days 1 \
  -extfile <(printf "subjectAltName=IP:127.0.0.1\nextendedKeyUsage=serverAuth") -out server.crt
openssl ecparam -name prime256v1 -genkey -noout -out client.key
openssl req -new -key client.key -subj "/CN=api" -out client.csr
openssl x509 -req -in client.csr -CA ca.crt -CAkey ca.key -CAcreateserial -days 1 \
  -extfile <(printf "subjectAltName=DNS:api\nextendedKeyUsage=clientAuth") -out client.crt

echo "### 2. release policy: workload 'api' may read secret/data/api/*"
echo '{ "rules": [ { "workloadId": "api", "allow": ["secret/data/api/*"] } ] }' > policy.json

echo "### 3. start real OpenBao (dev) and write a secret"
BAO_DEV_ROOT_TOKEN_ID=root nohup "$BAO" server -dev -dev-listen-address=127.0.0.1:8200 >bao.log 2>&1 &
BAO_PID=$!
curl -fsS --retry 30 --retry-connrefused --retry-delay 1 http://127.0.0.1:8200/v1/sys/health >/dev/null
"$BAO" kv put -address=http://127.0.0.1:8200 secret/api/db password=s3cr3t >/dev/null

echo "### 4. start the secret-broker"
nohup "$C8S" secret-broker --host 127.0.0.1 --port 8443 \
  --peer-verify=ca --client-ca ca.crt --tls-cert server.crt --tls-key server.key \
  --policy policy.json \
  --openbao-addr http://127.0.0.1:8200 --openbao-attested=false --openbao-token root \
  >broker.log 2>&1 &
BRK_PID=$!
# Strict mTLS: the health probe must present a client cert too (k8s uses a TCP probe).
curl -fsS --retry 30 --retry-connrefused --retry-delay 1 \
  --cacert ca.crt --cert client.crt --key client.key https://127.0.0.1:8443/healthz >/dev/null

echo "### 5. workload 'api' logs in over mTLS and reads the secret"
C="curl -fsS --cacert ca.crt --cert client.crt --key client.key"
TOKEN=$($C -X POST https://127.0.0.1:8443/v1/auth/cert/login | jq -r .auth.client_token)
GOT=$($C -H "X-Vault-Token: $TOKEN" https://127.0.0.1:8443/v1/secret/data/api/db | jq -r .data.data.password)
echo "    fetched secret/data/api/db password = $GOT"

[ "$GOT" = "s3cr3t" ] && echo "RESULT: PASS" || { echo "RESULT: FAIL"; cat broker.log; exit 1; }
