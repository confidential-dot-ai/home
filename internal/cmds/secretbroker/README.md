# secret-broker

`c8s secret-broker` is the c8s **Secrets Manager Proxy** (whitepaper §4.3, §5.6.4
"Fit and limits"). It sits inside the trust boundary and brokers access from
attested workloads to a vanilla **OpenBao** (or HashiCorp Vault) instance, so
key material is released only over an attestation-gated channel.

It speaks a subset of the **Vault HTTP API**, so unmodified Vault/OpenBao Agent
and CSI tooling work against it unchanged — point the agent's `vault.address` at
the broker.

```
 workload pod (CDS mesh identity)                in TCB                    store
 ┌───────────────────────────────┐         ┌──────────────────┐     ┌──────────────┐
 │ app ← /vault/secrets (tmpfs)   │ mTLS    │ secret-broker    │     │ OpenBao      │
 │ Vault Agent (UNMODIFIED) ──────┼────────►│  verify peer     │     │ (attested by │
 │   auth=cert (the c8s cert)     │ (broker │  policy check    │────►│  default, or │
 │   address=https://broker:8443  │  ends   │  Vault translate │     │  external)   │
 └───────────────────────────────┘  TLS)   └──────────────────┘     └──────────────┘
   caller measurement/identity is read off the CDS-issued client cert
```

## Trust flow

1. **Caller verification** happens at the TLS layer (`--peer-verify`):
   - `ratls` (default, production): the caller's client cert carries a TEE
     attestation report; the broker verifies the hardware chain and the launch
     measurement against `--measurements`. Needs SEV-SNP/TDX (or the in-cluster
     attestation-api for az-snp).
   - `ca`: the client cert is verified by X.509 chain to the CDS mesh CA
     (`--client-ca`) and identity is taken from the cert SAN. Use where the CDS
     issuance decision is the trust anchor, and for the hardware-free demo.
2. **Policy check** (`--policy`, deny-by-default): a JSON file maps
   `(measurement | workloadId)` to the KV paths they may read.
3. **Token mint**: on `cert/login` the broker mints a short-TTL token **bound to
   the caller's client cert** (a token cannot be replayed on a different cert).
4. **Brokered read**: the broker authenticates to OpenBao with its own identity
   (`--openbao-token` or AppRole) and returns the KV v2 value. The store never
   sees the workload — only the broker.

`--openbao-attested` (default `true`) requires the store to present a valid TEE
attestation (RA-TLS); set it `false` for an external/managed store, in which
case the broker is the documented edge of the trust boundary.

## Policy format

```json
{
  "rules": [
    { "workloadImages": { "main": ["sha256:<hex>"] }, "allow": ["secret/data/api/db#password"] },
    { "workloadId": "api", "measurements": ["<sha384-hex>"], "allow": ["secret/data/api/*#password"] },
    { "workloadId": "*", "allow": ["secret/data/shared/*"] }
  ]
}
```

A rule matches when every constraint it sets holds (AND); the caller's grant is
the union of `allow` across matching rules. `*` matches one path segment, `**`
matches any trailing segments.

Each constraint is bound to a different part of the caller's identity, and each
fails closed where that part is unavailable:

- `workloadImages` — `{ "init": [...], "main": ["sha256:…"] }`, the container
  images the workload is admitted to run. The broker hashes them with the same
  role-partitioned `workloadclaims.Digest` the caller's RA-TLS cert commits to
  (config-claims, per PR #85/#100) and releases only to the pod whose *whole*
  attested image set matches. This is the strong, per-workload bind — trustworthy
  in **both** peer-verify modes (REPORTDATA-bound under `ratls`, CDS-vouched at
  issuance under `ca`) — and a caller carrying no workload claim is denied. It is
  the combined role-hash over the full set, not a per-image contains-check; author
  it with the policy CLI, which resolves image refs to digests for you.
- `measurements` — the CVM launch digest; only available under `--peer-verify=ratls`,
  so a measurement-constrained rule never matches under `ca`.
- `workloadId` — the CDS-issued SAN. Only trustworthy (and only set) under
  `--peer-verify=ca`, where the mesh CA chain-verified the leaf; under `ratls` the
  leaf is self-signed, so the SAN is not read as identity and a `workloadId`-scoped
  rule fails closed. Prefer `workloadImages` for anything security-bearing.

Each `allow` entry is a path pattern with an optional field scope,
`pattern#field[,field]`: the broker filters the KV read down to the named
fields, so `secret/data/api/db#password` releases only `password` and never the
rest of the item. An entry with no `#` grants every field at the path; if any
matching entry is unscoped, the caller gets all fields (a broader grant wins).

## API surface

| Method | Path | Purpose |
| ------ | ---- | ------- |
| `GET` | `/v1/sys/health` | Agent preflight |
| `POST`/`PUT` | `/v1/auth/cert/login` | mint a token for the verified caller (stock agents use PUT) |
| `GET` | `/v1/auth/token/lookup-self` | coarse token metadata |
| `GET` | `/v1/{mount}/data/{path}` | KV v2 read (brokered) |

No write or management surface is exposed to callers.

## Workload opt-in (zero app change)

A workload opts in with pod annotations. It must already be a c8s workload
(`confidential.ai/cw`, which provides the mesh identity); then:

```yaml
metadata:
  annotations:
    confidential.ai/cw: api                 # mesh identity (required)
    confidential.ai/secrets-inject: "true"  # inject the templating agent
    confidential.ai/secret-db: secret/data/api/db#password   # → /vault/secrets/db
    # confidential.ai/secrets-renew: "true"   # add a renewal sidecar (default: one-shot)
    # confidential.ai/secrets-dir: /vault/secrets
```

The mutating webhook injects an unmodified OpenBao/Vault Agent that auto-auths
to the broker with the pod's mesh cert and templates each secret into an
in-memory file the app reads unchanged. `confidential.ai/secret-<name>` →
`<secrets-dir>/<name>`; the value is `<vault-path>[#<field>]` (no field templates
the whole KV `data` object as JSON).

## Deploy

Enable the broker in the chart and point it at a backing store:

```yaml
secretBroker:
  enabled: true
  peerVerify: ratls            # measurement-gated (needs TEE); "ca" for the mesh-CA path
  measurements: ["<sha384>"]   # callers accepted in ratls mode
  releasePolicy:
    rules:
      - { workloadId: api, allow: ["secret/data/api/*"] }
  openbao:
    address: https://c8s-openbao.c8s-system.svc:8200
    attested: true             # require the store's TEE attestation; false = external store
    credentialSecret: { name: openbao-broker-cred, key: token }
secretAgent:                   # the injected agent image
  image: { repository: ghcr.io/openbao/openbao, tag: "2.5.5" }
  command: bao                 # "vault" for a HashiCorp Vault agent image
```

## HashiCorp Vault

The broker speaks the Vault HTTP API and its store client uses Vault's
AppRole/token + KV v2 endpoints — identical between OpenBao and Vault — so a
HashiCorp Vault works as the backing store unchanged. For the injected agent,
set `secretAgent.image` to a Vault image and `secretAgent.command: vault`.

## Try it

```sh
make build-c8s                 # or: go build -o c8s ./cmd/c8s
C8S=./build/c8s ./scripts/secret-broker-demo.sh   # needs `bao` on PATH too
```

## Status

Implemented and tested: the broker, the `secret-agent-config` renderer, the
webhook agent injection, and the Helm wiring. Validated hardware-free against a
real OpenBao (broker + unmodified `bao agent` → templated file). Pending a TEE
cluster: on-hardware `--peer-verify=ratls`, and live in-cluster injection
ordering. Future: scoped/least-privilege OpenBao tokens (the broker uses one
identity today), KV v1, and dynamic/transit engines.
