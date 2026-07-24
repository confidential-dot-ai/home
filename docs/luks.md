# LUKS volumes (`c8s luks`)

Operator flow for provisioning OpenBao-keyed LUKS volumes for confidential
workloads. This page is the contract: the KV schema, the annotation grammar,
the store postures, and the release-policy rule every volume needs.

## Threat-model position

The passphrase's confidentiality **is** the volume's confidentiality. It moves:

```
operator machine (mint) ──TLS──▶ OpenBao (at rest) ──broker──▶ workload guest (RA-TLS) ──▶ luksFormat/luksOpen in TEE memory
```

- **Never on the cluster node** (`--driver pvc`): no cryptsetup, no device,
  no host path — the first `luksFormat` runs in the guest init container.
- **Transiently on the operator machine**: `create` mints the passphrase in
  process memory (zeroized best-effort after the KV write). Same trust class
  as the pinned operator keys (THREAT_MODEL §6.3).
- **`--driver local` without `--defer-format` breaks this**: `luksFormat`
  runs on the host that executes the CLI, exposing the passphrase *and* the
  dm-crypt master key to that host, outside any TEE. Gated behind
  `--allow-host-format`; dev only, never tenant data.

## Store postures — the floor the volume inherits

The volume is only as confidential as the OpenBao holding its passphrase:

| Posture | How | Guarantee |
|---|---|---|
| Attested store | broker `--openbao-attested=true` (default); store presents RA-TLS evidence | passphrase never leaves attested TCBs after mint |
| External store | customer-run OpenBao/Vault (HSM-backed, outside the cluster); broker `--openbao-attested=false` | the **broker** is the edge of the trust boundary; the store's own hardening is the floor |
| Chart dev store | `--kms` in-chart OpenBao | **dev-grade**: unattested, dev-cred token — a host reading its memory recovers every passphrase |

## Contract (what later stages parse)

**KV schema** — KV v2 mount `secret` (required; v2's cas and metadata-delete
semantics are load-bearing):

```
secret/data/<workload>/luks-<name>   {"passphrase": "<hex>"}
```

The hex string *is* the passphrase — nothing hex-decodes it; cryptsetup reads
it from stdin at both format and open time.

**Annotations** (emitted by `create`; parsed by the webhook):

```
confidential.ai/luks-<name>:   dev=<device>|pvc=<claim>,mount=<path>,secret=<kv-path>#passphrase,fstype=ext4|xfs,mode=open|format-if-empty
confidential.ai/secret-<name>: <kv-path>#passphrase
confidential.ai/secrets-inject: "true"   (required alongside)
```

- The luks `<name>` and the secret `<name>` are the same; the passphrase is
  templated to `/vault/secrets/<name>`.
- `mode=format-if-empty` means **format-if-not-LUKS**: first boot formats
  whenever no LUKS header is detected. A host presenting a swapped or zeroed
  device causes a silent reformat — the data becomes unreachable (not
  readable). Treat any format event on an existing volume as an alarm.
- `dev=/dev/loopN` (local driver) is volatile: loop numbers do not survive a
  node reboot.
- `--name` is capped at 54 chars (the `c8s-luks-<name>` pod volume name and
  annotation keys cap at 63); `--mount` is restricted to
  `[A-Za-z0-9/._-]` so later stages can never meet a separator or
  shell-active character.

## The release rule every volume needs

Nothing auto-creates the broker grant: **without a matching
`secretBroker.releasePolicy.rules` entry, the pod cannot boot.** `create`
prints the rule for the volume; it looks like:

```yaml
secretBroker:
  releasePolicy:
    rules:
      - workloadId: c8s-<workload>.<namespace>.svc   # the CDS-issued SAN, not the bare id
        allow: ["secret/data/<workload>/luks-<name>#passphrase"]
```

- `workloadId` binds at CDS-issuance strength (chart forces `peerVerify: ca`
  under kata). The stronger bind is `workloadImages` (the role-hashed digest
  of the workload's attested image set) — prefer it when the image set is
  known.
- Never `workloadId: "*"` — it matches any attested caller in either mode.
- Field-scope the allow with `#passphrase` so the rest of the KV item is
  never released.

## Least-privilege operator token

`c8s luks` never needs to *read* a passphrase. Scope its token:

```hcl
path "secret/data/*/luks-*"     { capabilities = ["create", "update"] }
path "secret/metadata/*/luks-*" { capabilities = ["read", "delete", "list"] }
```

The `delete` on metadata is required by both `destroy` and `create`'s
rollback. With this policy a leaked CLI token cannot read back any
passphrase; it can still create and crypto-shred, so protect it like an
operator key.

## Token handling

- Prefer `--openbao-token-file` (mode 0600). `--openbao-token` lands in shell
  history **and** `/proc/<pid>/cmdline`, readable by any local user.
- `--openbao-addr` must be https; `--openbao-ca-cert` pins the internal CA.
  `--allow-insecure-store` sends the token and passphrases in cleartext —
  dev/test only, and it is loud about it.
