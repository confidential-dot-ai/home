# c8s KMS Demo — attestation-gated secrets & encrypted volumes (node-as-CVM)

The operator-facing runbook for showing the c8s KMS stack — the
attestation-gated secret-broker in front of OpenBao, plus openbao-gated LUKS
volumes — working end-to-end on a real cluster. Use it three ways:

- **As a stage script.** The "On-stage flow" parts are ordered demo beats;
  each states what it proves, with talking points inline. Do the "Prep"
  section beforehand so the live portion starts at "watch me deploy a
  workload and read a secret".
- **As a guided tour** of the KMS feature set for an operator new to it —
  every annotation, CLI command, and failure mode appears in a working
  sequence, with a troubleshooting table at the end.
- **As a manual end-to-end smoke test** after changes to the broker, agent
  injection, or LUKS path — the beats double as acceptance checks
  (secret release, deny-by-default, renewal, ciphertext-at-rest,
  persistence).

Run it from a demo machine with cluster access — `kubectl`, `helm`, the
`c8s` CLI, `bao`, `crane` — against a **node-as-CVM** cluster: the nodes are
themselves confidential VMs (Azure CVM, self-managed bare-metal SNP/TDX,
GKE), pods run as ordinary processes attested via the node's quote, and
there is **no kata** — so `kubectl logs`/`exec` behave normally and every
demo output is visible live.

The narrative thread: **everything below the node CVM is the adversary** —
the hypervisor, the physical host, the cloud operator, the disks. Every beat
either delivers a secret into the TEE boundary, or shows the view from
outside it coming up empty.

---

## What gets demoed

| # | Beat | Proves |
|---|------|--------|
| 1 | Allowlist a demo image via `c8s allowlist add` | Fail-closed image policy; signed operator writes; ~30 s propagation to every node |
| 2 | Create a secret in OpenBao | Secrets live in a real KV store, not in etcd |
| 3 | Pod fetches it via annotations, zero app change | Unmodified `bao` agent auths with the pod's mesh cert; broker gates release |
| 4 | What the infrastructure sees: nothing | No k8s Secret, no ConfigMap, tmpfs-only; TEE memory opaque to the host below |
| 5 | Deny-by-default policy | Wrong workload identity → 403s in the agent log, pod held in Init |
| 6 | Live renewal | Rotate in OpenBao → file updates in the running pod |
| 7 | `c8s luks create` from the CLI | Encrypted volume provisioning, passphrase straight into OpenBao |
| 8 | Volume bound into a pod, read/write | Passphrase released only through the broker; app sees plain files |
| 9 | Host disk sees only ciphertext + persistence | LUKS at rest; data survives pod deletion |
| 10 | Lifecycle: `list` / `show` / `destroy`, allowlist `remove` | Operator UX; `show` never discloses the passphrase |

## Prerequisites

- A CVM-capable cluster. This runbook assumes **Azure CVM** (`--cvm-mode
  aks`, vTPM attestation via `/dev/tpm0`). For self-managed bare-metal
  SNP/TDX use `--cvm-mode node --hardware-platform sev-snp` (or `tdx`),
  and for GKE confidential VMs use `--cvm-mode gke` — every other step is
  identical.
- `kubectl`, `helm`, the `c8s` binary (this branch), the `bao` CLI, and
  `crane` on the demo machine; root on one node for the LUKS `local`
  driver.
- Outbound HTTPS from the demo machine to `kdsintf.amd.com` (bare-metal /
  gke / node paths only — `c8s cds verify` fetches AMD VCEK collateral
  in-process; the `aks` vTPM path doesn't need it).
- Demo workload runs in the `default` namespace with workload id `api`.

---

## Prep (once, before the demo)

Everything in this section is one-time setup so the on-stage flow can start
at "watch me deploy a workload and read a secret". If the cluster is already
installed differently, uninstall (`c8s uninstall`) and follow this from
scratch — collapsing the whole install into one shot is the point.

### P.1 Operator credentials

Signed allowlist writes are the whole point of Part 1, so mint the key now:

```sh
openssl ecparam -name prime256v1 -genkey -noout -out operator.key
openssl ec -in operator.key -pubout -out operator.pub
```

Keep both. `operator.pub` gets pinned on CDS at install time (P.4);
`operator.key` stays on the demo machine and signs writes at runtime.

### P.2 Broker credential Secret

Nothing to do — `--kms` (P.5) renders the dev store's root-token Secret
(`c8s-openbao-dev-cred`) and wires it to the broker. Worth calling out on
stage anyway: it is the only k8s Secret in this whole demo, and it holds the
*store token*, never a workload secret.

### P.3 Values file

One file, both concerns (tls-lb port + broker config). `c8s install` has no
`--set` passthrough — all chart overrides go through `-f`:

```yaml
# kms-demo-values.yaml
tlsLb:
  hostPort:
    # tls-lb's default binds :443 on the node; pick a free port when
    # something else already owns it (RKE2's rke2-ingress-nginx is the
    # common culprit — the tls-lb pod otherwise stays Pending, "didn't have
    # free ports"). Alternative: hostPort.enabled: false, and reach tls-lb
    # through its Service instead.
    https: 8443

secretBroker:
  enabled: true
  # peerVerify=ca: the caller's mesh cert is chain-verified to the CDS mesh CA
  # and its identity is the CDS-issued SAN. This is what makes the identity
  # deny-by-default beat (Part 5) work: the SAN is present on the cert at first
  # issuance, so a workloadId rule matches immediately. Do NOT use `ratls` with a
  # workloadId rule — an RA-TLS leaf is self-signed and its SAN is caller-asserted,
  # so the broker refuses to read it as identity (fix 7d3f7bc) and a workloadId
  # rule fails closed for EVERY caller, api included. (For a measurement-gated
  # ratls demo see the Measurement-pinning deep-dive; for the attested per-workload
  # digest bind see the workloadImages note below.)
  peerVerify: ca
  releasePolicy:
    rules:
      # workloadId matches the CDS-issued cert SAN, which for cw id "api" in
      # namespace "default" is c8s-api.default.svc — NOT the bare id. The SAN is
      # trustworthy here because peerVerify=ca chain-verified the leaf, and CDS
      # only issued it after attesting the node — so release is still
      # attestation-rooted, just gated on identity rather than a live measurement.
      - workloadId: c8s-api.default.svc
        allow: ["secret/data/api/*"]
  # No openbao: block — `--kms` (P.5) deploys the in-chart dev store and
  # defaults the broker to it (in-release address, unattested, dev-cred
  # token). Production replaces --kms with an explicit openbao: block
  # pointing at an external, eventually attested, store.
```

### P.4 Pin component digests (bypasses `--image-tag` uniformity)

`--image-tag kms-test` fans out to **every** entry in the chart's
`c8sComponents` list, including `attestationApi.image` — but the branch's
`kms-test-images.yml` workflow only publishes the c8s-repo images
(c8s-operator, cds, ratls-mesh, nri-image-policy). Attestation-api lives
in a separate repo, so `crane digest attestation-api:kms-test` fails with
`MANIFEST_UNKNOWN` and the whole install aborts before helm runs.

The clean fix is a one-line retag of `attestation-api:main` at `:kms-test`
(same bytes, new tag), but that needs push access to
`ghcr.io/confidential-dot-ai/attestation-api`. If you don't have a write
token handy, the workaround is `--resolve-digests=false` plus a values
file that pins each c8s component to its actual digest — attestation-api
at `:main`, everything else at `:kms-test`. The chart's image helper
prefers `.digest` over `.tag`, so the CLI's inert `.tag=kms-test` sets
don't matter.

Digests resolved from GHCR at time of writing — paste directly:

```yaml
# kms-demo-digests.yaml
# c8s components — branch build at :kms-test
image:                # c8s-operator
  digest: sha256:a45907c17f28ab2b4292c7cbcdfdc617dd0904fddf3e0db155291583742a31bd
cds:
  image:
    digest: sha256:85cfa8a659c6ef6eead03aa087cfea7ab4cf6bb4ab43867344812771e5a4b805
ratlsMesh:
  image:
    digest: sha256:1c7c4678e96f6968c1eb905dae5b35a833022862ec6750cda88675df60692246
nriImagePolicy:
  image:
    digest: sha256:d8ea0afb714802c1b91783bf0577c2498da8269680c40469032b9dc12dd0af1b
  bootstrapAllowlist:
    # --resolve-digests=false disables the derivation flag the CLI would
    # otherwise set; turn it back on so every pinned digest above (and
    # secretAgent.image.digest from the chart default) lands in the
    # CDS-served allowlist. Without this, fail-closed image policy would
    # reject every c8s pod.
    deriveComponents: true
# attestation-api is versioned separately from c8s — pinned at :main
attestationApi:
  image:
    digest: sha256:1e07209cecc0b6b0b19da146ea45f7d1f4f7675497594eb3759724a6c32e3209
```

If any of these have moved since the doc was written, re-resolve with
`crane digest ghcr.io/confidential-dot-ai/<image>:<tag>` (public reads
need no token) or with a raw curl:

```sh
IMG=c8s-operator; TAG=kms-test
TOKEN=$(curl -fsSL "https://ghcr.io/token?scope=repository:confidential-dot-ai/${IMG}:pull" | sed -E 's/.*"token":"([^"]+)".*/\1/')
curl -fsSL -o /dev/null -D - -H "Authorization: Bearer $TOKEN" \
  -H "Accept: application/vnd.oci.image.index.v1+json,application/vnd.docker.distribution.manifest.list.v2+json,application/vnd.oci.image.manifest.v1+json,application/vnd.docker.distribution.manifest.v2+json" \
  "https://ghcr.io/v2/confidential-dot-ai/${IMG}/manifests/${TAG}" \
  | awk -F': ' 'tolower($1)=="docker-content-digest"{gsub(/\r/,"",$2); print $2}'
```

Longer term this should be fixed on the branch by marking
`attestationApi.image` as `externalImage: true` in `c8sComponents` (same
treatment `secretAgent.image` already has) — the CLI would then skip it
for `--image-tag` rewriting and digest resolution, the chart's default
digest would stand, and `--resolve-digests=true` would keep working
end-to-end. Not blocking for the demo.

### P.5 Install

One shot — this is the install the whole demo runs against. Note the `c8s
install` subcommand: those flags are all install-specific; dropping the
subcommand gets a puzzling `unknown command "operator.pub" for "c8s"`
(cobra parses the flag, leaves its value as a positional, and tries to
route that to a subcommand).

```sh
c8s install --cvm-mode aks \
  --resolve-digests=false \
  --operator-keys operator.pub \
  --image-tag kms-test \
  --kms \
  -f kms-demo-values.yaml \
  -f kms-demo-digests.yaml
```

For bare-metal / GKE / self-managed CVM, swap the mode:
`--cvm-mode node --hardware-platform sev-snp` (or `tdx`), or
`--cvm-mode gke`. `--hardware-platform` is ignored under `aks` (Azure
attests through the vTPM regardless of CPU) and combining
`--cvm-mode aks --hardware-platform tdx` is refused.

`--image-tag kms-test` is still passed but is *inert* — with
`--resolve-digests=false` the CLI would emit `--set-string
<component>.image.tag=kms-test` for every non-external component, but the
digests you pinned in `kms-demo-digests.yaml` win at the chart's image
helper (digest > tag). Leaving `--image-tag` set makes the intent
obvious in shell history and keeps the fallback string informative if
something goes wrong.

Flag call-outs:

- **`--image-tag kms-test`** — the branch publishes every c8s component
  image at `:kms-test` via `.github/workflows/kms-test-images.yml`. Without
  it the install pulls the released tag, which lacks the operator flags
  (`--secret-agent-image`, `--luks-open-image`) and the `secret-broker`
  subcommand — the operator pod would fail with `unknown flag:
  --secret-agent-image` and the broker container with `unknown command
  "secret-broker" for "c8s"`. Delete this flag when the branch merges.
- **`--resolve-digests`** (default on) — pins every c8s component to its
  registry digest and enables derivation. Because `secretBroker.enabled` is
  true in the values file, the openbao agent digest (chart-pinned) also
  lands in the CDS allowlist, so the store Deployment in P.5 is admissible
  from the moment the plugin picks the entry up (~30 s poll).
- **`--operator-keys operator.pub`** — pins your key on CDS. Skipping this
  leaves allowlist writes disabled cluster-wide, which breaks Part 1.
- **`--kms`** — renders the dev-mode OpenBao in-chart (Deployment + Service
  `c8s-openbao` + root-token Secret) and points the broker at it; `c8s
  uninstall` tears it down with the release. Dev/demo only — the store is
  in-memory and its root token sits in a plain Secret. NOTE: if a previous
  run hand-applied a `c8s-openbao` Deployment/Service (the old P.6), delete
  those first — helm refuses to adopt resources it does not own.

`kata.enabled=false` is the default (this is the node-as-CVM shape), and
`attestationApi`/`ratlsMesh`/`nriImagePolicy` all default to enabled with
image policy fail-closed.

### P.6 Deploy the backing OpenBao (dev-mode, in-cluster)

Nothing to do — `--kms` deployed it as part of the release (Deployment +
Service `c8s-openbao`, image digest-pinned to `secretAgent.image` so the
derived allowlist already covers it). Never `kubectl apply` a same-named
Service over a chart-managed one: client-side apply *merges* selectors and
the result silently matches no pods.

### P.7 Verify

The broker may `CrashLoopBackOff` briefly (started before the dev store was
reachable); it recovers within a poll. Wait for `Running 2/2`:

```sh
kubectl -n c8s-system wait --for=condition=Ready pod \
  -l app.kubernetes.io/component=secret-broker --timeout=3m
kubectl -n c8s-system get pods
```

The broker's own init chain (`c8s-cert` → `c8s-cert-wait`) is the same mesh
bootstrap workloads get — mention this in passing when you walk the workload
init chain in Part 3.

---

## On-stage flow starts here

### Part 0 — Port-forwards (keep both running)

CDS has no public ingress; the allowlist CLI verifies its RA-TLS attestation
through the attestation-api:

```sh
kubectl -n c8s-system port-forward svc/c8s-cds 8443:8443 &
kubectl -n c8s-system port-forward svc/c8s-attestation-api 8400:8400 &
```

### Part 1 — Allowlist a demo image

Fail-closed image policy means the NRI plugin on **every node** denies any
container whose image digest is not in the CDS-served allowlist. The install
already covers the c8s components and the openbao image (derived); the demo
workload uses `busybox`, which isn't covered. Add it live:

```sh
export C8S_OPERATOR_KEY=operator.key
ALLOWLIST="--url https://localhost:8443 --attestation-api-url http://localhost:8400"

BUSYBOX_DIGEST=$(crane digest docker.io/library/busybox:1.36)
c8s allowlist add "$BUSYBOX_DIGEST" docker.io/library/busybox@"$BUSYBOX_DIGEST" $ALLOWLIST

c8s allowlist list $ALLOWLIST | head
```

Talking points:

- Writes are signed with the operator key and **body-bound** — a captured
  token can't authorize a different payload.
- Reads are unauthenticated.
- Every node's plugin polls CDS with If-None-Match every **30 s**, so the
  new entry is enforced fleet-wide within half a minute — no DaemonSet
  restart, no node access.

> **Optional live-denial beat.** For a more visceral demo, apply the Part 3
> pod **before** the allowlist add. It's denied with `image not in
> allowlist: docker.io/library/busybox@sha256:…`; add the digest, wait a
> tick, `kubectl delete pod kms-demo && kubectl apply …` and it passes.

> From here on, reference demo images **by digest**
> (`busybox@$BUSYBOX_DIGEST`) — the allowlist keys on the sha256, and a
> floating tag can silently move off the digest you just allowed.

### Part 2 — Create a secret

Port-forward the store and write a KV v2 secret. Writes go **direct to the
store** — the broker exposes *no write surface* to workloads (say it out
loud):

```sh
kubectl -n c8s-system port-forward svc/c8s-openbao 8200:8200 &
export BAO_ADDR=http://127.0.0.1:8200 BAO_TOKEN=root

bao kv put secret/api/db password=squirrel-lasagna-42
bao kv get secret/api/db
```

> KV v2 note: the CLI path is `secret/api/db`; the API/annotation path is
> `secret/data/api/db`. The policy rule from prep grants
> `secret/data/api/*`.

### Part 3 — Fetch it inside a container (zero app change)

The app is a stock busybox that reads a file. Everything else is annotations:

```sh
kubectl apply -f - <<EOF
apiVersion: v1
kind: Pod
metadata:
  name: kms-demo
  annotations:
    confidential.ai/cw: api
    confidential.ai/secrets-inject: "true"
    confidential.ai/secret-db: secret/data/api/db#password
spec:
  containers:
    - name: app
      image: busybox@${BUSYBOX_DIGEST}
      command: ["sh", "-c", "echo -n 'db password is: '; cat /vault/secrets/db; echo; sleep 86400"]
EOF
kubectl get pod kms-demo -w
```

While it starts, walk the injected init chain:

```sh
kubectl get pod kms-demo -o jsonpath='{range .spec.initContainers[*]}{.name}{"\n"}{end}'
```

```
c8s-cert               ← native sidecar: attests via the node's TEE quote, gets the mesh cert from CDS
c8s-cert-wait          ← gate: workload blocked until the attested cert exists
c8s-secrets-config     ← agent config rendered in-image (never a ConfigMap)
c8s-secrets-agent-init ← UNMODIFIED bao agent: cert-auth to broker, template, exit
```

The agent authenticates with the pod's mesh cert; the broker chain-verifies
that cert to the CDS mesh CA and reads its SAN — `c8s-api.default.svc`, which
matches the policy rule — then brokers the KV read. The cert is
attestation-rooted (CDS issued it only after attesting the node), so releasing
on its identity is still gated on attestation. The secret lands in an
**in-memory tmpfs** at `/vault/secrets/db`. Then, live:

```sh
kubectl logs kms-demo
#   db password is: squirrel-lasagna-42
```

### Part 4 — What the infrastructure sees: nothing

```sh
# No k8s Secret was created for the workload — the demo namespace is empty,
# and c8s-system holds only the dev store's own token + helm internals:
kubectl get secrets -n default
kubectl -n c8s-system get secrets

# Nothing in etcd-backed objects carries the value or the agent config:
kubectl get pod kms-demo -o yaml | grep -c squirrel     # → 0
kubectl get configmaps -A | grep -c secrets             # → no agent config CM
```

The secret exists in TEE-protected memory (tmpfs in the node CVM) and
nowhere else: not in etcd, not on any disk, not in the pod spec. In this
shape the *cluster admin* (kubectl) is inside the trust boundary — the
excluded party is everything **below** the node CVM: hypervisor, physical
host, cloud operator, storage.

> Kata comparison worth one sentence: on the per-pod-CVM shape even
> `kubectl logs`/`exec` come back empty/denied — the trust boundary tightens
> to the single pod, excluding the k8s admin too.

### Part 5 — Deny-by-default (the negative demo)

Same pod, wrong identity — `intruder` has no policy rule, and in this shape
you can watch it being refused live:

```sh
kubectl apply -f - <<EOF
apiVersion: v1
kind: Pod
metadata:
  name: kms-intruder
  annotations:
    confidential.ai/cw: intruder
    confidential.ai/secrets-inject: "true"
    confidential.ai/secret-db: secret/data/api/db#password
spec:
  containers:
    - name: app
      image: busybox@${BUSYBOX_DIGEST}
      command: ["sh", "-c", "cat /vault/secrets/db"]
EOF
sleep 20
kubectl get pod kms-intruder                          # → stuck in Init
kubectl logs kms-intruder -c c8s-secrets-agent-init   # → 403 permission denied, retrying
```

Note what *passed*: the intruder pod runs on the same attested node (same
measurement as `kms-demo`) and holds a valid CDS-issued mesh cert — its SAN is
just `c8s-intruder.default.svc`, which no rule grants. Identity-scoped policy is
what stops it, and under `peerVerify=ca` the SAN is CA-verified so the broker
trusts it as identity. Fail-closed: an app that would come up without its
secrets doesn't come up at all. Clean up: `kubectl delete pod kms-intruder --force`.

### Part 6 — Live renewal

Add `confidential.ai/secrets-renew: "true"` to the Part 3 pod
(delete/re-apply) — this injects a fifth entry, a long-lived
`c8s-secrets-agent` sidecar. Then rotate:

```sh
bao kv put secret/api/db password=rotated-hedgehog-7
```

Within the agent's static-secret re-render interval (~5 min by default) the
file updates in place — no restart, no redeploy:

```sh
kubectl exec kms-demo -c app -- cat /vault/secrets/db   # exec works in this shape
```

Stage-manage the wait: rotate now, show the result after Part 8.

### Part 7 — Encrypt a volume from the CLI

On the node that will host the pod (`local` driver = loop-file on that host;
root needed). Keep it small so the ciphertext checks stay snappy:

```sh
export BAO_ADDR=http://127.0.0.1:8200   # still port-forwarded from Part 2
sudo -E c8s luks create \
  --workload api --name data --size 1Gi --mount /data \
  --openbao-addr $BAO_ADDR --openbao-token root
```

What just happened (one command — narrate it):

1. generated a 32-byte passphrase,
2. wrote it to `secret/data/api/luks-data` `{passphrase: …}` — **into OpenBao,
   never a file, never a k8s Secret**,
3. created `/var/lib/c8s/luks/api-data.img`, attached a loop device,
   `luksFormat` + `mkfs.ext4`, closed it again,
4. printed exactly what to paste into the PodSpec:

```yaml
annotations:
  confidential.ai/luks-data: dev=/dev/loopN,mount=/data,secret=secret/data/api/luks-data#passphrase,fstype=ext4,mode=open
  confidential.ai/secret-data: secret/data/api/luks-data#passphrase
volume:
  name: c8s-luks-data
  hostPath: { path: /dev/loopN, type: BlockDevice }
```

Inspect without disclosure:

```sh
c8s luks list --workload api --openbao-addr $BAO_ADDR --openbao-token root
c8s luks show --workload api --name data --openbao-addr $BAO_ADDR --openbao-token root
# → KV metadata (created, versions); NO passphrase output, by design
```

The policy rule from prep (`secret/data/api/*`) already covers the
passphrase path.

> Variant worth one sentence: `--defer-format` skips local format entirely
> (`mode=format-if-empty`) — the pod formats on first boot, so the passphrase
> is only ever *used* by the workload that owns the volume.

> No node access? `--driver pvc` runs the whole thing over kubectl: it
> provisions a raw-block PVC (needs a `volumeMode: Block`-capable
> StorageClass), always emits `mode=format-if-empty`, and the webhook attaches
> the claim to the pod — no volume snippet, no nodeSelector, works multi-node.
> Parts 8–9's node-side ciphertext checks then need the CSI volume's actual
> device path instead of `/dev/loopN`.

### Part 8 — Bind it into a container and use it

Merge the emitted output into a pod pinned to the provisioning node. The LUKS
annotations *require* `secrets-inject` — the passphrase rides the exact same
broker path as Part 3:

```sh
kubectl apply -f - <<EOF
apiVersion: v1
kind: Pod
metadata:
  name: kms-luks-demo
  annotations:
    confidential.ai/cw: api
    confidential.ai/secrets-inject: "true"
    confidential.ai/secret-data: secret/data/api/luks-data#passphrase
    confidential.ai/luks-data: dev=/dev/loopN,mount=/data,secret=secret/data/api/luks-data#passphrase,fstype=ext4,mode=open
spec:
  nodeSelector: { kubernetes.io/hostname: <the-node> }
  containers:
    - name: app
      image: busybox@${BUSYBOX_DIGEST}
      command: ["sh", "-c", "echo kms-proof-\$(date +%s) >> /data/proof.txt; cat /data/proof.txt; sleep 86400"]
EOF
kubectl logs kms-luks-demo   # → kms-proof-<timestamp>
```

The init chain now ends with `c8s-luks-open` — privileged, but the privilege
is scoped to the node CVM's kernel, i.e. **inside** the TEE boundary (this
is exactly what the chart's `luks_plain_baremetal` guard enforces: no kata
and no node attestation ⇒ it refuses to arm LUKS injection at all). It
reads the templated passphrase from tmpfs, `luksOpen`s the device, mounts
the filesystem; the app finds ordinary files at `/data`.

### Part 9 — The disk sees only ciphertext; data persists

On the node:

```sh
sudo blkid /dev/loopN                       # → TYPE="crypto_LUKS"
sudo cryptsetup luksDump /dev/loopN | head  # → LUKS2 header, argon2id keyslot
sudo grep -a -c kms-proof /var/lib/c8s/luks/api-data.img || echo "plaintext: not found"
```

Whatever backs that file — local NVMe, a cloud block volume, a SAN — holds
LUKS ciphertext only. The passphrase lives in OpenBao and is released solely
through the attestation-gated broker; plaintext exists only in the node CVM's
memory. Then persistence — the append in Part 8's command makes this
self-demonstrating:

```sh
kubectl delete pod kms-luks-demo
# re-apply the same manifest from Part 8, then:
kubectl logs kms-luks-demo
#   kms-proof-<original timestamp>    ← survived the pod
#   kms-proof-<new timestamp>
```

### Part 10 — Cleanup

```sh
kubectl delete pod kms-luks-demo --ignore-not-found
# CAVEAT (node-CVM / kata off): deleting the pod does NOT close the LUKS
# dm-crypt mapper — it is a kernel-global device, not pod-scoped (see
# docs/pitfalls.md "LUKS local volumes leak a dm-crypt mapper..."). So the loop
# stays busy, and `luks destroy` (even with --force) unlinks the backing file
# but leaves /dev/mapper/c8s-data + /dev/loop* dangling. Close it by hand until
# the teardown fix lands:  sudo cryptsetup close c8s-data  (the loop then
# auto-detaches). The passphrase + backing file ARE removed, so the data is
# unrecoverable — the leftover is only a host-resource leak.
kubectl delete pod kms-demo --ignore-not-found
# On the provisioning node (removes the backing file and the KV entry; refuses
# while the loop is attached unless --force):
sudo -E c8s luks destroy --workload api --name data \
  --openbao-addr $BAO_ADDR --openbao-token root
sudo cryptsetup close c8s-data 2>/dev/null || true   # reap the dangling mapper (see caveat above)
bao kv delete secret/api/db

# Optional final beat — retire the busybox digest from the allowlist, live:
c8s allowlist remove "$BUSYBOX_DIGEST" $ALLOWLIST
c8s allowlist list $ALLOWLIST | head

kill %1 %2 %3   # the port-forwards
```

To fully tear down the demo cluster: `c8s uninstall`.

---

## Optional deep-dives (time permitting)

- **Measurement pinning.** The main flow gates on identity (`peerVerify: ca`);
  to *also* gate on the launch measurement, switch the broker to
  `peerVerify: ratls` and add a `measurements:` list. Read the node launch
  digest off the live cluster with `c8s cds verify https://localhost:8443`
  (verifies CDS's RA-TLS in-process, fetches the VCEK from AMD KDS, prints the
  SHA-384 digest), put it in `secretBroker.measurements`, and `helm upgrade`
  (the broker rolls itself — the pod template hashes the policy). Then boot a
  slightly-different node image and watch the broker reject it at the TLS
  handshake — the measurement pin catches "wrong code". NOTE: under `ratls` the
  `workloadId` rule stops matching (an RA-TLS SAN is caller-asserted, fix
  7d3f7bc), so pair the measurement pin with a `workloadImages` rule (next
  bullet) or accept that *any* attested TEE on that measurement is released to.
- **Attested per-workload digest bind (`workloadImages`).** The strongest,
  ratls-mode identity: pin `workloadImages: { main: ["sha256:…"] }` and the
  broker releases only to the pod whose *whole* attested image set hashes to it
  (docs/getcert-workload-binding.md). Caveat — it does **not** work through the
  secret-injection path used in Part 3: the injected agent-init gates the app,
  but the workload digest only binds at the *next* cert renewal (first issuance
  is claim-free), so the app never starts and the digest never binds — a
  deadlock (getcert-workload-binding.md "Corner 4"). Demonstrate it instead
  against a running pod that doesn't gate on the secret: `c8s verify
  --workload-image sha256:…` against the pod's mesh leaf (passes for the right
  digest, fails for any other), or a non-gating caller that fetches from the
  broker after startup.
- **Token ↔ cert binding.** A token minted on `cert/login` is bound to the
  caller's client cert — replaying it over a connection with a different
  cert is rejected. Covered by the broker's tests; for a live showing use
  the hardware-free script (below), which has the raw certs in hand.
- **Attested store.** Flip `openbao.attested: true` and run OpenBao itself
  as a confidential workload — the broker then requires the *store's* TEE
  attestation (RA-TLS) before trusting it with reads. End-state story:
  attestation on both sides of the broker.
- **Allowlist hygiene.** `c8s allowlist export` / `diff` for GitOps'ing the
  allowlist; `upload` replaces it wholesale and refuses (without `--force`)
  a file that would drop core c8s components.
- **Vault compatibility.** Point `secretBroker.openbao.address` at a
  HashiCorp Vault and set `secretAgent.image` + `secretAgent.command: vault`
  — the broker speaks the Vault HTTP API; nothing else changes.
- **Laptop fallback.** No cluster? `scripts/secret-broker-demo.sh` (repo
  root) runs the whole broker flow (real OpenBao, real mTLS, policy
  check, brokered read) hardware-free in ~10 seconds. Good as a backup
  recording.

## Troubleshooting

| Symptom | Cause / fix |
|---|---|
| Pod denied: `image not in allowlist: …` | Fail-closed NRI policy — Part 1. Add the digest (`c8s allowlist add`), wait ≤30 s, recreate the pod. Reference images by digest so a tag can't drift off the allowed sha256. |
| `allowlist add` → authorization error | CDS doesn't pin your key: install pinned a different `--operator-keys`, or none. `c8s cds verify https://localhost:8443` shows the pinned fingerprints. |
| Pod stuck in `Init` at `c8s-secrets-agent-init` | Policy denial (deny-by-default — check `workloadId` is the SAN form `c8s-<id>.<ns>.svc`, not the bare id). If you switched to `peerVerify: ratls`, a `workloadId` rule matches NOTHING (an RA-TLS SAN is caller-asserted, fix 7d3f7bc) — every caller 403s, so use `ca` (this demo's default) for identity rules. Also: measurement mismatch (only under `ratls` with a pinned `secretBroker.measurements`), broker unreachable, or wrong KV path. `kubectl logs <pod> -c c8s-secrets-agent-init` shows which. |
| Broker pod `CrashLoopBackOff` at startup | Bad `measurements` hex (only if pinned), unreachable `openbao.address` (external store only — `--kms` wires the address itself), or missing `credentialSecret`. `kubectl logs` the broker container. A brief crashloop right after P.5 is expected (dev store still starting) and clears on its own within a poll. |
| `helm upgrade` fails: `invalid ownership metadata` on `c8s-openbao` | A previous run hand-applied the old P.6 Deployment/Service. `kubectl -n c8s-system delete deploy/c8s-openbao svc/c8s-openbao` and re-run the install — `--kms` owns those resources now. |
| `crane digest attestation-api:kms-test` fails / `MANIFEST_UNKNOWN` during install | Attestation-api is versioned separately from c8s and doesn't publish at `:kms-test`. Retag main as kms-test (P.4), or when working on the branch mark `attestationApi.image` as `externalImage: true` in `c8sComponents`. |
| Broker: `unknown command "secret-broker" for "c8s"` / Operator: `unknown flag: --secret-agent-image` | Install pulled the released component image, not the branch's. Re-run `c8s install` with `--image-tag kms-test` — the branch's `kms-test-images.yml` workflow publishes every component at that tag. |
| `unknown command "operator.pub" for "c8s"` (or similar for another flag value) | The `install` subcommand is missing from your invocation. `--cvm-mode`, `--operator-keys`, `--image-tag`, `-f` etc. are all defined on `c8s install`; without the subcommand cobra falls back to routing the flag's value as a subcommand and fails. Prepend `install`. |
| tls-lb pod `Pending` — "didn't have free ports for the requested pod ports" | `tlsLb.hostPort.enabled=true` (the default) is trying to bind the node's `:443`, already owned by something else (RKE2's rke2-ingress-nginx is the common culprit). Change `tlsLb.hostPort.https` in the values file to a free port (or set `hostPort.enabled: false` and reach tls-lb through its Service) and reinstall — `c8s install` has no `--set` passthrough. |
| Admission: `pod requests secrets injection … no --secret-agent-image` | `secretBroker.enabled` not set on the release the operator runs from. |
| Admission: `luks-<name> … require secrets-inject` | LUKS annotations demand `confidential.ai/secrets-inject: "true"` and a matching `secret-<name>` — `c8s luks create` prints both. |
| Chart render fails `kind=luks_plain_baremetal` | LUKS + broker enabled with neither kata nor host attestation-api — the privileged luks-open injection is refused outside a TEE boundary. In this demo's shape `attestationApi.enabled=true` satisfies it; don't disable it. |
| Chart render fails `kind=uncovered_component_digest` | Fail-closed image policy without derivation: install with `--resolve-digests` (enables `deriveComponents`), or add the pinned openbao agent digest to `nriImagePolicy.bootstrapAllowlist.digests`. |
| Chart render fails `kind=broker_ratls_under_kata` | Only on kata-shaped clusters — `peerVerify: ratls` is inert there (the in-guest mesh already attests callers). This node-as-CVM demo defaults to `peerVerify: ca` (identity via the CDS-issued SAN); `ratls` is the measurement-pinning variant (see the deep-dive), and node-as-CVM is where it belongs. |
| Secret file readable but renewal never lands | The Part 3 pod is one-shot; renewal needs `confidential.ai/secrets-renew: "true"` (Part 6) and patience (~5 min default re-render interval). |
