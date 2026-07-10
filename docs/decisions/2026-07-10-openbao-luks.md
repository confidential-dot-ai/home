# 2026-07-10 — openbao-gated LUKS volumes for confidential workloads

Stage 5 of the openbao integration (`feat/openbao-integration`). This doc
records the design **before** implementation so the shape is agreed and the
seam with PR #295 (kata-guest confidential workload support) is explicit.

## Goal

A confidential workload can attach a **persistent, LUKS-encrypted volume**
whose passphrase is stored in openbao under an attestation-gated policy.
The passphrase is delivered to the workload pod through the same
secret-broker path Stage 4 exercises for file-templated secrets; the pod
uses it to `cryptsetup luksOpen` the volume before the application starts.

Success criterion: `kubectl apply -f <workload>` on an appropriately
annotated pod causes an encrypted block device to appear as a mounted
filesystem inside the workload container, decrypted with a key openbao only
released after policy-matching TEE attestation.

## Non-goals for Stage 5

- **Volume provisioning / device attachment.** For the first pass the block
  device is expected to already be attached to the pod (e.g. via a
  `PersistentVolumeClaim` backed by a hostPath / iSCSI / whatever the
  cluster offers). Stage 5 owns the **key delivery + open/mount** half. The
  provisioning half is Stage 6 (`c8s` CLI) — the CLI will wire a PV/PVC and
  seed the passphrase in openbao as one step.
- **Key rotation / rekey.** LUKS supports up to 8 keyslots; we install
  exactly one, per volume, at creation time. Rotation is a follow-up.
- **Sharing a volume across pods.** LUKS + a single-writer filesystem
  assumes one pod at a time. Multi-writer is out of scope.
- **Guest-side scratch disk from PR #295.** That is a distinct primitive:
  per-boot random-key, host never sees the key, wiped at reboot. Ours is
  the opposite: openbao holds the key, released after attestation, so the
  volume survives reboots. Both can coexist in the same guest — different
  disks, different threat models. See "Seam with PR #295" below.

## Design

### The annotation surface

Add one new annotation family, mirroring the Stage 4 template annotations:

    metadata:
      annotations:
        confidential.ai/cw: api                            # mesh identity (required, existing)
        confidential.ai/secrets-inject: "true"             # existing; agent injection on
        confidential.ai/luks-data: dev=/dev/vdb,mount=/data,secret=secret/data/api/luks#passphrase

`confidential.ai/luks-<name>` per volume; value is a comma-separated key=value list:

- `dev=`     — the block device to `luksOpen` (required)
- `mount=`   — the mountpoint inside the workload container (required)
- `secret=`  — the KV path (with `#field`) the LUKS passphrase lives at (required)
- `fstype=`  — filesystem inside the LUKS container (default: `ext4`)
- `mode=`    — `open` (default; expect volume to be already luksFormat'd)
                or `format-if-empty` (luksFormat with the passphrase on
                first-use if `cryptsetup isLuks` says no).

Ordering: the LUKS unlock must run **after** the secrets agent has
templated `/vault/secrets/<name>` but **before** the application container
starts. So it's a new init container that runs last.

### What the webhook injects

For a pod with N `luks-*` annotations, the webhook renders:

1. **Existing** `c8s-cert` init (mesh identity).
2. **Existing** `c8s-cert-wait` gate (blocks until the mesh cert + CA are on
   disk — a native sidecar is "started", not done, when the next init runs).
3. **Existing** `c8s-secrets-config` init (Vault Agent config render).
4. **Existing** `c8s-secrets-agent-init` one-shot Vault Agent (templates
   passphrases into `/vault/secrets/<name>` as regular files, same shape as
   Stage 4).
5. **NEW** `c8s-luks-open` init container — runs cryptsetup for every
   `luks-*` entry, mounts the decrypted filesystem into a per-volume
   emptyDir shared with the app container.

For the app container:

- Volume mount added at each `mount=` path pointing at the
  emptyDir the init container mounted the decrypted filesystem onto.

The `c8s-luks-open` container needs the cryptsetup tools and CAP_SYS_ADMIN
(for `mount(2)`) + `securityContext.privileged=true` (for `/dev/mapper/*`
and access to the raw block device). Both are already present in the
distroless-plus-cryptsetup image PR #295 pulls (`cryptsetup-bin` via
`EXTRA_PKGS`). We reuse the same image for consistency.

### Where the code lives

- `internal/webhook/luks.go` — parse `confidential.ai/luks-<name>`
  annotations, mirror `internal/webhook/secrets.go`. Return a slice of
  `luksVolume{name, dev, mount, secretPath, fstype, mode}`.
- `internal/webhook/pod_mutator.go` — call `parseLUKS`, thread through
  `injection`, render the extra init container + volume mounts.
- `cmd/c8s-luks/` OR extend `cmd/c8s` with a `luks-open` subcommand — the
  actual cryptsetup-driving binary. Argv-only, no daemon: it reads
  `/vault/secrets/<name>`, runs `cryptsetup luksOpen /dev/<x>
  c8s-<name>`, mkfs on first use if `mode=format-if-empty`, `mount` onto
  the shared emptyDir path, exits 0. Second entry runs for each volume.
- `internal/helmchart/c8s/values.yaml` — a `luks` section for the image
  reference (defaults to the openbao branch's chosen cryptsetup image).

### Openbao side

Passphrases are just KV v2 entries under `secret/data/<workload>/luks-<name>`,
one per volume. The `secretBroker.releasePolicy` rule that Stage 3 uses
(`workloadId: api, allow: [secret/data/api/*]`) already covers them.
No new openbao mount type; no wrappers.

Passphrase generation is Stage 6's CLI job — for now the operator writes
one via `bao kv put` or curl.

### Threat model

The passphrase is a plaintext string in openbao — the trust boundary is:

1. Only workloads with the correct mesh identity + measurement can retrieve
   it (broker `peerVerify`, mesh policy).
2. Once retrieved, the passphrase lives in the pod's tmpfs
   `/vault/secrets/` for the pod's lifetime. The kata guest is
   TEE-encrypted memory, so the host never sees the passphrase.
3. `cryptsetup luksOpen` derives the master key from the passphrase inside
   the kata guest, exposes `/dev/mapper/c8s-<name>` inside the guest, and
   the encrypted volume's plaintext bytes only ever exist in guest memory.
4. On pod delete: the emptyDir goes away, the mapper is removed. Only the
   still-encrypted block device survives (fine — the passphrase is in
   openbao and re-releasable next time).

Threat model **does not cover**:

- Guest memory dumps (kata-CC's job, not ours).
- The host maliciously corrupting the block device (dm-crypt has no
  integrity — same limitation PR #295 flags for the scratch disk). Fix
  with dm-integrity layered under dm-crypt; deferred.
- A workload with the right identity leaking the passphrase after
  retrieving it. Standard secrets-management gap.

### Seam with PR #295

PR #295's `scratch-setup.service` mounts a **per-boot random-keyed**
dm-crypt device (`/dev/vd?` → `/dev/mapper/kata-scratch`) at
`/var/lib/kata-containers/scratch` inside the guest. That is a
guest-owned, single-boot, single-purpose disk for large workload images
during unpack.

Stage 5's LUKS device is:

- **Separate block device** — a distinct `/dev/vd?` attached to the pod
  via k8s volume machinery, not the kata guest's scratch disk.
- **Keyed by openbao** — the passphrase persists across boots; only the
  workload's attested identity releases it.
- **Mounted at an app-configurable path** — not the kata guest's
  internal image-unpack area.

They coexist without interference. If a future workload wants both, both
scratch and openbao-LUKS disks can be attached; each has its own mapper
name (`kata-scratch` vs. `c8s-<name>`).

If PR #295 lands before Stage 5 ships, no rework: the two flows never
touch the same disk, key, or mapper name.

If Stage 6's CLI later adds per-CVM ephemeral scratch (unlikely — that's
PR #295's job), we'd revisit; not now.

## Sequencing / staging

Land in this order:

1. **Design doc merged** (this document).
2. **Annotation parsing + injection** in the webhook, with unit tests
   covering:
   - single luks-<name> with all fields
   - multiple luks-<name> (sorted deterministic)
   - malformed value (missing dev/mount/secret → refuse admit)
   - luks-<name> without secrets-inject: true → refuse admit (the
     passphrase must land in /vault/secrets first).
3. **`c8s luks-open` subcommand** — the cryptsetup-driving binary.
   Unit-test the argv/env parsing; integration-test against a loop-file on
   the host in CI.
4. **Chart wiring** — the extra init container, the emptyDir/volume mount
   plumbing, image reference.
5. **In-cluster proof of life** — apply a workload that mounts a
   pre-formatted 100 MB loop file, writes a marker, restart pod, verifies
   the marker survives.

## Deferrals

- **Rotation:** LUKS keyslot 0 only; no `cryptsetup luksAddKey` /
  `luksRemoveKey`. Deferred until Stage 6 (CLI) or later.
- **Multi-writer / RWX volumes:** out of scope.
- **dm-integrity under dm-crypt:** same gap PR #295 tracks; layer both in
  a single change.
- **Automatic passphrase generation:** Stage 6's `c8s luks create` command.
