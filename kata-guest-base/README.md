# kata-guest-base

The kata **guest rootfs** that every c8s `kata-qemu-snp` pod boots into,
built with kata's own **osbuilder** and sealed with dm-verity.

**Trust model**: node-as-host. The kata-deploy DaemonSet installs the
kata-containers runtime on each c8s node; kata-runtime boots this guest
for every `runtimeClassName: kata-qemu-snp*` pod. The pod *is* the
SEV-SNP confidential VM — its memory is encrypted against the host. See
[`../docs/kata-guest-base.md`](../docs/kata-guest-base.md) for the design
rationale, the attestation flow, and how it fits into `c8s install --cvm-mode=pod`.

## Boot model — why this is NOT an IGVM/UKI image

kata-qemu does measured **direct-kernel boot**. There is no IGVM and no
UKI on kata's path (verified against kata 3.30.0: its QEMU wrapper has no
`igvm-cfg` object and no `igvm` config knob; SNP boots via
`-object sev-snp-guest,...,kernel-hashes=on` over OVMF + a directly-loaded
kernel). So kata wants **three passive parts**, not a self-booting image:

| kata config key | what we supply |
|---|---|
| `kernel` | a bare `vmlinuz` (confos's hardened kernel) |
| `image` | `kata-rootfs.img` — a 2-partition image: **p1 = ext4 rootfs, p2 = dm-verity hash tree** (no superblock) |
| `kernel_verity_params` | `root_hash=…,salt=…,data_blocks=…,…` (from osbuilder) |

kata builds the dm-verity table from `kernel_verity_params` at boot,
pinning `root=/dev/dm-0` over `vda1`/`vda2` (qemu drops nvdimm for SNP).
The root hash rides in the kernel cmdline, which `kernel-hashes` folds
into the SNP launch measurement — so the rootfs is attested transitively.

confos is the wrong tool for that shape (it builds UEFI/IGVM self-booting
disks), so the **rootfs** is built by kata's osbuilder — which also
installs the version-matched **kata-agent** for us. confos is kept ONLY
for the hardened **kernel** (decoupled from the rootfs in kata).

## What's baked in

osbuilder produces the base ubuntu rootfs (systemd, `AGENT_INIT=no`) with
the kata-agent + its systemd unit + the OPA policy engine
(`AGENT_POLICY=yes`). On top of that, `scripts/build.sh` overlays the
`extra/` tree before sealing the dm-verity image:

| Path | Source | Purpose |
|---|---|---|
| `/usr/local/bin/ratls-mesh` | c8s (Go) | In-guest mesh proxy — runs as `ratls-mesh in-guest`. |
| `/usr/local/bin/policy-monitor` | c8s (Go) | In-VM container-digest enforcement — watches `/run/kata-containers/` via inotify, SIGKILLs containers whose digest isn't on the baked allowlist. |
| `/usr/local/bin/attestation-service` | attestation-rs `attestation-api` bin (Rust) | Localhost-only attester on `127.0.0.1:8400` (staged under the attestation-service role name). |
| `/etc/c8s/attestation-service.toml` | this dir | Localhost-only mode config — no API key, no TLS. |
| `/etc/c8s/bootstrap-allowlist.json` | rendered by `scripts/fetch.sh` | Image-digest allowlist `policy-monitor` reads at boot. Digests of the c8s images at `IMAGE_TAG` are substituted in. Part of the dm-verity root → covered by the launch measurement; updates require an image rebuild. |
| `/etc/kata-opa/default-policy.rego` | this dir | Overlays osbuilder's allow-all with our policy: `SetPolicyRequest` is denied (the host can't swap the policy at runtime), and so are the host-reach-in RPCs `ExecProcessRequest`/`ReadStreamRequest`/`WriteStreamRequest` (no `kubectl exec`/`logs` against a locked guest — see "Debug variant" below). The agent is built with `AGENT_POLICY=yes` so this is enforced. Per-image-digest gating is policy-monitor's job — see `docs/kata-image-policy.md`. |
| `/etc/systemd/system/attestation-service.service` | this dir | Owns `/dev/sev-guest`. |
| `/etc/systemd/system/c8s-cloudinit-env.service` | this dir | One-shot — turns cloud-init user-data into `/run/c8s/ratls-mesh.env`. |
| `/etc/systemd/system/ratls-mesh.service` | this dir | Runs the in-guest proxy with `CAP_NET_ADMIN`. |
| `/etc/systemd/system/policy-monitor.service` | this dir | Runs `policy-monitor monitor`. |
| `/etc/systemd/system/c8s-ready.target` | this dir | Synthetic target reached when the in-guest mesh is healthy. |
| `/etc/tmpfiles.d/c8s.conf` | this dir | Creates `/run/c8s/` early in boot. |
| `/usr/local/lib/c8s/cloudinit-env.sh` | this dir | Invoked by `c8s-cloudinit-env.service`. |
| `/usr/lib/systemd/system-preset/50-c8s.preset` | this dir | Records which c8s units are on; `build.sh` enables them offline. |

**kata-agent is not in this table** — osbuilder installs and enables the
version-matched `kata-agent.service`; we don't ship our own. The c8s
units layer on top via `c8s-ready.target` (`After=`/`Wants=`); kata-agent
comes up independently.

## Build

```bash
# Once per build host: Docker (osbuilder runs in containers) + the confos
# kernel-builder sandbox deps (mkosi/uv). osbuilder also needs root +
# loop devices for the verity image — this CANNOT run in a user-
# namespaced dev container.
sudo apt-get install -y docker.io && sudo systemctl enable --now docker

# Once per c8s/attestation-rs revision: build the in-guest binaries.
cd /workspace/c8s            && make build-c8s-node && make build-policy-monitor && make build-rtmr3-measurer
cd /workspace/attestation-rs && cargo build --release -p attestation-api --bin attestation-api --target x86_64-unknown-linux-musl

# Stage the binaries + the bootstrap allowlist into extra/. (The attester
# unit + config are recipe-owned, already under extra/.) IMAGE_TAG pins
# the c8s image digests baked into the allowlist (or pass
# CDS_DIGEST/GET_CERT_DIGEST directly for a local build).
cd /workspace/c8s/kata-guest-base
IMAGE_TAG=<c8s-release-tag> ./scripts/fetch.sh

# Build: confos kernel (vmlinuz) + osbuilder rootfs + overlay + dm-verity
# image. Fetches the kata source at the pinned version via gh.
./scripts/build.sh

# Output: ./output/{vmlinuz, kata-rootfs.img, manifest.json,
#                   kernel_verity_params, rootfs_type}
```

The kernel is built from confos's required + hardening baseline plus this
image's `kernel/container.config` fragment, passed as `confos kernel
--kernel-config-fragment`. confos resolves the merged `.config` and writes
it to a snapshot in its own tree (there is no `--kernel-snapshot` /
`--update-snapshot` flag). `scripts/build.sh` then copies that snapshot to
`kernel/config-x86_64.snapshot` in **this** repo: the committed, reviewable
record of the resolved guest-kernel config (confos's baseline + this
fragment, merged). It is a lockfile, not a build input — editing the
fragment or re-pinning confos (`CONFOS_REF` in the workflow) moves it, so
commit the snapshot alongside that change and review its diff. It is the
only place a change in confos's kernel base that affects our guest kernel
shows up. For kernel version bumps see
[base-images/rke2/README.md](https://github.com/confidential-dot-ai/base-images/blob/master/rke2/README.md)
"Bumping versions".

## How it's consumed in-cluster

The `c8s-kata-image-puller` DaemonSet (`internal/helmchart/c8s/templates/
kata-image-puller.yaml`) `oras pull`s the published artifact onto each
node and patches the `runtimes/qemu-snp/configuration-qemu-snp.toml` that
containerd's `ConfigPath` references:

```
kernel               = <dir>/vmlinuz
image                = <dir>/kata-rootfs.img
rootfs_type          = "ext4"
kernel_verity_params = "<from manifest>"
shared_fs            = "none"
default_vcpus        = 1
default_maxvcpus     = 1          # pin VMSA count -> stable launch digest
experimental_force_guest_pull = true   # workload OCI images pulled in-guest
```

`shared_fs="none"` + guest-pull is for the **workload** container's rootfs
(pulled inside the guest over virtio-net); the guest OS rootfs is the
dm-verity `image=` above.

## Measurement / attestation

Because kata uses kernel-hashes, the SNP launch digest is a function of
OVMF + `vmlinuz` + the kata-generated cmdline (which embeds the verity
`root_hash`) at a fixed vCPU count. It's predicted with `sev-snp-measure`
from a captured cmdline; `c8s install` pins the kata version + config, and
we pin `default_vcpus`/`default_maxvcpus` to 1 so the digest is stable
across pods. See [`../docs/kata-guest-base.md`](../docs/kata-guest-base.md)
for the full attestation chain; the kata version pin (below) is what
keeps the predicted digest valid across a kata bump.

## Debug variant

Every build also seals a **`-debug` image** from the same rootfs
(`scripts/build.sh` Step 5/5, output in `output-debug/`, published in
lockstep at `<tag>-debug` by the workflow). One delta: the baked
kata-agent policy is regenerated with the host
`Exec`/`ReadStream`/`WriteStream` RPCs allowed, so `kubectl logs` and
`kubectl exec` work against kata-qemu-snp pods. `SetPolicyRequest` stays
denied. Container I/O is then readable by the (untrusted) host — debugging
only, never production. Because the policy is in the dm-verity root, the
debug image's launch measurement necessarily differs from the locked one:
attestation pinned to the locked reference value rejects debug guests, so
a debug image can't silently stand in for a locked one. Select it with
`c8s install --cvm-mode=pod --debug` (`kata.guestImage.debug=true`).

## Constraints

- **osbuilder needs Docker + root + loop devices.** It cannot run inside a
  user-namespaced dev container (same constraint the old confos/mkosi path
  had). CI uses an `ubuntu-latest` runner; locally use a real host.
- **No SSH server, no shell into a locked guest.** The image is driven by
  kata-runtime via vsock + cloud-init, and the locked policy denies the
  host exec/stream RPCs — `kubectl exec`/`logs` work only on the `-debug`
  image variant (above).
- **Cloud-init's user-data is host-injected** and visible to the host —
  C8S_* values are URLs and workload IDs, not secrets.
- **kata version pin.** `scripts/build.sh` (osbuilder source tag) must
  stay in lockstep with `internal/helmchart/c8s/values.yaml` (kata-deploy
  version) — host/guest agent skew breaks the ttRPC contract.
