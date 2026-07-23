# kata-guest-base

The Confidential kata guest image — the SEV-SNP-measured guest every c8s
`kata-qemu-snp` pod boots into. `ratls-mesh` and `attestation-service`
are baked into the dm-verity rootfs, so they are part of the guest's
launch measurement; every workload, including CDS, runs inside a VM
that already has a working mesh + attester before the workload's
container is started.

The recipe and the authoritative description of **what the image is and
how it's built** live next to the source at
[`kata-guest-base/README.md`](../kata-guest-base/README.md): the
osbuilder dm-verity rootfs, the confos-built `vmlinuz`, the
`kernel_verity_params`, the full "what's baked in" table, and the
build/consume steps. This document is the **design rationale** above the
recipe — why the image lives in this repo, how it boots, how a pod
reaches end-to-end attestation, and how in-guest image-policy
enforcement ([`kata-image-policy.md`](kata-image-policy.md)) hangs off
it.

> **Boot model in one line.** kata-qemu does measured *direct-kernel
> boot* (a bare `vmlinuz` + a dm-verity ext4 rootfs whose root hash
> rides in the kernel cmdline) — no IGVM or UKI on kata's path. The
> mechanics (`kernel_verity_params`, SNP `kernel-hashes`, 1 vCPU for a
> stable digest) are in
> [`kata-guest-base/README.md`](../kata-guest-base/README.md).

## Why it lives here

Two of the three binaries baked into the image come from this repo
(`ratls-mesh` from `cmd/ratls-mesh/`, plus the in-guest `C8S_*` cloud-init
config — **Status:** today a single fixed default baked into the rootfs
(`C8S_WORKLOAD_ID=c8s-broker`), not per-pod host-injected; per-pod injection
was never built). The third — the in-guest attester staged
under the `attestation-service` role name — is the `attestation-api`
binary from the sibling
[confidential-dot-ai/attestation-rs](https://github.com/confidential-dot-ai/attestation-rs)
repo (the former standalone attestation-service was folded into it),
built static-musl and fetched at build time. Co-locating the recipe
with the Go source it depends on lets a c8s PR that changes
`ratls-mesh in-guest` also update the rootfs in the same commit, with
one CI run validating both halves.

The `base-images` repo continues to own the **node** images
(`rke2`, `rke2-kata`); only the kata **guest** image lives here.

## Boot order inside the guest

```
network.target ─┐
                ├─→ attestation-service.service ─┐
cloud-init.service ─→ c8s-cloudinit-env.service ─┤
                                                 ├─→ ratls-mesh.service ──┐
                                                 │   (ExecStartPost:      │
                                                 │    ratls-mesh          ├─→ c8s-ready.target
                                                 │    readiness-check)    │   (Requires=+After=
                                                 │                        │    both services)
local-fs.target ─→ policy-monitor.service ───────┘
                   (Requires=/Wants= nothing else itself; enforces from
                    t=0 on the baked seed. c8s-ready.target gates on it.)

                                  (parallel) kata-agent.service
                                             reads /etc/kata-opa/default-policy.rego
                                             — a baked file in the dm-verity root.
                                             After= network-online.target only.
```

The dependency surface is intentionally minimal. kata-agent's bootstrap
policy is part of the dm-verity root (covered by the launch
measurement), not a runtime artifact, so kata-agent doesn't wait for any
other in-guest service to render anything before it can load and enforce
it. `policy-monitor` pulls in nothing itself (it `Requires=`/`Wants=` no
other in-guest service), but it is **not** ungated: `c8s-ready.target`
`Requires=`+`After=` it, so readiness — and therefore workload-container
creation — waits for the monitor to be up and to have run its startup
seed pass. It enforces from t=0 on the baked seed with no network, so
gating on it adds no CDS bootstrap cycle. It observes what
kata-agent does (via inotify on `/run/kata-containers/`) and reacts. See
[`kata-image-policy.md`](kata-image-policy.md) for the enforcement
mechanics.

### Readiness semantics and the CDS bootstrap

`ratls-mesh readiness-check` returns 0 once the proxy's accept loops
are bound and the cert manager has minted *any* leaf — the bootstrap
self-signed one suffices. The background upgrade to a CDS-issued leaf
does NOT gate readiness.

This is deliberate. The CDS pod's workload is a single CDS container
that kata-agent starts *after* `c8s-ready.target` is reached — and
`c8s-ready.target` won't reach unless `ratls-mesh.service` is active.
If readiness required a CDS-issued leaf, ratls-mesh would wait for
CDS, kata-agent would wait for ratls-mesh, and CDS would wait for
kata-agent to start it. Deadlock. The weak readiness gate breaks the
cycle: ratls-mesh comes up self-signed so `c8s-ready.target` can be
reached, kata-agent then starts the CDS container, and CDS — being its
own in-process CA — issues its own leaf via the in-process
attest → verify → mint chain (verifying SNP evidence against the
in-guest attestation-service at `127.0.0.1:8400`, then signing in the
same process). The upgrade goroutine swaps ratls-mesh's provider over
to that CDS-issued leaf in the background.

CDS is a singleton whose in-memory mesh CA key does not survive a restart
without handoff; `cds.handoff.enabled=true` preserves CA continuity across
replacement. See [CDS is a singleton until handoff is enabled](operator.md#operational-warning-cds-is-a-singleton-until-handoff-is-enabled)
in [`operator.md`](operator.md) for the mechanism and operational detail.

Because the image-policy allowlist is fully baked into the dm-verity
root (no in-VM fetch from CDS), the older "guest-policy-agent"
bootstrap-deadlock concern is gone entirely: the current design
eliminates the dependency chain by removing the fetch rather than
splitting it via an informational-only render. See
[`kata-image-policy.md`](kata-image-policy.md).

The in-guest binary paths, systemd unit names, ports, environment
variables, and cloud-init keys that the chart and the rootfs must agree
on are the "What's baked in" table in
[`kata-guest-base/README.md`](../kata-guest-base/README.md) — keep the
chart aligned with it.

## How a pod reaches end-to-end attestation

| Layer | Measurement | Verifier |
|---|---|---|
| Kata guest image | SNP launch digest over OVMF + `vmlinuz` + the kata cmdline (which embeds the dm-verity `root_hash`), at 1 vCPU; predicted separately with `sev-snp-measure`. `manifest.json` contains the artifact hashes and prediction inputs, not the launch digest. | The operator supplies the predicted digest to the relevant measurement allowlists. `kata.guestImage.tag` selects the artifact but is not a cryptographic measurement pin. |
| Container image inside the VM (CDS / workload) | OCI image digest | Operator attests post-install via the existing `confidential.ai/cw` flow. The pod webhook injects `c8s-cert`, which obtains a leaf cert from CDS — CDS verifies the container's measurement and signs in one process. |
| Workload identity (leaf cert) | RA-TLS cert with attestation evidence as a SAN extension | Peer pods in the mesh verify on the mTLS handshake. |

The first layer is what `kata-guest-base` adds. Were the guest the
stock upstream kata `kata-static` rootfs, `ratls-mesh` and
`attestation-service` would live outside the trust boundary (host
DaemonSets) and a malicious host could intercept their startup. With
this image both are inside the SNP-encrypted memory boundary from boot,
and a peer that verifies an RA-TLS handshake transitively verifies both.

The launch digest is a function of OVMF + `vmlinuz` + the
kata-generated cmdline, so it must be re-derived whenever the kata
version or guest config changes — which is why the recipe pins the kata
version in lockstep with the kata-deploy version (see *Constraints* in
[`kata-guest-base/README.md`](../kata-guest-base/README.md)).

## Everything else runs as a container

`kata-guest-base` is the only measured guest image. Every other c8s
component — CDS, tls-lb, user workloads — runs as a
normal container image that the kata-agent guest-pulls into a
kata-guest-base VM at pod start. The launch measurement is always
`kata-guest-base`'s; the workload's container-image digest is a
secondary measurement the operator attests post-install. Because
`kata-guest-base` already carries ratls-mesh + attestation-service in
the TCB, the container inherits a working in-VM mesh + attester without
needing its own measured rootfs.

If a future component ever justifies its own measured guest image (a
hypothesis, not a roadmap), the missing pieces — a values key, the
puller's multi-image loop, per-variant RuntimeClasses — can be re-added
in the same PR that introduces the new build. They're not here today
because there's nothing to point them at.

### What guest-pull is

The guest runs with `shared_fs = "none"`, so the host cannot bind-mount
the workload's unpacked rootfs into the VM. Instead the kata-agent's
confidential-data-hub (CDH) pulls the OCI image **inside** the guest,
over the guest's own network, and unpacks it there. The host therefore
never sees the unpacked workload rootfs — only the encrypted VM memory
that holds it. One consequence: the host's CRI still does its own
image-exists pull (the kata-runtime reports the image present), so
registry credentials are needed host-side too, not just in the guest.
This is the mechanism every reference to "guest-pull" in these docs
points back to; the host-visibility limits during the transport are
covered in [G3](kata-image-policy.md#g3--image-content-is-visible-to-the-host-during-the-guest-pull).

The c8s images are public, so the in-guest pull is anonymous and needs no
credential of its own.

## In-guest image-policy enforcement

How c8s stops an arbitrary container image from running inside a
`kata-qemu-snp` VM — the `policy-monitor` daemon, the baked
`bootstrap-allowlist.json`, the kata-agent OPA policy, the threat
scenarios, and the known gaps — is its own document:
[`kata-image-policy.md`](kata-image-policy.md). It builds directly on
the boot order and the dm-verity measurement described above.

## Per-workload RTMR[3] measurement (TDX)

`rtmr3-measurer` (`internal/cmds/rtmr3measurer`, unit
`rtmr3-measurer.service`) is the in-VM workload measurer on
`kata-qemu-tdx`: it scans kata-agent's container bundles under
`/run/kata-containers` and extends TDX RTMR[3] with each deployed
workload's image digest, so the guest's attestation quote binds *which*
container ran — dynamically, for any image, with no baked allowlist. It
is the measurement-only counterpart to `policy-monitor` (allowlist
enforcement); the two are independent and either or both may run.
Requires a guest kernel exposing the TDX RTMR-extend sysfs
(`/sys/devices/virtual/misc/tdx_guest/measurements/`, mainline ≥ 6.16).

**Convention.** Pinned by [`pkg/rtmr3`](../pkg/rtmr3/rtmr3.go), the
single source of truth for both sides:
`event = SHA384("sha256:"+hex)`, `RTMR3' = SHA384(RTMR3 ‖ event)`,
folded from the boot value (all zeros). Golden vectors in
`pkg/rtmr3/rtmr3_test.go` freeze it; a client-side verifier is a
tracked follow-up and MUST build on `pkg/rtmr3`, never re-derive the
convention.

**Dedup and restart safety.** RTMR[3] is hardware-append-only, so each
DISTINCT image must extend exactly once: restarts and replicas (same
image, new container id) are collapsed, else the register matches no
golden value and the pod is unverifiable. The dedup log lives at
`/run/c8s/rtmr3-measured` — tmpfs, so it survives a daemon restart
(`Restart=always`) but is wiped with the VM, exactly RTMR[3]'s
lifetime. The daemon records a digest to the log *before* extending: a
crash between the two can only under-extend, which startup repairs by
reading the register back and comparing it against the log's fold
(never the reverse — an extra extend is unrecoverable).

**Scan, not inotify.** kata-agent sets up `/run/kata-containers` as its
own mount after the daemon starts at boot; an inotify watch added early
binds the pre-mount inode and never sees the `<cid>` dirs created on
the mounted fs. A 1 s poll is immune to that (and to dropped events).

**Ordering caveat.** In the common one-workload-per-sandbox case
RTMR[3] is a single deterministic extend. A pod with multiple distinct
workload images extends them in first-seen (scan) order, which is not
guaranteed stable across runs; a verifier for such pods must account
for ordering, or the deployment should keep one workload image per
sandbox.

## Encrypted scratch disk for large images

Guest-pull unpacks workload images to a RAM tmpfs, which caps image
size at guest memory. When the VM is launched with an ephemeral disk
tagged `serial=confai-scratch` (see
`kata-guest-base/scripts/kata-qemu-scratch-wrapper.sh`),
`scratch-setup.service` backs the image store
(`/run/kata-containers/image`) with dm-crypt on that disk instead:
random per-boot key generated in-guest, piped straight into
`cryptsetup` (never written anywhere), held only in TDX-encrypted guest
RAM — the host never sees plaintext and never holds a key. The volume
is reformatted every boot (pure scratch). No scratch disk → no-op, the
tmpfs default stands.

Integrity status and the qemu wrapper's shim nature remain known gaps.

## Reproducible root_hash

Two builds from the same inputs produce a bit-for-bit identical
dm-verity `root_hash` — the property that lets a verifier rebuild the
image from source and recompute the launch measurement instead of
taking the build on trust. `build.sh` pins every source of per-build
randomness:

- `SOURCE_DATE_EPOCH` — mke2fs derives a deterministic FS UUID,
  dir-hash-seed and created-time from it (e2fsprogs ≥ 1.45.7); every
  rootfs file's mtime is stamped to it before sealing (`cp -a`
  preserves those into the ext4 inodes).
- `VERITY_SALT` — veritysetup would otherwise pick a random salt,
  changing `root_hash` even for byte-identical content. Public value
  (it rides in the measured cmdline), fixed, not secret.
- `FIXED_FS_UUID` / `FIXED_HASH_SEED` — mkfs.ext4 randomises both
  regardless of `SOURCE_DATE_EPOCH` (which only pins timestamps), and
  tune2fs can only reset the UUID, not the hash-seed; both live in the
  superblock that dm-verity hashes, so they are injected at mkfs time.
- `UBUNTU_REPO_URL` — pins the apt archive; empty means osbuilder's
  default `archive.ubuntu.com`, which drifts over time. Set it to
  `https://snapshot.ubuntu.com/ubuntu/<YYYYMMDDTHHMMSSZ>` to time-pin
  the base (old snapshots also need apt `Check-Valid-Until=false` in
  osbuilder's mmdebstrap call).

Additionally, `image_builder.sh` populates the partition by mounting an
empty ext4 and `cp -a`-ing files in, which leaves block allocation,
journal and mount metadata non-deterministic (~114 MB of the image
differed build-to-build). `seal_and_assemble` re-lays the partition
offline with `mkfs.ext4 -d` (deterministic order, no mount, pinned
UUID/hash-seed, fully-initialised inode tables/journal) and then
verity-seals with the fixed salt, reusing image_builder's block
geometry.

**Toolchain caveat.** The re-lay runs `mkfs.ext4` and `veritysetup` on
the build host, so the `root_hash` is reproducible only across builds
using the same e2fsprogs and cryptsetup versions. The build records the
versions it used in `manifest.json` (`relay_toolchain`) so a verifier
knows exactly what to install; set `REPRO_E2FSPROGS_VERSION` /
`REPRO_CRYPTSETUP_VERSION` to make a version mismatch fatal (the CI
publish path should pin both). Running the re-lay inside a
version-pinned container is the tracked longer-term fix.

## Releasing and pinning

The [`kata-guest-base.yml`](../.github/workflows/kata-guest-base.yml)
workflow builds the image and pushes it to
`ghcr.io/confidential-dot-ai/kata-guest-base` (flat at the org level, matching
every other c8s artifact). It tags images as `<short-sha>` on every
commit to `main` or `feat/**` branches that touches the recipe or the
in-guest binaries. On a release tag (`v*`) the same image also gets the
release version; `latest` moves only on `main`.

Operators select the artifact tag by setting `kata.guestImage.tag` in a values
file (`c8s install --cvm-mode=pod -f values.yaml`). The
`c8s-kata-image-puller` DaemonSet picks that up and pulls accordingly —
see "How it's consumed in-cluster" in
[`kata-guest-base/README.md`](../kata-guest-base/README.md).

This is separate from measurement pinning. The build manifest records the
kernel/rootfs hashes and verity parameters needed to reproduce the launch
inputs, but it does not contain a launch digest, and the workflow currently
publishes the ORAS artifact without a cosign signature. After predicting the
digest from the exact OVMF, kernel, command line, and VM shape, operators must
supply it to `cds.measurements`, `ratlsMesh.measurements`, or client-side
`--measurements` policies as appropriate. Those policies default to empty.

Every tag has a `-debug` sibling published from the same build whose guest
policy allows the host log/exec stream RPCs (`kubectl logs`/`exec` work;
container I/O becomes host-readable). `c8s install --cvm-mode=pod --debug` selects
it via `kata.guestImage.debug=true`; its launch measurement differs from
the locked image, so locked-reference attestation rejects it. See "Debug
variant" in [`kata-guest-base/README.md`](../kata-guest-base/README.md).

## Puller DaemonSet

`internal/helmchart/c8s/templates/kata-image-puller.yaml`. Per node, the
puller does two things:

1. `oras pull ghcr.io/confidential-dot-ai/kata-guest-base:<tag>` into
   `${hostPath}/base/` (default `/var/lib/c8s/kata-images/base/`). The
   artifact contains the hardened kernel (`vmlinuz`), the dm-verity
   rootfs image (`kata-rootfs.img`), the verity-params and rootfs-type
   sidecars (`kernel_verity_params`, `rootfs_type`), and `manifest.json`.
   kata-qemu boots these via measured direct-kernel boot — there is no
   IGVM/UKI on kata's path. Pulling is bandwidth-bound, not CPU-bound;
   the puller idles after the initial pull.
2. Rewrites the qemu-snp configuration TOML to point kata-runtime at the
   pulled image+kernel and to force guest-pull. kata-deploy lays the
   file down inside `runtimes/qemu-snp/` with a symlink at the
   `share/defaults/kata-containers/` root; containerd's `ConfigPath`
   reads the `runtimes/` file, so we patch that file directly and
   re-point the parent symlink at it (patching the symlink path is a
   silent no-op — see the comment in
   `files/scripts/pull-and-configure.sh`). We snapshot the upstream
   config once at `<real>.upstream` so subsequent runs re-derive from
   the pristine base.

The pull-and-configure logic is a standalone POSIX script
(`files/scripts/pull-and-configure.sh`) pulled into the ConfigMap via
`.Files.Get` so shellcheck sees it; all of its inputs come from the
container env wired from `.Values.kata.guestImage.*` (no helm
interpolation lives inside the script). The DaemonSet is idempotent:
`oras pull` is content-addressable and re-running on a node that
already has the image at the same digest is a no-op, as is patching a
TOML that is already correct. A `checksum/config` annotation on the pod
template rolls the DaemonSet when `repository` or `tag` change — same
trick the chart uses for the attestation-service DaemonSet.

**Threat model.** The puller container runs privileged with the host
`/opt/kata` and `/var/lib/c8s/kata-images` bind-mounted. That's the same
posture as kata-deploy itself — installing a runtime onto a host is
inherently privileged. The puller image is digest-pinned (see
`values.yaml`) so a repointed tag can't become arbitrary code on every
node. The rootfs it pulls is dm-verity-sealed and its root hash rides
in the kata kernel cmdline, which kernel-hashes folds into the SNP
launch measurement — so a malicious registry payload surfaces as a
launch-digest mismatch at attestation time and clients refuse the pod.

## See also

- [`kata-guest-base/README.md`](../kata-guest-base/README.md) — the recipe: boot model, what's baked in, build, consume, measure.
- [`kata-image-policy.md`](kata-image-policy.md) — in-guest per-image enforcement (`policy-monitor`).
- [`kata.md`](kata.md) — installing and enforcing the kata runtime (`c8s install --cvm-mode=pod`).
- [`install-flows.md`](install-flows.md) — how the two install modes assemble the platform.
