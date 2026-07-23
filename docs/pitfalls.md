# Pitfalls

Gotchas for humans and agents working on c8s. Each cites the relevant code.

## Attestation freshness anchor: pass it unpadded, never as the 64-byte field

`internal/cmds/verify/evidence.go` (`evidence.erd`), `pkg/attestationclient/verify.go` (`verifySNPEvidence`)

The expected REPORTDATA exists in two shapes that are not interchangeable:
producers bind the **unpadded** anchor (48-byte SHA-384;
`attestclient.MakeSNPRATLSAttestFunc` truncates to 48 before asking the
attestation-api), while the SNP/TDX hardware `report_data` field is that anchor
zero-padded to 64. The hardware-report verifiers zero-pad the expected value to
the field size, but the Azure vTPM verifiers (az-snp, az-tdx) compare it **raw**
against the quote's extraData — a pre-padded 64-byte value fails with
`TPM nonce length mismatch: quote has 48 bytes, expected 64`. This broke
`c8s verify` / `c8s cds verify` against every az-snp target while
cluster-internal pinning (which shapes per platform in
`attestationclient.verifySNPEvidence`) kept working. Carry the anchor unpadded
and let each platform verifier do its own shaping; `c8s-verify-js/PROTOCOL.md`
("az-snp") is the contract.

## The bare-report KDS fetch is attestation-go's job; c8s only bounds and classifies it

`internal/cmds/verify/verify.go` (`verifyEvidence`), `internal/localverify/localverify.go` (`Verify`, `dispatch`)

`c8s verify` of a bare RA-TLS cert (SNP report, no inline VCEK) once hung for
minutes on Zen4c (Siena/Bergamo) hosts, ignoring `--timeout`: verification ran
with no context, and go-sev-guest's own KDS fetcher retried an unclassifiable
`Unknown`-product URL. The VCEK fetch — including the Zen4c→Genoa product-line
mapping — now lives in attestation-go (`snp.VerifyReportContext`; background in
its README, "AMD KDS collateral for bare SNP reports"). What c8s must uphold:
the verification context carries the `--timeout` deadline (`verifyEvidence`),
and a failed fetch (`snp.ErrCollateralUnavailable`) maps to exit 3 (collateral
unavailable), never a verification verdict (exit 2).

## get-cert injection integrity is name-based — reserve the name, don't trust it

`internal/webhook/pod_mutator.go`, `internal/helmchart/c8s/templates/cw-label-integrity-policy.yaml`

The injected mesh-cert sidecar is named `c8s-cert`, and the webhook stamps the
`confidential.ai/cw` label (workload Service membership) only when it injects.
So the identity and the sidecar are meant to be inseparable — but the name and
the `confidential.ai/c8s-injected` marker are just pod fields an author can
also set. The original idempotency check skipped injection when a container of
that name already existed and gated injection on the marker, so a pod could
pre-declare its own `c8s-cert` (or preset the marker) to keep the cw identity
while shedding the real, attestation-bound sidecar — no VAP checked sidecar
presence, only `label == annotation`.

Injection is now idempotent **by reconstruction**, not by trust:
`injectInitContainers` drops any pre-existing `c8s-cert` / `c8s-cert-wait` init
container and prepends the operator-built `c8s-cert` sidecar and `c8s-cert-wait`
gate (so a decoy is overwritten, and a reinvocation converges),
`rejectReservedCertContainer` denies either reserved name in the
regular/ephemeral lists (which the init-slot rebuild cannot reach), and the
marker no longer gates injection. The `cw-label-integrity` VAP backstops it in
the API server: a pod carrying the `confidential.ai/cw` label must declare a
`c8s-cert` init container with `restartPolicy: Always`, so the label cannot
exist without the sidecar even on paths the CREATE-only webhook misses. The VAP
check is structural (name + native-sidecar restartPolicy), matching
kata-enforcement's "pin the contract, not the digest"; the webhook owns the
exact image/args. The reinject sweep (`internal/controller/reinject_sweep.go`)
still keys on the marker, but it keys on the cw *annotation*, not the label, so
a spoofed marker there yields no Service membership.

## Allowlist operator token: the body-binding must hash the exact bytes sent

`pkg/operatorauth/operatorauth.go`, `pkg/allowlistclient/client.go`

The operator write token carries `pbh = base64url(SHA-256(request body))`, and CDS
(`internal/allowlist/handler.go` → `operatorauth.Verifier.Authorize`) re-hashes
the body it received and compares. If the client serializes the body once for
signing and again for sending, any difference (key ordering, whitespace) makes
`pbh` mismatch and the write 401s. `allowlistclient.mutate` marshals the body
**once** and hands those exact bytes to the `Authorizer` before sending them —
do not re-marshal between signing and sending. `internal/cmds/allowlist`'s
end-to-end test (`integration_test.go`) exists to catch a regression here.

## Operator key-pinning: revocation is coarse; the attested config protects only pinning verifiers

`internal/cmds/cds/run.go` (`loadOperatorKeys`), `pkg/operatorauth/operatorauth.go`, `docs/ratls.md`

Allowlist writes are authorized by **pinned operator public keys**
(`cds.operatorKeys`); `operatorauth.Verifier` accepts a token signed by any
pinned key and consults **no CRL/OCSP**. Consequences to know before relying on
it:

- **Revoking one operator means editing the pinned-key list and re-installing**
  (remove its public key from `cds.operatorKeys`). There is no per-key
  revocation short of that. Keys are long-lived; a leaked operator private key is
  usable until removed. Protect operator keys (vault/HSM/hardware token).
- **The attested config-claims digests only protect verifiers that pin them.**
  CDS binds the digests of its loaded key set and applied seed into its
  serving-cert evidence, but the CDS args are still host-supplied: a control
  plane can restart CDS with different keys or seed. That swap fails closed
  only for clients pinning the expected values (`c8s cds verify
  --operator-keys/--allowlist-seed`, pinned from the operator's own install
  inputs); a client that pins nothing accepts whatever the running CDS
  attests to, and
  in-cluster enforcers pin nothing. Verify continuously (CI), not just at
  bootstrap, and gate ingress exposure on a passing verify.
- **A rotated-out config stays claimable until cert expiry.** After changing
  operator keys or the seed, the previous serving cert (and its claims)
  remains replayable until its RA-TLS TTL (`cds.ratlsCertTTL`) runs out. A
  config change also fails handoff by design (claims must byte-match), so a
  rotation rolls a fresh CA lineage rather than inheriting the old one.

This was a deliberate stop-gap to ship `c8s allowlist` without standing up a
PKI. **Longer term** we want a CA + short-lived operator certificates (chain
carried in the JWT `x5c` header), giving delegated issuance and CA-based
revocation instead of editing a pinned-key list, plus single-file (cert+key)
operator credentials.

## Operator-key auth is app-layer on purpose (do not switch CDS to mTLS)

`internal/cmds/cds/run.go`

CDS serves RA-TLS (`ratls.NewServerTLSConfig`) and sets **no** `ClientAuth`, so
no client presents a TLS client cert. Operator writes are verified at the
handler layer, not the TLS handshake. Enabling `tls.VerifyClientCertIfGiven` /
`RequireAnyClientCert` on the CDS listener would change the handshake for every
mesh client (ratls-mesh, nri-image-policy, get-cert, policy-monitor — all
`Policy`-only RA-TLS clients today). Keep operator verification in
`operatorauth.Verifier`, off the listener.

## Kata webhook injection needs an operator image that matches the chart

`internal/webhook/pod_mutator.go` + `internal/helmchart/c8s/templates/kata.yaml`

A `--cvm-mode=pod` install renders the GPU RuntimeClass, shim, puller, and device plugin
off `kata.enabled`, but the *injection* — the platform's confidential classes
for `confidential.ai/cw` and `nvidia.com/*` pods — lives in the operator binary
(`kataRuntimeClassFor`). The chart and the operator binary ship as a unit: bump
the operator image with (or before) chart changes. The skew now fails loudly:
the chart passes `--hardware-platform` to the operator under `kata.enabled`, so
an operator image that predates it exits on the unknown flag and the Deployment
sits in CrashLoopBackOff naming the flag — if you see that after a chart-only
bump, the operator image is stale, not the chart broken. (Historic silent
shape, for archaeology: a pre-GPU operator with a GPU-era chart used to inject
`kata-qemu`/`kata-qemu-snp` for GPU pods, which then never scheduled.)

The corollary: **`--image-tag` must be a tag every c8s component publishes.**
The component images publish in lockstep (docker.yml); a tag that exists only
for some other artifact — e.g. a kata-guest-base guest-image tag like
`branch-<name>` — is not an install tag. `c8s install` fails fast on this:
digest resolution (`--resolve-digests`, the default) aborts on the first
unpublished component with guidance naming the right knob
(`kata.guestImage.tag` via `-f` for guest-image tags), and with
`--resolve-digests=false` a preflight verifies the operator image exists in
the registry (via crane, best-effort) before anything touches the cluster. Do
**not** dodge the error by falling back to `:main` for the components — a
mismatched operator is the silent mis-injection above. A real
operator↔chart capability handshake (operator reports its webhook feature
set; the render fails if the chart needs more) is future work.

## A GPU request alone forces the confidential GPU class — no annotation needed

`internal/webhook/pod_mutator.go` (`kataRuntimeClassFor`), `docs/kata-gpu.md`

On a kata cluster, any workload pod with an `nvidia.com/*` resource in any
container (init containers included) is injected with the platform's
confidential-GPU RuntimeClass — regardless of whether it carries the
`confidential.ai/cw` annotation, and overriding what the annotation alone
would pick. c8s has no non-confidential GPU runtime, so "requests a GPU"
means "runs as a confidential VM with the device passed through". Surprises
this causes: a GPU pod copied from a stock-Kubernetes manifest boots as a CVM
with the locked guest policy (empty `kubectl logs`, no exec), needs a
platform-labelled GPU node, and inherits the GPU guest-config constraints
(single vCPU on SNP, no memory limits — `docs/kata-gpu.md` "Limitations").
The two ways out are deliberate and visible: an explicit `runtimeClassName`
is honored (and validated), and host-namespace pods are exempt (they cannot
be VMs — but then a `nvidia.com/*` request gets an unusable VFIO handle, not
a working GPU).

## GPU passthrough is silently disabled if `pcie_root_port` stays 0

`internal/helmchart/c8s/files/scripts/pull-and-configure.sh` (GPU block),
`internal/helmchart/c8s/templates/validations.yaml` (`kind=gpu_pcie_root_port`)

The stock `configuration-qemu-nvidia-gpu-*.toml` ships `pcie_root_port = 0`,
which means cold-plug VFIO attaches **no** GPU — the pod boots as a confidential
VM with no device, and the failure is a missing `/dev/nvidia*` inside the guest,
not an obvious error. The GPU puller sets it to `kata.gpu.guestImage.pcieRootPort`
(default 8). Two guards keep 0 from shipping: the chart refuses to render
`pcieRootPort < 1` (`VALIDATION_ERROR kind=gpu_pcie_root_port`), and the puller
script exits non-zero (pod stays NotReady) when the env var is empty or 0. If
you ever see a GPU pod schedule and run but the workload reports no CUDA
device, check this key first — a hand-patched config can still regress it.

## The `<tag>-nvidia` guest boots kata's GPU kernel, not the confos one

`kata-guest-base/scripts/build.sh` (Step 6), `docs/kata-gpu.md`

The GPU guest image IS the c8s guest (in-guest attestation-service /
ratls-mesh / policy-monitor, locked policy, measured, c8s-published reference
manifest) — but it boots kata's GPU kernel with the NVIDIA modules grafted
from kata's own GPU rootfs, because the confos kernel has `CONFIG_MODULES=n`
and cannot load the driver. Module loading is locked down after driver
bring-up (`kernel.modules_disabled=1`), and everything grafted sits inside
the measured verity root — but the kernel/driver provenance is the kata
release, not the c8s build. Compiling signed modules against a confos GPU
kernel flavor closes this. Also remember GPU SPDM
attestation is not wired yet (`docs/kata-gpu.md` "Threat-model gaps").

## kata-qemu-snp on a non-SNP host is a QEMU crash-loop, not a clean rejection

`internal/helmchart/c8s/templates/kata.yaml`, `cmd/c8s/install.go` (`preflightSNPNodes`)

Kata's `confidential_guest = true` auto-detects the **host** TEE. On a host
with a different TEE (tested: Intel TDX with 8× B200), a `kata-qemu-snp` pod
launches a **TDX guest with the SNP-shaped config** (SNP OVMF/params), which
cannot boot: QEMU SIGABRTs (`kvm run failed Input/output error`, vCPU dead at
the reset vector; dmesg: `kvm_intel: Guest access before accepting 0x807000`)
and kubelet retries forever — an unbounded crash-loop spamming register dumps
every ~90 s, not an error surfaced on the pod. Since the chart pins
`kata-qemu-snp` on CDS and tls-lb, a `--cvm-mode=pod` install on such a
host crash-loops its own control plane.

Two guards exist; keep both intact:

1. the `kata-qemu-snp` / `kata-qemu-snp-nvidia` RuntimeClasses carry a
   `scheduling.nodeSelector` on the `confidential.ai/sev-snp=true` label
   (`kata.snpNodeSelector`), so a confidential pod on an unlabelled node stays
   `Pending` with a clear scheduling message;
2. `c8s install --cvm-mode=pod` labels every kata-targeted node from the declared
   `--hardware-platform` (`cmd/c8s/tee_label.go` — declarative, no hardware
   probe; it refuses to run while any node still carries the other
   platform's label, printing the clear command) and fails fast when no
   node qualifies (both skipped with `-f`).

Because the label is declared rather than probed, `--hardware-platform` on
the wrong hardware recreates exactly this crash-loop — on every node at once,
so it fails loudly at first pod, not intermittently. Installs that never run
the CLI — GitOps `HelmRelease` (c8s-fleet) and `c8s install -f` — get **no
auto-labelling**, so their nodes must be labelled out-of-band (provisioning,
NFD, or kubectl) or every confidential pod stays Pending. The label is a
scheduling aid, not a security boundary — attestation is.

## kata-image-puller vs kata-deploy: the guest-pull config clobber

`internal/helmchart/c8s/templates/kata-image-puller.yaml`

kata-deploy rewrites the stock `runtimes/qemu-snp/configuration-qemu-snp.toml` on
every (re)install and has **no ordering dependency** on the puller. If the puller
patched once and idled, a later kata-deploy restart silently reverts
`experimental_force_guest_pull` (and the kernel/rootfs pointers) — and the next
`kata-qemu-snp` sandbox dies with `failed to mount …/rootfs: ENOENT` (no guest
rootfs, because guest-pull is off and `shared_fs="none"` shares nothing).

The puller is therefore a **reconcile loop** (single `reconcile` container) that
re-applies the patch whenever it drifts; readiness tracks "patch present". Do not
"simplify" it back to a one-shot initContainer + `pause` — that reintroduces the
clobber. Verified: clobbering the config self-heals in ~24s.

## Guest-pull fetches workload image layers anonymously

`internal/helmchart/c8s/templates/kata.yaml` (`EXPERIMENTAL_SETUP_SNAPSHOTTER`),
`internal/helmchart/c8s/files/scripts/pull-and-configure.sh`

The confidential shims route through the nydus-snapshotter that kata-deploy
installs (`nydus-for-kata-tee`, guest-pull mode), so the host never pulls the
workload's **layers** — the kata-agent fetches them *inside* the guest, and
that pull is **anonymous** (there is no in-guest registry-auth path). A
workload image must therefore be pullable without credentials: public, or on a
registry the guest reaches anonymously. A private image — a tenant workload, or
a private mirror of the c8s components — 401s the in-guest layer fetch; the
stock c8s component images are public, so the default install is unaffected.
Note containerd's CRI still **resolves** the manifest on the host first, so an
image whose registry gates even manifest resolution also needs
`serviceAccount.imagePullSecrets` — but that host-side Secret does not
authenticate the guest's layer pull.

## cds cannot reach Ready as runc on a host that is not an SNP guest

`internal/helmchart/c8s/templates/cds.yaml`

cds's RA-TLS serving cert needs SNP evidence from `/dev/sev-guest`, which only
exists **inside** an SNP guest (the host has `/dev/sev`, not `/dev/sev-guest`).
The non-kata probes are httpGet/HTTPS. So running cds as host runc (no `--cvm-mode=pod`)
on bare metal has no clean Ready path — it is intended to run as `kata-qemu-snp`
(gated on `kata.enabled`). For a non-confidential dev box, disable cds's RA-TLS
(`cds.ratlsPlatform=""`, plaintext) and expect the HTTPS probe to fail.

## Do not flip `kata.enabled` on a live cluster

`internal/helmchart/c8s/templates/cds.yaml`

cds's `runtimeClassName`, attestation-api URL (host DaemonSet vs in-CVM
loopback `127.0.0.1:8400`), `securityContext`/`runAsUser`, and probes are all
keyed on `kata.enabled`. Toggling it on an existing release therefore silently
moves cds between a runc pod and a `kata-qemu-snp` CVM, and between host and
in-guest attestation — a disruptive, easy-to-miss change that rewrites the trust
boundary cds runs in. It is harmless on a fresh install but sharp on a running
one. Pick kata vs non-kata at install time and keep it fixed; to switch, plan it
as a deliberate migration (drain, reinstall), not a `helm upgrade --set`.

## The bootstrap allowlist binds to floating `:main` digests — operators MUST pin by digest

`kata-guest-base/scripts/fetch.sh`, `internal/helmchart/c8s/values.yaml`

The kata-guest-base build resolves `cds:main` and `get-cert:main` via
`oras manifest fetch` at build time and bakes their **digests at that moment**
into `/etc/c8s/bootstrap-allowlist.json` on the dm-verity rootfs. The allowlist
is therefore sealed into the SNP launch measurement and is, by construction,
**only as fresh as the floating `:main` tag at the moment of build**. Two
consequences worth knowing:

1. `kata-guest-base.yml` chains off `Docker` via `workflow_run` so the build
   reads a `:main` that Docker just finished pushing — this kills the
   *concurrent-read* race (Docker mid-push while fetch.sh resolves). It does
   **not** make `:main` immutable; Docker's next main push moves it.
2. If a `kata-guest-base` build fails for an unrelated reason (snapshot 5xx,
   docker+apparmor, …), `cds:main` has already advanced and `kata-guest-base:main`
   stays at the previous build. The two floating tags drift, and a deploy that
   pulls both at `:main` produces a `kata-guest-base` whose baked seed doesn't
   permit the deployed `cds`'s digest — policy-monitor SIGKILLs cds and the
   bootstrap stalls.

**Mitigation — pin by digest in `values.yaml`, not by tag.** Every c8s image
(`cds`, `get-cert`, `attestationService`, the oras puller, …) exposes an
`image.digest` field. Resolve it once at deploy time:

```sh
oras manifest fetch --descriptor ghcr.io/confidential-dot-ai/cds:<release-tag> \
  | jq -r .digest
```

and set it in your values file. With every image pinned by digest, the floating
`:main` movement is invisible to your deployment.

**Runtime mitigation that does the heavy lifting in production:** the
`policy-monitor` CDS-allowlist-refresh path
(`kata-guest-base/extra/etc/systemd/system/policy-monitor.service` + `internal/
cmds/policymonitor/cds_refresh.go`) **grows** the in-VM allowlist at runtime
from CDS's RA-TLS-pinned allowlist, so operator-pinned digests not in the baked
seed are still admitted. The seed only needs to be "good enough to boot the
first cds container," after which the in-cluster CDS extends the set. That's
why bootstrap-allowlist drift is tolerable for any deploy where the operator
pinned the chart's digests; it's only fatal for an unpinned `:main`-everywhere
deploy.

**Known gap (deferred fix):** `kata.guestImage` (the kata-guest-base oras
artifact itself) currently has only a `tag:` field, no `digest:` — the puller
pulls by tag. Pin to a specific `<short-sha>` tag rather than `latest`/`main`
until the puller learns `oras pull <ref>@<digest>`. The proper fix is **atomic
floating-tag promotion**: a third workflow that rolls `:main` and `:latest` on
all c8s artifacts only after BOTH `Docker` AND `kata-guest-base` succeed for
the same commit. Out of scope here; tracked as a follow-up.

## `kata-guest-base` puller credentials for a private mirror (`kata.guestImage.pullerAuthSecret`)

`internal/helmchart/c8s/templates/kata-image-puller.yaml`, `internal/helmchart/c8s/values.yaml`

The kata-image-puller fetches the `kata-guest-base` oras artifact by shelling
out to `oras pull` **inside the puller pod** (see `files/scripts/pull-and-configure.sh`).
This is **not** a kubelet image pull: `oras` only reads `~/.docker/config.json`
and is oblivious to Kubernetes `imagePullSecrets` — Secret references on the
puller ServiceAccount only help kubelet pull the puller's **own** image. The
stock `ghcr.io/confidential-dot-ai` artifact is public, so the anonymous
default just works; against a **private mirror**, a pull without a projected
credential 401s with:

```
Error response from registry: failed to resolve <tag>: GET …/manifests/<tag>: unauthorized
```

**Mitigation:** the chart projects a `kubernetes.io/dockerconfigjson` Secret's
`.dockerconfigjson` key to `/root/.docker/config.json` in the puller pod —
exactly where `oras` looks (the container runs as root under
`privileged: true`, so `$HOME=/root`). That Secret defaults to the
install-time `imagePullSecret`, so a plain
`c8s install --cvm-mode=pod --image-pull-secret ghcr-secret` covers the oras pull
along with every kubelet pull. Set `kata.guestImage.pullerAuthSecret` only
when the artifact needs a different credential than the c8s images:

```sh
kubectl create secret docker-registry ghcr-puller-creds \
  -n c8s-system \
  --docker-server=ghcr.io \
  --docker-username=<user-or-x-access-token> \
  --docker-password="$GITHUB_TOKEN"

helm upgrade c8s … --set kata.guestImage.pullerAuthSecret=ghcr-puller-creds
```

**This is operator-side, not TCB-relevant.** The credential never enters the
guest and is not part of the SNP launch measurement. Rotation is a Secret
update + puller DaemonSet restart — no re-attestation, no kata-guest-base
rebuild, no re-pinned digest.

## Bump `KATA_SRC_COMMIT` in lockstep with `KATA_VERSION`

`kata-guest-base/scripts/build.sh` (`KATA_SRC_COMMIT`)

The kata source (osbuilder) is fetched by **immutable commit** (`KATA_SRC_COMMIT`),
not by the `KATA_VERSION` git tag — a git tag is mutable, and a re-pointed
`3.30.0` would silently swap the osbuilder source baked into the dm-verity root
and thus the SNP launch measurement. The gotcha: `KATA_VERSION` and
`KATA_SRC_COMMIT` are two separate knobs that **must move together**. Bumping
`KATA_VERSION` alone leaves the source pinned to the old release's commit while
`stage-kata-conf.sh` pulls the new `kata-static` asset — a silent source/asset
mismatch. On a version bump, re-resolve the commit and update both:

```fish
gh api repos/kata-containers/kata-containers/git/refs/tags/<ver> --jq .object.sha
```

(The `kata-static` release asset is separately sha256-pinned in
`stage-kata-conf.sh`, so only the git-tag source fetch needed this treatment.)

## Running clusters do NOT pick up re-published kata-guest-base artifacts

`internal/helmchart/c8s/files/scripts/pull-and-configure.sh`

The puller reconcile is level-triggered on its **inputs** (a `# c8s-config:`
fingerprint embedded in the drop-in): a changed value (tag, debug, registry
auth, GPU knobs) or a deleted drop-in/artifact re-pulls and rewrites within a
tick. What it deliberately does NOT detect is a re-published artifact under
the **same** tag — the fingerprint is env-only, there is no registry-digest
poll. Pods keep booting the previously pulled guest until the tag changes or
the drop-in is deleted. During the 2026-07-07 GPU bring-up this masked three
consecutive same-tag artifact updates. Verify what a node actually runs by
hashing `/var/lib/c8s/kata-images*/base/kata-rootfs.img` against the CI run's
uploaded blob digest, not by looking at tags — and publish immutable tags.

## kata-agent replaces /run/kata-containers at sandbox creation — inotify watches die

`internal/cmds/policymonitor/monitor.go`, kata-agent `rpc.rs` (`create_sandbox`)

kata-agent's `create_sandbox` does `remove_dir_all` + `create_dir_all` on
`CONTAINER_BASE` (`/run/kata-containers`) — the whole directory is a new inode
by the time the first bundle is written, and an inotify watch installed at
guest boot is bound to the dead inode. This made policy-monitor silently
non-enforcing in the field ("active, 3 seed entries loaded", zero decisions):
the fsnotify event channel just stops delivering, no error, no exit.
policy-monitor now watches in generations (Remove/Rename of the watch dir or a
failed inode identity check re-establishes the watch and re-runs the seed
scan). Any future in-guest component that watches a path kata-agent owns must
handle the same replacement — watch liveness, not just watch existence, and
rescan after re-watching.

## policy-monitor's cgroup lookup must match the systemd-scope name, or the SIGKILL silently misses

`internal/cmds/policymonitor/kill.go` (`findCgroupDir` / `cgroupDirMatchesCID`)

policy-monitor denies a non-allowlisted container correctly, then locates its
init PID by walking `/sys/fs/cgroup` for the container's cgroup and reading
`cgroup.procs`. The lookup used to match a directory whose basename equals
`<cid>` **exactly**. But a systemd-PID-1 kata guest (our case) uses the systemd
cgroup driver, so the container's cgroup is a **scope**:
`cri-containerd-<cid>.scope` (containerd) or `crio-<cid>.scope`, nested under
`kubepods.slice/.../kubepods-*-pod<uid>.slice/`. The exact-basename match never
found it, `findInitPID` returned not-found, and the kill was a **silent no-op**
— the denied image ran fully unenforced (worse than the bounded post-start
window: unbounded). Same failure family as the inotify-watch death above:
policy-monitor *decides* correctly but the *enforcement action* silently
misses, with no error surfaced. `cgroupDirMatchesCID` now matches `<cid>`,
`<cid>.scope`, and `<prefix>-<cid>.scope`. Any change to the kill path must be
validated against a real systemd-PID-1 guest's cgroup layout (verify with
`find /sys/fs/cgroup -name '*<cid>*'` in a guest debug console), not just the
fs-driver `<cid>` shape the unit tests fabricate.

## kata guests: inbound TCP port 8443 bypasses the mesh (baked passthrough)

`kata-guest-base/extra/etc/c8s/cloudinit.env` (`C8S_MESH_INBOUND_PASSTHROUGH`),
`internal/cmds/ratlsmesh/in_guest_linux.go`

The in-guest mesh redirects all inbound TCP to the mutual-RA-TLS proxy, which
makes a guest that terminates its own TLS for external clients (tls-lb nginx
on 8443, CDS on 8443) unreachable — certless clients get `certificate
required`. The baked env therefore sets `C8S_MESH_INBOUND_PASSTHROUGH=tcp:8443`
so those front doors work. Because the env file is a single baked default for
EVERY guest, the flip side is: **a workload listening on 8443 inside a kata
pod is reachable without mesh mTLS.** Don't serve plaintext or
mesh-trust-assuming endpoints on 8443 in kata pods; rebuild the guest image
with the variable emptied for a fully-meshed posture (front doors then need
`kubectl port-forward` + a mesh client cert, i.e. are effectively internal).

## First `--cvm-mode=pod` install can exceed helm's `--wait` window

`cmd/c8s/install.go` (`buildInstallHelmArgs`)

On a node without a prior kata install, kata-deploy downloads the multi-GB kata
payload inside the helm `--wait` window. `c8s install --cvm-mode=pod` therefore waits
10 minutes (vs 5 for non-kata installs), which covers typical first installs —
but a slow registry path can still blow it: the release lands as `failed` while
the cluster converges fine underneath, and a second `c8s install` run (helm
upgrade) flips it to `deployed`. Don't start debugging from the helm status —
check the pods first.

## `c8s uninstall` sweeps the TEE node labels — relabel before reinstalling

`cmd/c8s/uninstall.go`, `cmd/c8s/tee_label.go`

The kata sweep removes `confidential.ai/sev-snp` / `confidential.ai/tdx`
along with the kata artifacts. A subsequent
`c8s install --cvm-mode=pod -f <values>` can fail fast at the TDX/SNP node check (the
auto-label path doesn't cover every `-f` shape). Relabel by hand and rerun.

## `cds.node.selector: null` in a values file does not survive helm's multi-file merge

`internal/helmchart/c8s/values.yaml` (`cds.node.selector`)

`c8s install` layers your `-f` file with a generated values file; helm's
null-override semantics across multiple `-f` files are unreliable, so
`selector: null` can silently revert to the chart default (`role: cds`) and CDS
sits `Pending` with `didn't match Pod's node affinity/selector`. Either label
the node (`kubectl label node <n> role=cds`) or set a real selector instead of
null.

## The sandbox device plugin only registers vfio devices present at startup

`internal/helmchart/c8s/templates/kata-sandbox-device-plugin.yaml`

If a GPU is bound to vfio-pci after the plugin pod started (fresh install
ordering, or a GPU claimed from the host driver later), the node keeps
advertising `0` until the plugin restarts:
`kubectl -n c8s-system rollout restart ds c8s-kata-deploy-sandbox-device-plugin`.
Check `kubectl get node -o jsonpath` allocatable before debugging anything
deeper.

The same applies after any GPU **re-enumeration** while the plugin is running
— a CC-mode toggle, BAR-resize remove/rescan, or vfio unbind/rebind (the
bare-metal `normalize-gpus.sh` does all three): the CDI spec the plugin wrote
at startup (`/var/run/cdi/nvidia.com-<MODEL>.yaml`) keeps the old
`/dev/vfio/devices/vfioN` paths and device IDs, and reset devices stay marked
unhealthy. Sandboxes then fail at cold-plug against the stale spec until the
DaemonSet is rolled. The plugin binary is NVIDIA's (no in-tree fix); roll it
after any host-side GPU reconfiguration.

## KubeVirt and the kata sandbox plugin must not both own a node's GPUs

Nothing in-tree configures KubeVirt `permittedHostDevices` today, but adding
one for GPUs in the vfio set creates a silent double-advertisement: kubelet
sees two resource names for the same 8 cards, double-counts allocatable, and
can hand one GPU to a KubeVirt VM and a kata pod at once. A kata pod
requesting the KubeVirt resource name schedules but dies at CDI
(`unresolvable CDI devices`) — the sandbox plugin only writes specs for its
own per-model names. And the c8s webhook prefix-matches `nvidia.com/*` (see
"A GPU request alone forces the confidential GPU class"), so virt-launcher
pods requesting the passthrough resource get the kata GPU class injected
unless their namespace is in `webhook.extraExcluded`. One owner per GPU node —
see `bare-metal-infra-management/docs/nvidia-gpu-operator-comparison.md`
"GPU ownership".

## Symbolic image `USER` fails at pod start under guest-pull

Under guest-pull the host never unpacks the image rootfs, so containerd's CRI
cannot resolve a symbolic Dockerfile `USER` (e.g. `USER curl_user`) against
the image's `/etc/passwd` — pod creation fails host-side before kata ever
runs. Neither kata-runtime nor kata-agent has a name-resolution fallback (the
runtime spec carries only a numeric uid). Fix: set a numeric
`securityContext.runAsUser` in the pod spec (which skips the lookup), or bake
a numeric `USER <uid>` into the image. Prefer non-root regardless — the
in-guest mesh exempts UID-0 egress.

## kubelet's `runtime-request-timeout` (default 2m) caps kata pod creation

Per-shim kata timeouts differ: the GPU shims' base toml ships
`create_container_timeout`/`dial_timeout` = 1200 s, while the stock CPU shims
ship **60 s** — which large-memory TEE guests can exceed just booting to the
agent (TDX page acceptance; observed intermittently at 128 GiB). The c8s
drop-in (`pull-and-configure.sh`) raises the CPU shims to 600 s. Either way
the **effective** ceiling is `min(kubelet runtime-request-timeout, kata
timeout)` — kubelet cancels the CRI call at 2 m, containerd tears the sandbox
down, and the pod loops in `ContainerCreating` with the cause hidden. A healthy
c8s GPU guest boots to agent in <1 min so the default rarely bites now, but any
slow path (cold registry, huge image, big-memory guest) hits the 2 m wall
first. RKE2: `kubelet-arg: runtime-request-timeout=20m` in
`/etc/rancher/rke2/config.yaml` (matches the fleet ansible default).

## Injected/chart probes on kata-guest containers must not use `exec`

`internal/webhook/pod_mutator.go` (`certContainer` / `certWaitContainer`),
`internal/helmchart/c8s/templates/_helpers.tpl` (`c8s.getCertContainers`)

The locked `kata-qemu-snp` guest denies `ExecProcessRequest`
(`kata-guest-base/extra/etc/kata-opa/default-policy.rego`, intentional — it is
what blocks `kubectl exec` into a confidential pod). kubelet cannot distinguish
an exec **probe** from a host exec, so **any `exec` probe on a container that
runs inside a locked guest never passes**, and the pod hangs in `Init`
(`Startup probe errored … ExecProcessRequest is blocked by policy`). This bit
the get-cert readiness gate: a `startupProbe: exec [/c8s probe-file tls.crt]`
on the `c8s-cert` native sidecar meant **every confidential workload pod was
stuck in Init on the locked guest** — masked for a while because the published
`kata-guest-base:main` was briefly a `c8s-debug` build (exec allowed), so it
only surfaced on the real locked guest.

Fix pattern: gate the workload with a plain **run-once init container**
(`c8s-cert-wait`, running `c8s probe-file --wait`) that blocks on the cert file
and exits 0 — running a container is `CreateContainerRequest`, which the guest
allows, and normal init-completion ordering fails closed. The `c8s-cert`
sidecar stays the long-lived first init container (it anchors
`shareProcessNamespace` under kata), just without a probe. Any future readiness
signal for a kata-guest container must be non-exec: a run-once gate container,
or `httpGet`/`tcpSocket`/`grpc` (CDS's own probes are `tcpSocket`/`httpGet` for
this reason). Never add an `exec` probe to CDS, tls-lb, or an injected
workload container.

## `kubectl logs` on locked-guest pods is empty by design

`kata-guest-base/extra/etc/kata-opa/default-policy.rego`

The locked guest policy denies `ReadStreamRequest`/`ExecProcessRequest` — the
untrusted host cannot read container stdout, so `kubectl logs` returns nothing
even for a successful pod. Judge workloads by exit code, or deploy the
`<tag>-debug` guest variant (`c8s install --debug`) when log access is needed.
Do not burn time "fixing" empty logs on the locked image.

## Guest kernel params: config-file edits may not reach the cmdline — use the pod annotation

`internal/helmchart/c8s/files/scripts/pull-and-configure.sh` (drop-in `kernel_params`)

Observed live (kata 3.30, qemu-nvidia-gpu-tdx): appending to `kernel_params` in
the runtime toml **or** the `config.d` drop-in did not change the qemu
`-append` line of new sandboxes, while the per-pod annotation
`io.katacontainers.config.hypervisor.kernel_params` (allowed by
`enable_annotations`) applied immediately. For guest debugging (e.g.
`systemd.debug_shell=hvc0 systemd.wants=debug-shell.service agent.log=debug`),
annotate the pod instead of editing host config — it's also self-cleaning and
per-workload.

The observation is unexplained (a suspect: kata-deploy's config clobber racing
the edit), and it does **not** license removing the puller's kernel_params
preservation: kata's config loader (`updateFromDropIn`) REPLACES a scalar the
drop-in sets, so whenever the drop-in IS honored, a `kernel_params` line that
failed to carry the stock params forward would drop load-bearing boot args
(`cgroup_no_v1=all`, `nvrc.smi.srs=1`). Net advice: rely on the annotation for
ad-hoc params, keep the puller's preservation, and don't trust manual config
edits to land until this is root-caused on a live sandbox.

## Workload-claims broker socket: group must be reachable by the non-root sidecar

`pkg/workloadclaims/workloadclaims.go` (`ListenUnix`, `BrokerSocketGID`), `internal/webhook/pod_mutator.go` (`ensureSupplementalGroup`)

The broker runs as root (nri-image-policy is a containerd-launched NRI plugin),
so its Unix socket is created `root:root`. get-cert connects as the non-root
sidecar (UID/GID 65532) over a **read-only** mount. A `root:root 0660` socket is
unreachable by that caller — `connect()` needs write permission on the socket
node — and get-cert is **fail-closed** on a broker error, so the pod hangs
forever on its initial cert (`c8s-cert-wait` never passes). It is a silent,
node-wide brick of every `cw` pod, not a graceful degradation.

The socket must therefore be group-owned by a GID the sidecar carries: `ListenUnix`
chgrps it to `BrokerSocketGID` and the webhook injects that same GID as a pod
`SupplementalGroups` entry. **The two must stay equal** — they share the one
constant, so change it in one place only. Do not "fix" a connect failure by
relaxing fail-closed (broker error ⇒ issue claim-free): that hands an attacker
who blocks the broker exactly the claim-free cert fail-closed exists to deny.
Connecting to a socket is exempt from the read-only-mount write block (sockets
are not regular files), so the RO mount still prevents a socket-file swap
without blocking the connect. The same-process broker unit tests cannot catch
this (listener and client share a UID); `TestListenUnixSetsModeAndGroup` and
`TestWorkloadClaims_InjectsBrokerSupplementalGroup` guard the two halves.
