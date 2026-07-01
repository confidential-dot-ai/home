# Pitfalls

Gotchas for humans and agents working on c8s. Each cites the relevant code.

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

## kata-qemu-snp pods still need a host-side image pull (no nydus-snapshotter)

Without a nydus-snapshotter, containerd does a host-side CRI pull of the workload
image **before** kata guest-pulls it inside the VM. For a private image
(e.g. `ghcr.io/confidential-dot-ai/cds`) the host pulls *anonymously* and gets `401` unless
`serviceAccount.imagePullSecrets` supplies creds. So a guest-pull workload needs
creds in **two** places: the host (an image-pull Secret) **and** the guest
(`agent.image_registry_auth`, set by the puller — see
`internal/helmchart/c8s/files/scripts/pull-and-configure.sh`). For the c8s
components themselves the host side is one flag: create the Secret once and
pass `c8s install --image-pull-secret <name>` (or set `imagePullSecret` via
values) to wire it into every component's `imagePullSecrets` at install time
— see docs/QUICKSTART.md "Private registry credentials".
Adding a nydus-snapshotter would make the host pull metadata-only and remove
the host-creds requirement.

## cds cannot reach Ready as runc on a host that is not an SNP guest

`internal/helmchart/c8s/templates/cds.yaml`

cds's RA-TLS serving cert needs SNP evidence from `/dev/sev-guest`, which only
exists **inside** an SNP guest (the host has `/dev/sev`, not `/dev/sev-guest`).
The non-kata probes are httpGet/HTTPS. So running cds as host runc (no `--kata`)
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

## Private `kata-guest-base` puller credentials (`kata.guestImage.pullerAuthSecret`)

`internal/helmchart/c8s/templates/kata-image-puller.yaml`, `internal/helmchart/c8s/values.yaml`

The kata-image-puller fetches the `kata-guest-base` oras artifact by shelling
out to `oras pull` **inside the puller pod** (see `files/scripts/pull-and-configure.sh`).
This is **not** a kubelet image pull: `oras` only reads `~/.docker/config.json`
and is oblivious to Kubernetes `imagePullSecrets` — Secret references on the
puller ServiceAccount only help kubelet pull the puller's **own** image.
Without a projected credential the `kata-guest-base` pull is anonymous and
401s against the private `ghcr.io/confidential-dot-ai` artifact with:

```
Error response from registry: failed to resolve <tag>: GET …/manifests/<tag>: unauthorized
```

**Mitigation:** the chart projects a `kubernetes.io/dockerconfigjson` Secret's
`.dockerconfigjson` key to `/root/.docker/config.json` in the puller pod —
exactly where `oras` looks (the container runs as root under
`privileged: true`, so `$HOME=/root`). That Secret defaults to the
install-time `imagePullSecret`, so a plain
`c8s install --kata --image-pull-secret ghcr-secret` covers the oras pull
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
rebuild, no re-pinned digest. Contrast `kata.guestImage.registryAuth` and the
baked `ghcr-auth.json` (see next section), both of which **do** move the
measurement.

**Remove this once the artifacts go public.** Same rationale as the baked
`ghcr-auth.json` tradeoff below — `pullerAuthSecret` exists only because
`kata-guest-base` is currently a private oras artifact. When the repos /
artifacts flip public, drop the value from your values file and delete the
Secret; the puller will pull anonymously and the host-side credential goes
away entirely.

## `ghcr-auth.json` bakes a real GHCR PAT into the measured rootfs — by design, but know the tradeoff

`kata-guest-base/extra/etc/c8s/ghcr-auth.json` is a docker auth.json baked into
the dm-verity guest rootfs so kata's `experimental_force_guest_pull` can fetch
**private** `ghcr.io/confidential-dot-ai` workload images from inside the guest. It is
**generated at build time** by `kata-guest-base/scripts/fetch.sh` from the
`READ_PRIVATE_GHCR_TOKEN` env — a classic **read-only** (`read:packages`) PAT
that CI passes from the repo secret of the same name. At boot, tmpfiles
(`extra/etc/tmpfiles.d/c8s.conf`) copies it to `/run/image-security/auth.json`,
the `file://` path named by `agent.image_registry_auth` on the guest kernel
cmdline (the puller appends that from `kata.guestImage.registryAuth`, which now
**defaults** to `file:///run/image-security/auth.json` — see
`internal/helmchart/c8s/values.yaml`).

It is gitignored (`kata-guest-base/.gitignore`) because it holds a credential
and is build output — **never commit it.** But, unlike before, the CI build
**does** consume the secret and bake it. The four things to keep in mind:

1. **The credential is inside the SNP launch measurement.** The file's bytes are
   part of the dm-verity root, exactly like `bootstrap-allowlist.json`. So
   **rotating the PAT changes the measurement** and requires an image rebuild +
   re-pinned digest. The cmdline value itself is a fixed `file://` URI (not the
   secret), so adding it is deterministic — but it still *moves* the measurement
   vs. the old empty default, so re-predict after upgrading to a guest-base that
   carries it.
2. **Why this is acceptable today:** the token is read-only and the repos +
   published artifacts are private; once they go public the PAT grants no more
   than anonymous access already would. This is the deliberate decision recorded
   here — it is *not* a leak to fix.
3. **The secret-free path still exists.** A build run **without**
   `READ_PRIVATE_GHCR_TOKEN` bakes an empty auth set (`{"auths":{}}`) — no
   credential in the image, anonymous guest-pull only. Production that wants zero
   baked secrets should build that way and set `kata.guestImage.registryAuth` to
   a `kbs://` URI so CDH fetches the auth.json from the Key Broker Service *after*
   the guest attests.
4. **A locally hand-placed `ghcr-auth.json` is preserved.** `fetch.sh` only
   overwrites it when `READ_PRIVATE_GHCR_TOKEN` is set, so a developer's
   pre-staged file for local guest-pull testing survives a no-token `fetch.sh`.

## Bump `KATA_SRC_COMMIT` in lockstep with `KATA_VERSION`

`kata-guest-base/scripts/build.sh:79`

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
