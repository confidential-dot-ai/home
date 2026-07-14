# Kata image policy

How c8s prevents an arbitrary container image from running inside a
kata-qemu-snp VM. This document complements
[`kata-guest-base.md`](kata-guest-base.md) (the guest-image design) and
[`kata-guest-base/README.md`](../kata-guest-base/README.md) (the recipe)
by walking through the threat scenarios the policy defends against, and
the gaps it does not.

> **Measurement model.** Wherever this doc says a file is "baked in" or
> "part of the launch measurement", that means it sits on the dm-verity
> root: its bytes are covered by the SNP launch digest and cannot change
> without changing the digest. The measurement mechanics (osbuilder
> dm-verity erofs, `kernel-hashes`, the verity root hash in the kata
> kernel cmdline, no IGVM/UKI) live in
> [`kata-guest-base/README.md`](../kata-guest-base/README.md).

The short version: kata-agent's OPA policy is permissive on
CreateContainerRequest (allow-all defaults with `default
SetPolicyRequest := false`), so kata-agent does not gate by image digest
inside the agent itself. The in-VM `policy-monitor` daemon watches
kata-agent's container-bundle directory via inotify, reads each new
container's OCI annotations to get the image digest, checks it against
the allowlist, and SIGKILLs the container's init PID if the digest isn't
on the list.

The allowlist is a **baked seed plus a CDS refresh** (see
[Allowlist sourcing](#allowlist-sourcing-baked-seed--cds-refresh)). The
seed — `/etc/c8s/bootstrap-allowlist.json`, on the verity root and part
of the launch measurement — lets the guest enforce from t=0 with no
network. At runtime policy-monitor polls CDS's `/allowlist` over RA-TLS
(pinned to `cds.measurements`) and merges what CDS serves on top, so
operator additions land without a guest rebuild. The merge only ever
*grows* the set, so a compromised or unreachable CDS degrades to "stale
but no smaller" — never "open".

A previous design (`guest-policy-agent`) also fetched a allowlist from
CDS over RA-TLS, but only *rendered* it informationally — it enforced
nothing inside the VM. policy-monitor keeps the same authenticated CDS
source and actually enforces (SIGKILL). The trade-off it makes — a
post-start kill window — is documented in
[Post-start kill window](#post-start-kill-window) and the
[BPF-LSM upgrade path](#bpf-lsm-upgrade-path) below.

## Trust boundary

| Component | In TCB? | Notes |
|---|---|---|
| `kata-guest-base` guest image (`vmlinuz` + dm-verity rootfs) | yes | Launch digest verified at boot (SEV-SNP, kernel-hashes). |
| `kata-agent` inside the guest | yes | Installed into the rootfs by kata's osbuilder (version-matched) at build. |
| `policy-monitor` inside the guest | yes | Built from this repo, baked into the dm-verity root. |
| `/etc/c8s/bootstrap-allowlist.json` (verity root) | yes | The allowlist **seed** the monitor loads at boot. Part of the launch measurement. |
| CDS `/allowlist` additions (pulled over RA-TLS) | yes, via attestation | Runtime additions merged on top of the seed. Trusted because the pull is RA-TLS-pinned to `cds.measurements` (the host can't substitute a fake CDS), not because they're measured into this guest. |
| `ratls-mesh` + `attestation-service` inside the guest | yes | Same. |
| Host (containerd, kata-runtime, kata-shim) | **no** | Adversarial. Can call kata-agent RPCs via vsock, cannot read VM memory (SEV-SNP). |
| Cloud-init user-data (the `C8S_*` env file) | **partially** | Host controls its contents when per-pod injected; pinned values must be verifiable inside the guest. Today this is a single fixed default baked into the rootfs, not per-pod host-injected. |

## Bootstrap order (the load-bearing piece)

Systemd inside the guest brings the services up in two largely
independent dependency chains. The image-policy chain is short:
`policy-monitor.service` orders only on `local-fs.target` so
`/etc/c8s/bootstrap-allowlist.json` is readable when the monitor
starts — nothing else needs to be up. Only the two units this doc
reasons about are shown below; for the full boot/dependency graph
(attestation-service, ratls-mesh, `c8s-ready.target`) see
[Boot order inside the guest](kata-guest-base.md#boot-order-inside-the-guest)
in [`kata-guest-base.md`](kata-guest-base.md).

```
local-fs.target ─→ policy-monitor.service       (orders only on
                                                  local-fs.target; observes
                                                  /run/kata-containers and
                                                  acts on what it sees.
                                                  c8s-ready.target
                                                  Requires=+After= it —
                                                  see kata-guest-base.md)

(parallel) kata-agent.service
           loads /etc/kata-opa/default-policy.rego
           — a baked file on the dm-verity root. After=
           network-online.target only.
```

Key invariants:

- **kata-agent's policy is the baked
  `/etc/kata-opa/default-policy.rego`**, a real file on the verity
  root that's part of the launch measurement. It carries `default
  SetPolicyRequest := false` plus upstream allow-all defaults for
  every other RPC. It does NOT carry image-digest enforcement —
  that's policy-monitor's job.
- **policy-monitor gates readiness, but `Requires=` nothing itself.**
  `c8s-ready.target` `Requires=` (and `After=`) policy-monitor.service,
  so the guest does not reach readiness — and workload containers, which
  `Requires=c8s-ready.target`, do not start — until the monitor is up and
  its startup seed pass has run. That closes the window where containers
  could run while digest enforcement is offline. The monitor itself
  `Requires=` nothing (only `After=`/`Wants=` ordering for the optional
  CDS refresh), so there is no bootstrap cycle: it enforces from t=0 on
  the dm-verity-baked seed with no network. kata-agent doesn't reference
  the monitor directly — the gate is pulled from c8s-ready.target's side.
- **`kata-agent.service` carries `FailureAction=poweroff`.** If
  kata-agent crashes after start, the VM shuts down rather than
  entering an ambiguous half-running state. kata-runtime sees the
  VM gone, surfaces `CreateContainerError` to kubelet.
- **The seed is read-only; the in-memory set only grows.**
  policy-monitor loads `/etc/c8s/bootstrap-allowlist.json` once at boot
  — the file is on the verity root, so neither the guest nor the host
  can rewrite it, and SEV-SNP memory encryption covers the in-memory
  copy. The runtime CDS refresh only ever *adds* digests to the
  in-memory set (see [Allowlist sourcing](#allowlist-sourcing-baked-seed--cds-refresh));
  it cannot remove the seed or shrink the set, so a compromised or
  unreachable CDS can never reduce enforcement below the measured seed.

## Post-start kill window

`policy-monitor` enforces *after* kata-agent has called fork+exec on
the container init. Concretely:

1. kata-agent's `do_create_container` (rpc.rs:200) writes
   `/run/kata-containers/<cid>/config.json` and forks the init
   process via rustjail. The init lands inside an `exec` fifo wait
   (it cannot run user-supplied code until kata-agent receives a
   StartContainerRequest and writes to the fifo).
2. The directory creation triggers a kernel inotify event on
   policy-monitor's watch. policy-monitor's handler reads config.json,
   extracts the digest, consults the allowlist, and (on deny) reads
   `cgroup.procs` to get the init PID and `kill(pid, SIGKILL)`.
3. The init never reaches the user-binary `execve` — it dies inside
   the exec fifo wait, or (in the worst case) within a few ms after
   StartContainer fires.

The window between fork and SIGKILL is the **post-start kill gap**.
It exists because:

- kata-agent has no upstream-supported pre-start callout we can
  intercept other than the in-process OPA policy, and that policy
  is structurally permissive (see "Why the OPA policy is permissive"
  below).
- Userspace inotify delivers events asynchronously; the kernel
  doesn't pause the writer until a userspace consumer reads the
  event.

The window is bounded (single-digit ms on real hardware), and the
denied container has no useful capabilities inside it (no network
configured yet, no `execve` to user code yet). The
[BPF-LSM upgrade path](#bpf-lsm-upgrade-path) below describes how to
close the gap by hooking `security_bprm_check_security` in the kernel.

**The bound holds only if the kill actually lands.** Step 2's `cgroup.procs`
read depends on locating the container's cgroup, and on a systemd-PID-1 guest
that cgroup is a systemd *scope* — `cri-containerd-<cid>.scope` nested under
`kubepods*.slice` — not a bare `<cid>` directory. A cgroup matcher that only
recognizes the bare `<cid>` silently misses the kill on the common (systemd)
guest: policy-monitor *denies* the container but `findInitPID` returns
not-found, so the SIGKILL never fires and the denied image runs **unenforced**
(this was a 2026-07 field bug, fixed). The matcher must handle the
systemd-scope naming — see `internal/cmds/policymonitor/kill.go`
(`cgroupDirMatchesCID`).

## Why the OPA policy is permissive

kata-agent's bootstrap OPA policy in this image is
`allow-all.rego`-plus-`SetPolicyRequest := false`. We don't carry a
per-image-digest Rego rule there because:

1. **Regorus crypto.** Adding `data.agent_policy.allow if
   input.digest in allowed_digests` to the baked Rego would couple
   the guest image to a specific allowlist (the same coupling we get
   from the JSON file policy-monitor reads). That's fine in principle,
   but if the operator later wants to sign a runtime update,
   regorus would need crypto builtins it doesn't have — and the
   c8s posture is "the guest image is the version pin", so adding a
   runtime-update path would be re-creating a problem we already
   solved.
2. **Policy-monitor cleanliness.** Keeping enforcement in a
   userspace daemon means the audit log is in journald (where the
   operator already looks), the decision logic is in Go (easier
   to test and patch than embedded Rego), and the "kill the
   container" action is a syscall not an ttRPC reply that
   kata-runtime might map back into a CreateContainerError that
   the operator has to grep for in kubelet logs.

A future PR may revisit this and put a `default allow := false`
clause in the baked policy plus the allowed digests as Rego data;
that would close the post-start window in the agent itself, but at
the cost of regorus integration testing on every kata version
bump. Today the simpler path is policy-monitor.

## Allowlist sourcing: baked seed + CDS refresh

policy-monitor's allowlist has two sources, unioned in memory:

1. **Baked seed.** `/etc/c8s/bootstrap-allowlist.json` is materialised
   at guest-image build time (`kata-guest-base/scripts/fetch.sh`
   substitutes the resolved **cds** and **get-cert** image digests) and
   sits on the dm-verity root, so it's covered by the kernel-hashes
   launch measurement. policy-monitor loads it once at boot. This is
   what lets the guest enforce from t=0 with **no network** — there's
   no boot-path fetch, so no CDS-bootstrap deadlock and no "fails open
   until the first pull" window.

2. **CDS refresh.** When the guest is configured with a CDS URL
   (`C8S_CDS_URL`, delivered via the same cloud-init env file
   `ratls-mesh` reads — **Status:** today that env file is a single fixed
   default baked into the rootfs, not per-pod host-injected, so a
   non-default-namespace install needs the real injection),
   policy-monitor polls CDS's `GET /allowlist` on
   an interval and merges the result on top of the seed. The pull uses
   the **same mechanism the host nri-image-policy worker uses**:
   `pkg/allowlistclient` over an RA-TLS transport (`pkg/ratls`) whose
   peer cert is pinned to `cds.measurements`. So the in-guest enforcer
   and the host enforcer consult the same authenticated CDS allowlist;
   the in-guest one is the strictly-stronger check (the TEE re-deciding
   for itself rather than trusting the host's NRI verdict).

The merge is **grow-only**: it adds digests, never removes them, and
never touches the seed. Consequences:

- A CDS outage, a slow CDS, or a CDS the RA-TLS handshake rejects
  (measurement mismatch) leaves the current set intact — at minimum the
  measured seed. Enforcement degrades to "stale but no smaller", never
  "open". (This is the right failure mode for an *allow*-list.)
- Operator additions to the cluster allowlist propagate to running kata
  guests within one refresh interval, **without a guest-image rebuild**
  — the operational cost the older baked-only model carried (see
  [G2](#g2--allowlist-additions-no-longer-need-a-guest-image-rebuild)).
- With `C8S_CDS_URL` unset (no cloud-init, or a deliberately air-gapped
  guest) policy-monitor never opens the network and enforces the baked
  seed alone — still fully fail-closed.

`C8S_CDS_MEASUREMENTS` pins CDS's RA-TLS serving-cert launch digest.
Leaving it empty **disables the refresh** (logged as an error at
startup): policy-monitor deliberately refuses to pull unpinned. This is
*stricter* than `ratls-mesh`, which warns and proceeds on an empty pin —
the asymmetry is intentional. For the mesh, an unpinned peer still has
to be *some* attested TEE; for the refresh, "any attested TEE" is not
enough, because the host can boot its own CVM from this same guest
image, run a CDS in it serving an attacker-chosen allowlist, and pass
"attested" — and grow-only merging is no defence when *additions* are
the attack. With the refresh disabled the guest enforces the measured
seed alone, which is fail-closed.

**Status:** no shipping path delivers this pin to guests today, so the
refresh is disabled on every default install — operator additions reach
the host-side enforcer but not running guests. Baking the pin is
structurally impossible (under kata, CDS runs from this same guest
image, so the pin's value would change the launch measurement it pins),
and per-pod cloud-init injection is host-controlled, so a host-supplied
pin could point at the host's own fake CDS. See GAPS.md ("in-guest CDS
allowlist refresh") for the status and the candidate fix.

## Scenarios

For each scenario: setup, attacker action, expected outcome, why.

### S1 — Cold pod start, happy path

**Setup.** Operator has built and pinned a kata-guest-base image whose
baked `/etc/c8s/bootstrap-allowlist.json` seed contains the SHA-256
digests of the c8s bootstrap images at the matching release tag
(cds, get-cert). Pod manifest references `kata-qemu-snp` (after webhook
injection).

**Flow.** kata-runtime boots the guest → systemd starts services →
policy-monitor opens the inotify watch and loads the allowlist →
kata-agent starts and accepts CreateContainerRequest → kata-agent
writes config.json and forks the init → inotify event reaches
policy-monitor → monitor extracts the digest, finds it on the
allowlist, logs allow, does nothing → kata-agent receives
StartContainerRequest and signals the init's exec fifo → container
runs.

**Outcome.** Pod runs.

### S2 — Malicious workload image (not on allowlist)

**Setup.** Adversary submits a pod manifest referencing an image
whose digest is not on the operator-pinned allowlist baked into the
guest image. (The "adversary" here is anyone with cluster-write
permission: a compromised CI pipeline, a tenant in a multi-tenant
cluster, etc.)

**Flow.** Pod is admitted. Pod gets `kata-qemu-snp` via the c8s
webhook. kata-runtime boots the guest, kata-agent's CreateContainer
forks the container init. policy-monitor sees the new bundle, reads
config.json, extracts the image digest from the OCI annotation, the
digest is NOT in the allowlist → monitor resolves init PID via the
container's cgroup, sends SIGKILL.

**Outcome.** Container's init process dies before its first
post-StartContainer instruction. kata-agent's exec fifo notification
arrives to a dead PID (ESRCH on the signal); kata-agent reports
container exit to kata-runtime; kubelet records `CrashLoopBackOff`
or `CreateContainerError` depending on timing. Pod doesn't reach a
running state.

### S3 — Host attempts to relax policy via SetPolicy

**Setup.** Pod is running. Compromised host wants to bypass the
baked kata-agent policy (e.g. so it can land a container with a
different policy).

**Flow.** Host's kata-shim opens a vsock connection to kata-agent's
control channel and sends a `SetPolicyRequest` → kata-agent
evaluates against the current (baked) policy → the baked policy has
`default SetPolicyRequest := false` → kata-agent returns
`PERMISSION_DENIED` → the in-memory policy is unchanged.

Note: even if SetPolicy were allowed, the host could not change
the policy-monitor's allowlist. SetPolicy targets kata-agent's
in-process Rego engine, not the verity-protected
`/etc/c8s/bootstrap-allowlist.json` file.

**Outcome.** Host's policy mutation is rejected.

### S4 — Host attempts to modify the allowlist file on disk

**Setup.** Pod is running. Compromised host wants to swap
`/etc/c8s/bootstrap-allowlist.json` to permit a new image.

**Flow.** The file lives on the verity-protected rootfs.
Any modification breaks the verity hash chain — the kernel's
dm-verity layer fails the read, policy-monitor sees an I/O error
on its (cached) in-memory snapshot... actually policy-monitor
already loaded the file at boot, so the in-memory snapshot is
the authoritative copy for the lifetime of the VM. Modifying the
on-disk file does nothing.

Even if the host could tamper with the on-disk file pre-boot:
that would change the guest image's launch measurement, and the
operator's attestation flow would reject the pod.

**Outcome.** Allowlist tampering is not reachable from the host.

### S5 — Host attempts to kill policy-monitor

**Setup.** Pod is running with a denied container queued. Compromised
host wants to disable policy-monitor so the denied container runs.

**Flow.** kata-runtime can ask kata-agent to signal arbitrary PIDs
via the SignalProcessRequest RPC, but only against PIDs of
*containers* kata-agent knows about. policy-monitor runs under
systemd as a system service (PID is allocated by systemd at boot,
unknown to kata-agent), not as a container; its PID is not a valid
target for SignalProcessRequest. The host can't otherwise reach into
the VM's process table because SEV-SNP memory encryption hides it.

**Outcome.** policy-monitor cannot be killed from the host.

### S6 — Container init exits before SIGKILL lands

**Setup.** A denied container's init process exits on its own (e.g.
a crash, or it's a `/bin/false` test) before policy-monitor can
SIGKILL it.

**Flow.** policy-monitor reads cgroup.procs and either gets ESRCH
on the kill (process already gone) or doesn't find a PID at all
(cgroup empty). The monitor logs the case at info level and moves
on. The container is effectively "killed" — by itself — before any
useful work.

**Outcome.** Denied container exits, just as if policy-monitor had
killed it. No false-positive enforcement; no leakage.

### S7 — kata-agent crashes mid-pod

**Setup.** Pod is running normally. kata-agent encounters an
unrecoverable bug, panic, or OOM.

**Flow.** Process exits → systemd sees the failure →
`FailureAction=poweroff` fires → guest VM shuts down → kata-runtime
sees the VM gone → kata-shim reports failure to kubelet.

**Outcome.** Pod terminates. policy-monitor's state is moot — the
VM is gone.

### S8 — Pre-startup container injection

**Setup.** Adversary wants to run code in the guest VM before
kata-agent is up.

**Flow.** Before kata-agent is up, the only processes inside the VM
are systemd-managed services from the guest image — `attestation-service`,
`ratls-mesh`, `policy-monitor`, plus the cloud-init phase. None of
these are container runtimes; none of them honor arbitrary
exec-this-binary requests from the host. To run a container, the
host has to talk to kata-agent over vsock. kata-agent doesn't exist
yet.

**Outcome.** No exposure window before policy load.

### S9 — Bootstrap: c8s-cert sidecar, which the webhook injects

**Setup.** Operator deploys a workload pod. The c8s webhook injects a
single `c8s-cert` native sidecar (init container with
`restartPolicy: Always`). It uses `cfg.GetCertImage` from the chart
(`ghcr.io/confidential-dot-ai/get-cert:<tag>`).

**Flow.** kata-runtime calls CreateContainer for the sidecar.
kata-agent forks its init; policy-monitor sees the new bundle,
extracts the digest, the get-cert digest IS in the allowlist (the
bake-time substitution at guest-image build time put it in the seed
alongside cds), monitor logs allow, init runs, gets the workload's
leaf, exits 0.

**Outcome.**
- If the operator built the guest image from a c8s release that
  included the get-cert image at the matching tag (the default path —
  `scripts/fetch.sh` resolves the digest from the IMAGE_TAG env
  var): pod runs as designed.
- If the operator overrode the IMAGE_TAG to a tag whose get-cert
  was different and forgot to refresh: get-cert's digest is not on
  the allowlist, the init container is killed, the pod never
  reaches the workload container. Operator's monitoring catches
  it; the workload never runs.

The hazard ("operator forgot to refresh") is a configuration
concern, not a security failure — the design is fail-closed.

### S10 — Cold pod start with no user-data at all

**Setup.** Pod creation racing some kata-runtime bug, or a
misconfigured pod that doesn't trigger user-data injection.

**Flow.** cloud-init runs but finds no NoCloud datasource. The c8s
`cloudinit-env.sh` script falls back to writing an empty env file.
ratls-mesh's validation fails → ratls-mesh.service enters `failed`
→ c8s-ready.target never reaches active. policy-monitor reads the same
env file: with no `C8S_CDS_URL` it simply runs **baked-seed-only** (the
CDS refresh never starts, the network is never touched) and continues
to enforce the seed on any container kata-agent does start.

**Outcome.** Pod doesn't reach mesh-ready state; workloads can't
talk over the mesh. But the kata-agent + policy-monitor pair still
behaves correctly on any in-bundle workload — fail-closed for
ratls-mesh, still-enforcing (against the measured seed) for
policy-monitor.

### S11 — Two CreateContainer calls (pause + workload)

**Setup.** Standard kubernetes pod with a pause sidecar and a
workload container. kata-agent gets two CreateContainerRequest calls
in succession.

**Flow.** Both calls are evaluated against the same baked OPA policy in
kata-agent (allow-all on CreateContainerRequest). policy-monitor sees an
inotify event per container bundle and evaluates each independently
against the in-memory allowlist — except the sandbox (pause) container,
which is out of allowlist scope (see Outcome).

**Outcome.** The workload container passes iff its digest is on the
allowlist; the first denied workload container halts the pod. The
sandbox (pause) container is **not** an allowlist entry: kata-agent
ships its own pause baked into the dm-verity rootfs (the `/pause_bundle`
staged by `build.sh`), so its integrity is anchored by the launch
measurement — the host cannot substitute it — and it needs no allowlist
digest. The bootstrap allowlist therefore carries only the host-pulled
component images (`cds`, `get-cert`); the sandbox container is treated as
measured-by-construction and skipped, not digest-enforced.

## Host can't substitute a fake CDS allowlist

policy-monitor *does* fetch the allowlist from CDS at runtime (the
hybrid refresh), so the question is whether a compromised host — which
brokers the guest's network — can feed it a fake, over-permissive list.
It cannot, for two independent reasons:

- **RA-TLS measurement pinning.** The refresh dials CDS over an RA-TLS
  transport that verifies the peer's attestation evidence against
  `cds.measurements` (the same `pkg/ratls` pin `ratls-mesh` and the host
  nri-image-policy worker use). A host that MITMs the connection or
  points it at an attacker-run service presents evidence that doesn't
  match the pinned CDS launch digest, the handshake fails, and the pull
  is rejected — policy-monitor keeps its current set.
- **Grow-only merge over a measured seed.** Even if a fetch returned
  bogus data, the merge only *adds* digests on top of the verity-measured
  seed; it can't remove the seed or shrink enforcement. And a host that
  simply *blocks* the refresh achieves nothing beyond freezing the set
  at its current (≥ seed) contents.

So the host can, at most, prevent *new* legitimate additions from
reaching a guest (a liveness nuisance, surfaced as denied workloads the
operator can see) — it cannot inject an entry to smuggle an
unattested image past policy-monitor.

## BPF-LSM upgrade path

This is a future-direction note, not a TODO we're committing to —
the goal is "we won't forget this is an option." It is the
documented way to close the post-start kill gap (G1).

The post-start kill window is inherent to a userspace inotify
watcher. To close it pre-`bprm_check`, the policy decision has to
happen inside an LSM hook — and the kernel hook that fires before
a process's first `execve` settles its credentials is
`security_bprm_check_security` (LSM's `bprm_check_security`).
Linux's BPF-LSM (CONFIG_BPF_LSM=y, with `CONFIG_LSM` containing
"bpf") lets us attach a CO-RE eBPF program to that hook.

Sketch:

1. **Boot-time install.** A small initialisation phase in
   policy-monitor (or a sibling unit ordered before `kata-agent`)
   loads a CO-RE BPF object on boot. The object exposes:
   - An eBPF `BPF_MAP_TYPE_HASH` from container-id (or PID
     namespace cookie) to a "allow" bool.
   - A program attached to `lsm/bprm_check_security` that
     looks up the calling task's cgroup → container id → map
     entry, returns -EPERM if denied.
2. **Per-container population.** When the userspace monitor sees a
   new bundle and resolves its digest, it writes the allow/deny
   decision into the map under the container's cgroup id (the
   bprm_check hook can read the cgroup id of `current`).
3. **Race-free start.** The kernel evaluates the hook before
   `do_execveat_common` commits the new mm to the task, so a
   denied digest never reaches userspace `main`. No millisecond
   gap.

Practical considerations:

- BTF: the kernel must be CO-RE-friendly. SEV-SNP-eligible kernels
  (>= 6.x with the SNP guest patches) ship BTF by default.
- LSM stacking: `CONFIG_LSM=...,bpf,...` must place "bpf" before
  any LSM that fails closed if our program is unloaded. The
  kata-static kernel we use already builds with bpf+selinux
  stacking; verify before relying.
- Allowlist materialisation: unchanged from today's sourcing. The
  userspace monitor still owns the allowlist (baked seed + CDS
  refresh) and just writes each allow/deny decision into the BPF map
  per container; the kernel hook only reads the map. So the BPF path
  inherits the same seed-plus-refresh trust chain — it moves *where*
  the decision is enforced (pre-execve in-kernel), not *how* the
  allowlist is sourced.

The work is non-trivial but linear; it's captured here so a future
contributor doesn't rediscover the option from scratch.

## Known gaps

### G1 — Post-start kill window

policy-monitor enforces *after* kata-agent has forked the container
init, not before — the mechanics and bounds are in
[Post-start kill window](#post-start-kill-window) above.

**Severity: low** — *provided the kill lands*. The TCB protection
(SEV-SNP-encrypted memory) holds for the duration of the gap; the denied
init cannot exfiltrate. But the gap is honest and called out for
completeness. Note the bound is only "low severity" once the kill path
matches the guest's systemd-scope cgroup naming (see the reliability caveat
in [Post-start kill window](#post-start-kill-window) above); a matcher that
missed it turned this bounded gap into unbounded non-enforcement.

**Mitigation.** The [BPF-LSM upgrade path](#bpf-lsm-upgrade-path)
hooks `security_bprm_check_security` to make the decision
pre-execve. Future direction, not committed today.

### G2 — Allowlist additions no longer need a guest-image rebuild

Earlier baked-only versions of this design required a full guest-image
rebuild + pod roll to add an allowed digest (the allowlist was *only*
the measured seed). The hybrid refresh resolves that: operator
additions land in CDS's allowlist and propagate to running guests over
the RA-TLS pull within one refresh interval — no rebuild. The
[Allowlist sourcing](#allowlist-sourcing-baked-seed--cds-refresh)
section covers the mechanism and its grow-only / fail-safe properties.

**What still needs a rebuild:** the *seed* itself — the bootstrap set
(cds, get-cert) the guest enforces before its first successful CDS
pull. That's deliberate: the seed must be measured, and a guest that
trusted an unmeasured boot-time allowlist would defeat the point. So
the trust pin is unchanged (the seed is in the launch measurement);
only the day-2 *additions* are now dynamic, and they ride the same
RA-TLS-authenticated CDS channel the host enforcer uses.

**Residual note.** The refresh is pull-only and grow-only, so there is
no in-guest *revocation* path: removing a digest from CDS does not
retract it from a guest that already pulled it (until that guest
restarts and reloads the seed). Image policy is an allow-list, so a
stale-but-larger set only ever permits images the operator explicitly
allowlisted at some point — acceptable, and called out for honesty.

### G3 — Image content is visible to the host during the guest-pull

The guest runs with `experimental_force_guest_pull = true` and
`shared_fs = "none"`, so the workload's OCI image is
[guest-pulled](kata-guest-base.md#what-guest-pull-is) inside the VM
rather than unpacked on the host and bind-mounted in. The host no
longer sees the unpacked rootfs.

What the host still sees is the *transport*: it brokers the guest's
outbound network, so for an anonymous pull from a public registry it
observes which image reference and layers are fetched (a metadata
leak, not a content-confidentiality break — the bytes are public).
Registry credentials for private pulls are delivered to the in-guest
CDH after attestation (KBS) rather than baked, so they are not
exposed to the host.

policy-monitor still enforces on CreateContainer (it reads the
digest from the bundle's `config.json`). Moving the decision earlier
— an inotify watch on the guest-pull image work dir
(`/run/kata-containers/image/`, kata-agent's KATA_IMAGE_WORK_DIR,
`confidential_data_hub/image.rs:22`) to reject on PullImage rather
than CreateContainer — would shrink the G1 window further and is
tracked as a future tightening.

### G4 — BPF-LSM upgrade path

The post-start kill gap (G1) is the most consequential gap the
current design has. The [BPF-LSM upgrade path](#bpf-lsm-upgrade-path)
above is the linear, non-controversial way to close it (and carries
the full implementation sketch). Not on today's roadmap.

## What this design does and doesn't claim

**It claims:**

- The host cannot mutate kata-agent's bootstrap policy after boot
  — the `SetPolicyRequest := false` rule in the baked policy
  rejects the canonical mechanism, and the on-disk file is on the
  verity-protected, SEV-SNP-encrypted rootfs the host can't write
  to. (S3, S4.)
- The host cannot inject an over-permissive allowlist. The seed
  `/etc/c8s/bootstrap-allowlist.json` is on the verity root and part of
  the launch measurement (S4), and the runtime CDS additions arrive over
  RA-TLS pinned to `cds.measurements`, so the host can't substitute a
  fake CDS ("Host can't substitute a fake CDS allowlist"). At worst the
  host blocks new additions — it can't shrink enforcement below the
  measured seed.
- The host cannot kill policy-monitor from outside the VM. (S5.)
- The kata VM is the trust boundary (SEV-SNP-encrypted memory)
  and policy-monitor + ratls-mesh + attestation-service inside
  the guest image are part of the launch measurement. (S1, S11.)
- Per-image-digest enforcement happens for every CreateContainer
  inside the VM (S2, S6, S9, S11) — at the cost of a single-digit-ms
  post-start window (G1).

**It does not claim:**

- That the denied container's init *never executes any code*.
  policy-monitor SIGKILLs the init after the kernel has forked it
  (G1). The init has no network and no user-execve in that window,
  but the window exists.
- That CDS unreachability blocks the pod from booting or changes what
  policy-monitor enforces. The measured seed enforces regardless; a CDS
  outage only stops *new* additions from merging (grow-only). (Mesh-layer
  mTLS still fails closed on unreachable CDS via the get-cert init, but
  that's a separate enforcement layer.)
- That image *content* is hidden from the host during the
  guest-pull transport (G3).

The G1 gap (post-start kill window) is the most consequential
honest limitation. The BPF-LSM upgrade path (G4) is the documented
way to close it; today's design accepts it because the in-VM
post-fork pre-execve window is short, capability-poor, and inside
the SEV-SNP trust boundary.
