# get-cert and the workload-digest → RA-TLS cert binding

This walks the **workload-digest** path end to end: how a pod's container
images end up bound into its mesh certificate, and the several corners that
routinely confuse people. It is the companion narrative to
`docs/ratls.md` (the normative wire spec) — read this for *how the flow
works and why it is safe*, read that for *the byte formats and verification
rules*.

Scope: Layer 3 (workload digests). The operator-key and allowlist-seed claims
(Layers 1–2) ride the same config-claims extension but are set by CDS on its
own serving cert, not by workloads; they are covered in the Config-claims
section of `docs/ratls.md`.

---

## The one-paragraph version

`get-cert` (the injected `c8s-cert` sidecar) asks a node-local **broker** —
part of the image-admission component itself (`nri-image-policy` on node-CVM,
`policy-monitor` on kata), not a standalone service — "what containers does
my pod run?" *without saying who it is*. The broker learns the caller's
identity from the **kernel** (unix-socket peer credentials), maps it to a
pod, and returns that pod's admitted containers — each as an
`(image digest, argv)` tuple, argv being the merged entrypoint+cmd the
runtime will actually `execve`. `get-cert` hashes them into two commitments
— `workloadDigest` (image-only) and `workloadArgsDigest` (image+argv,
per-container) — binds both into its CSR's attestation evidence, and
forwards the plain tuples to CDS. CDS re-derives both hashes, confirms every
listed image is allowlisted, and stamps the claim onto the issued leaf. A
relying party can then pin the workload at either granularity
(`c8s verify --workload-image sha256:…` for image-only, or
`c8s verify --workload-spec` for image+argv) or read a live mesh peer's
digests off the connection with `ratls.PeerConfigClaims` (docs/ratls.md,
"Reading a peer's claims").

---

## FAQ — "wait, isn't this brittle?"

The flow looks indirect on first read. It is indirect on purpose: every
shortcut (let the pod report its own image, name the pod in the request, trust
get-cert outright) is a forgery vector. The answers below are the quick
version; each points at the Corner with the full argument.

**Doesn't the pod already know what image it runs?** No — and a self-report
wouldn't be trustworthy even if it did. A pod is a set of containers; a single
container sees its own rootfs, not the registry *digest* it was pulled as, and
nothing about its siblings. The workload identity is the pod's whole image set,
which only the component that admitted those containers — the broker — holds. A
malicious container could also just lie about its own digest, so self-report is
a non-starter regardless. (Corner 1, Corner 6.)

**How does the broker know which pod is calling — is that operator-controlled?**
No, and that is the crux. get-cert sends no identity at all. When it connects,
the **kernel** stamps the caller's PID onto the socket (`SO_PEERCRED`); the
broker reads that PID and resolves it PID → cgroup (`/proc`) → container → pod
from its *own* admission record. Every link is kernel/runtime-derived — nothing
the caller or the control plane supplies is used for identity. The kernel doing
the stamping is in the TCB (the node is the CVM under node-CVM; the measured
guest under kata). (Corner 1.)

**Does get-cert check it's in a TEE first?** No, and it doesn't need to. It
generates attestation evidence via the local attestation-api, and **CDS**
verifies that evidence — hardware signature chain plus the pinned launch
measurement — before issuing anything. Outside a real TEE the evidence does not
verify, so no certificate is issued. (Step 5; `docs/ratls.md`.)

**How does CDS know to trust get-cert — is it baked into the base image?** Two
layers, and the second is why brittleness in the first doesn't sink it. (1)
get-cert's integrity is allowlist/measurement-rooted: under node-CVM its image
runs only because nri-image-policy admitted it (allowlisted); under kata it is
baked into the measured guest image. (2) CDS does not *have* to trust get-cert:
it treats the forwarded digest list as an untrusted proposal and independently
confirms it hashes to the evidence-bound `workloadDigest` **and** that every
digest is allowlisted. The compiled-in socket path is a related but separate
property — because the path is part of get-cert's own image digest, the control
plane cannot repoint get-cert at a rogue broker. (Corner 5, Corner 6.)

**It says "claimed image" — what stops a malicious pod claiming some other
image?** Less than the flow first suggests, and this is the feature's key
limitation. **Guaranteed:** a claim can never carry a **non-allowlisted** image
(CDS re-checks every digest against the allowlist store), and the forwarded list
must hash to the evidence-bound digest. **Not guaranteed:** that a workload
claims only what it *actually runs*. Any admitted workload can run the attest
flow itself — the attestation-api binds caller-chosen `REPORT_DATA`, and CDS
enforces only list↔claim-hash and allowlist membership; it does **not** verify
the claim came from the honest get-cert→broker path (`SO_PEERCRED` binds
*get-cert's* caller, and CDS does not re-check it). So a malicious pod can assert
**any allowlisted image set**, including a victim workload's, and satisfy
`c8s verify --workload-image <victim>`. **The pin therefore distinguishes honest
workloads only** — it detects an honest workload drifting or a config swap, not a
lying one. Binding the claim to what the pod is measured/admitted to run,
enforced at `/attest`, is the real close, and
unimplemented (GAPS §Trust model). (Corner 5, Corner 6.)

**What stops "same image, different `command`" from slipping through — the
busybox case?** The broker records each admitted container's **argv** — the
merged entrypoint+cmd the runtime will `execve`, after image config and
pod-spec overrides — alongside its image digest, and get-cert folds argv into
a per-container leaf inside a second commitment, `workloadArgsDigest`. Same
image with different argv → different leaf → different digest. A verifier
that pins with `--workload-spec` (image+argv) catches the swap; a verifier
that pins only `--workload-image` sees identical image sets and does not —
the operator picks the granularity. Trust for argv rides the same chain as
for the image digest: NRI/kata report what they admitted, the broker binds
the caller by kernel credentials, and CDS re-derives the hash and gates on
allowlist membership. env is not bound — accepted risk (Corner 3).

**Is the unix socket secured so a malicious pod can't hijack it?** Two separate
threats:

- *Impersonating another pod over the socket* — closed by `SO_PEERCRED`. The
  socket's mode gates who can *reach* the broker, but identity comes from the
  kernel-reported PID, not anything a caller sends, so even a reachable caller
  is bound to its own pod.
- *Replacing the socket file* — the real hijack vector. get-cert mounts the
  socket directory **read-only**, so it cannot swap the socket from inside its
  own pod. On node-CVM the socket lives on a host directory, so a *separate*
  malicious pod that could `hostPath`-mount that directory read-write could
  swap the socket before get-cert connects — a PodSecurity / filesystem-
  permission concern (the socket dir must be unwritable by untrusted pods), not something attestation closes. Under kata the mount is a
  guest bind-mount inside the measured VM, so there is nothing host-supplied to
  swap. **Who creates the socket, and why the L0 host can't inject one, is
  Corner 7.** (Corner 5, "Why a unix socket".)

---

## The actors

- **get-cert** — runs in the `c8s-cert` native sidecar the webhook injects
  into every `confidential.ai/cw` pod. Generates the leaf key, builds the CSR,
  drives the CDS attestation flow, writes the cert. (`internal/cmds/getcert`)
- **The broker** — serves "the calling pod's admitted image digests." It lives
  *inside the component that already makes the admit/deny decision*, so what it
  vouches for is exactly what was admitted:
  Both shapes serve it over a **unix socket** get-cert dials at one compiled
  path:
  - **node-CVM**: `nri-image-policy` (the host NRI plugin). The node is the
    confidential VM, so the plugin is in the TCB.
  - **pod-CVM (kata)**: `policy-monitor` inside the measured guest, whose
    socket directory the guest bind-mounts into the pod.
- **CDS** — verifies the evidence, checks each claimed image against the
  allowlist store, signs the leaf with the mesh CA, embeds the claim.
- **The verifier** — anyone doing `c8s verify --workload-image …`, or a future
  mesh peer that pins workload identity.

---

## Step by step

1. **get-cert asks, anonymously.** It opens the broker at its compiled Unix
   socket path (`--workload-claims-broker`, the same in both shapes) and sends
   a plain `GET /v1/workload-digests`. The request carries **no** PID, pod
   name, or container ID. (See "Corner 1".)

2. **The broker binds the caller from the kernel.** On the unix socket it reads
   the peer's PID with `getsockopt(SO_PEERCRED)`
   (`pkg/workloadclaims/peercred_linux.go`), resolves that PID to a container
   via `/proc/<pid>/cgroup` (`cgroup.go`), maps container → pod from its own
   admission record, and returns the pod's **non-injected** containers as
   `{name, image digest, argv}` tuples
   (`internal/cmds/nri-image-policy/broker.go`). Nothing the caller *sent* is
   used for identity.

3. **get-cert folds the containers into two digests, split by role.** It
   splits the broker's containers into the pod's init set and main set (by
   the init-container names the webhook passed), and computes both
   `workloadDigest` (image-only, `workloadclaims.Digest`) and
   `workloadArgsDigest` (per-container `(image, argv)` leaves,
   `workloadclaims.ArgsDigest`). `BuildConfigClaims` puts both in a
   config-claims extension (operator-keys and seed fields left at the unset
   sentinel — a workload attests only its own identity). (See "Corner 3".)

4. **get-cert binds the claim into the CSR evidence.** The claims DER is folded
   into the attestation `REPORT_DATA` as a domain-separated, length-framed
   transcript
   `SHA-384("c8s/config-claims/v1\0" || framed(csrPubkey) || framed(claimsDER) || framed(challenge))`,
   `framed(x) = uint64-BE(len(x)) || x` (`pkg/attestclient/client.go`
   `reportDataForCSR`). The `/attest` request carries the evidence, the CSR, the
   claims DER, **and** the plain init and main container tuples
   (`{image, args}` per entry) that both `workloadDigest` and
   `workloadArgsDigest` were computed over.

   get-cert **also embeds a second, nonce-free attestation** over the same
   claims — the same transcript with an empty `framed(nonce)` — as
   an RA-TLS attestation extension on the CSR
   (`attestclient.AttestationExtensionForClaims`), the same embed the mesh
   client uses for its leaf. CDS copies that extension onto the issued leaf
   (`internal/issuer/sign.go`), which is what lets a verifier check the leaf's
   config-claims against **hardware evidence** rather than only the CA
   signature. CDS rejects a claims request whose CSR carries no such extension
   (the leaf would be unverifiable). It is nonce-free because the leaf is later
   verified with no per-request nonce (Step 6).

5. **CDS verifies, gates, and embeds.** It folds the *same* claims bytes into
   the expected `REPORT_DATA` and proves them via the attestation-api
   (`VerifyEnforced` — this is what makes the claim TEE-attested, not just
   asserted). Only then does it (a) re-derive **both** role-partitioned
   digests from the forwarded init/main tuples and require them to equal the
   bound `workloadDigest` **and** `workloadArgsDigest` — so neither the
   tuples, nor any argv, nor the init/main split can be swapped — (b) reject
   any non-sentinel operator/seed field, and (c) check **each** image against
   the allowlist store. All pass ⇒ it signs the leaf and stamps the claims
   extension onto it (`internal/cmds/cds/attest.go` `verifyWorkloadClaims`,
   `internal/issuer/sign.go`).

6. **The relying party pins.** Two granularities, same underlying mechanism.
   `c8s verify --workload-image sha256:A --workload-image sha256:B`
   recomputes the image-only set-hash, folds it into the nonce-free
   `REPORT_DATA`, verifies the leaf's embedded RA-TLS evidence (Step 4)
   against that anchor, and checks the recomputed digest equals the leaf's
   attested `workloadDigest`.
   `c8s verify --workload-spec <path-or-@inline>` does the same with a JSON
   document that names each container's image and argv, additionally pinning
   `workloadArgsDigest` when every container's argv is concrete (containers
   with `args: "*"` fall back to image-only for that container). Either pin
   holds only because the leaf carries evidence bound to those exact claims.

---

## Corner 1 — get-cert sends no PID; the kernel reports it

The most common confusion: *how does get-cert tell the broker which process to
look up?* It doesn't. If a caller could name a PID (or pod, or container), a
malicious pod would name a victim's and the binding would be worthless.

Instead, when the broker **accepts** the unix-socket connection, the kernel
attaches the peer's credentials to the socket; the broker reads them with
`SO_PEERCRED`. The PID comes from the kernel's own accounting of who opened the
socket. The chain is entirely kernel/runtime-derived — `SO_PEERCRED` → cgroup →
container → pod — and none of it is caller-supplied.

**PID-namespace subtlety.** get-cert runs in a container where its own PID
might be 1. `SO_PEERCRED` reports the PID *as seen by the reader* — the
nri-image-policy plugin, which runs on the **host** (launched by containerd,
host PID namespace). So the kernel translates get-cert's PID into the host
namespace, and `/proc/<host-pid>/cgroup` on the host resolves to the
container's cgroup. This is why the plugin needs the host PID view and why
`workload_claims.proc_root` is `/proc` (the host's), not a mounted `/host/proc`.

**kata is simpler.** `policy-monitor` serves the *same* unix socket
(`policymonitor/broker.go`), but in a kata guest there is exactly one pod, so
there is nobody to disambiguate: the broker ignores the peer PID and returns
the guest's admitted digests. Peer-cred co-location does not matter here — the
guest boundary *is* the isolation — but reusing the socket lets get-cert dial
one compiled path in both shapes.

---

## Corner 2 — the cgroup resolver picks the *shallowest tracked* container, not the deepest

A container's cgroup path can contain more than one 64-hex component
(CRI-O nests the sandbox ID above the container scope; an attacker can nest a
child cgroup). The resolver returns **all** candidates shallow→deep and the
broker picks the shallowest that is a *tracked container*
(`ContainerIDCandidatesForPID`, `broker.go`).

Why shallowest: a process can only move itself **deeper**, into cgroups it
creates — its runtime-assigned container scope is always an *ancestor* of
anything it nests. So a caller that creates a child cgroup named with a
victim's container ID produces `…/cri-containerd-<attackerCID>.scope/<victimCID>`;
shallowest-tracked resolves to `<attackerCID>` (the caller's own container) and
never to the nested victim. It also skips CRI-O's untracked parent sandbox ID
(it is not a tracked *container*). Taking the last/deepest match — the naive
choice — is the exploitable one.

---

## Corner 3 — the digest is two role sets (init, main), not one flat set

A pod usually has several non-injected containers, including user **init
containers**, which the broker records too (NRI's `CreateContainer` fires for
init and regular containers alike; only the injected `c8s-cert`/`c8s-cert-wait`
are excluded, by name). The broker returns them with their **names**; get-cert
splits them into the pod's init set and main set (using the init-container
names the webhook passes from the pod spec), and `workloadclaims.Digest`
commits to both:
`SHA-256("init\n" || sorted-init-set || "main\n" || sorted-main-set)`.

- **Order-independent *within* a role.** The same images in a different
  container order hash identically, so a reschedule that reorders containers
  does not churn the identity.
- **Role-distinguishing *across* roles.** `{init: A, main: B}` and
  `{init: B, main: A}` produce **different** digests. This is what a flat set
  could not do: where an init container provisions a key or unseals a secret
  into a shared volume before the main container runs, the claim now
  distinguishes "A sets up for B" from "B sets up for A", so an attacker who
  runs the setup image as a long-lived main container fails a verifier pinning
  it as init.
- **Whole-set per role.** You cannot add, drop, or re-role an image without
  changing either digest. A verifier pins with `--workload-init-image`
  (init set) and `--workload-image` (main set) for image-only, or
  `--workload-spec` for image+argv (docs/ratls.md, "The workload commitments").
  One exception weakens this: if the broker cannot resolve an admitted
  container's image digest, it records an empty digest and omits that
  container (logged at error, see `recordForBroker`) — the claim then commits
  a *subset*. A pin-holding verifier still catches the resulting mismatch,
  but the whole-set guarantee does not hold for an image the broker failed
  to resolve.
- **CDS re-derives both role-partitioned digests** from the forwarded init
  and main tuples and checks every image against the allowlist, so the
  leaf's compact hashes are a faithful commitment to exactly those role
  sets — images and argv.
- **Argv is bound alongside the image, per container.** The claim also
  commits a `workloadArgsDigest` — a role-partitioned hash whose leaves are
  `SHA-256(image, argv)` (length-framed at every level so no in-argv byte
  can collide with a distinct tuple; wire preimage in docs/ratls.md, "The
  workload commitments"). Same image with different argv produces different
  leaves and different digests, closing the busybox case where two pod specs
  differ only in `command`/`args`.

The role split is only as trustworthy as the classification source: the
init/main assignment comes from the pod spec, which is control-plane data
(Corner 5). It distinguishes roles *as declared*; it does not by itself defeat
a control plane that misdeclares them.

### Where argv comes from and what it does not bind

Argv rides the same trust chain as the image digest: whoever admits the
container reports it, and the broker binds the caller from the kernel
(Corner 1).

- **node-CVM (NRI)**: `api.Container.Args` on the `CreateContainer` event.
  Containerd has already merged image-config `Entrypoint`/`Cmd` with pod-spec
  `command`/`args` overrides into the exact vector it will pass to
  `execve` — no re-derivation on the broker side.
- **kata (policy-monitor)**: `process.args` from the OCI runtime spec that
  kata-agent writes to `/run/kata-containers/<cid>/config.json` before
  forking init. Also the merged, post-override argv, same shape as NRI's
  field.

Both sources see argv **after** pod-spec overrides applied — so a control
plane that ships `busybox` with `command: [malicious]` produces a broker
record with `args = [malicious]`, and the resulting `workloadArgsDigest`
diverges from an honest workload's without the attacker having to touch the
image.

Argv does **not** bind:

- **env vars.** Accepted risk. Env comes from image config + pod spec +
  downward API + secrets + webhook injection; folding all of it in binds too
  much (rebinding on secret rotation) or too little (only the image-config
  subset). A verifier pinning argv on a shell script whose behavior branches
  on `$X` cannot distinguish two runs with different `$X`. Same limit the
  image-only pin already has.
- **files inside the rootfs.** Trust for rootfs contents comes from the image
  digest (registry-signed), not from argv. argv binds *how* the rootfs is
  invoked, not what's in it.
- **argv[0] conventions.** Some runtimes rewrite `argv[0]` (login shells
  write `-sh`); the commitment is whatever the runtime hands the container.
  A workload that legitimately runs with argv[0] rewriting has its pin
  captured that way.

---

## Corner 4 — first issuance is claim-free; the digest binds at renewal

There is **one cert per pod**, not one per container. get-cert writes it to the
shared `c8s-certs` tmpfs, which the webhook mounts read-only into every
container, so the identity is the pod's — get-cert is just the thing that
fetches and renews it. That sharpens the ordering problem: the pod's single
cert is minted *before the pod's app containers are even admitted*.

The webhook injects `c8s-cert` as a **native sidecar** (an init container with
`restartPolicy: Always`) plus a `c8s-cert-wait` init gate. Kubernetes starts
the sidecar, then `c8s-cert-wait` blocks on the first cert file, and the pod's
**app containers only start after all init containers pass**. So when the pod's
cert is first minted, the app containers **have not been created** — the NRI
plugin has not seen them — and the broker returns an **empty** set.

get-cert handles that distinctly from an error: an empty broker result means
"app containers not up yet," so it issues **without** a workload claim this
round and binds the digests at the next renewal (re-attestation), once the app
is running (`internal/cmds/getcert/run.go` `workloadClaims`). A *broker error*
(unreachable, malformed) is fail-closed — issuance aborts. This is the
"as of issuance, corrected at next renewal" semantics.

**Enforcement is on the verifier, not on issuance.** A relying party pinning
`c8s verify --workload-image` fails closed against a pod that carries no or a
wrong claim — that is where a workload's images are checked. Issuance stays
best-effort by necessity: mandating a claim on every `/attest` would reject the
claim-free first issuance, so the pod's cert never lands, `c8s-cert-wait` never
passes, and the app containers never start — an unconditional deadlock, since
the images the claim needs are exactly what the pending cert is blocking.
Moving enforcement to issuance would first require decoupling app-container
start from cert existence (letting them start and relying on the mesh being
fail-closed for un-carted traffic) — a separate architecture change.

**Staggered starts** can also bind a *partial* set: regular containers start
~together, but a renewal fetch landing mid-startup could commit `{A}` and the
next renewal rebind `{A,B,C}`. The workload digest is only *stable* once every
container is steady-state, so a strict verifier could momentarily fail against
a mid-startup leaf. Hardening this would mean waiting for an expected container
count before binding — a deliberate follow-up, not baked in.

**Init-container eviction churns the init set.** An init container runs to
completion and exits; once the kubelet garbage-collects the exited container,
NRI fires `RemoveContainer` and the node-CVM broker evicts it, so a renewal
after GC rebinds with an **empty init set**. `--workload-init-image` pins are
therefore reliable only until init-container GC — a digest *change* at renewal
here is expected, not tampering. The same expected-container-count hardening
would fix it; not baked in.

---

## Corner 5 — the broker is not control-plane-redirectable, and CDS re-validates regardless

Two independent properties keep a malicious control plane from forging the claim.

**get-cert's broker target is measured, not injected.** get-cert dials a
**compiled** Unix socket path (`workloadclaims.BrokerEndpoint`, selected by
`--workload-claims-broker`) in both shapes — the platform injects only the
read-only socket *mount* (a webhook hostPath on node-CVM, a guest bind-mount
under kata), never the path — so the control plane cannot point get-cert at a
rogue broker by changing an arg. The "point get-cert at an attacker's broker"
vector is closed.

**CDS re-validates the list regardless (defense in depth).** CDS never trusts
the broker or get-cert. It treats the forwarded digest list as an untrusted
proposal and independently checks (a) the list hashes to the evidence-bound
claim, and (b) **every** digest is in the allowlist store. The allowlist — not
the broker — is the invariant, so even a reporter that lied could not smuggle
an unallowlisted image.

This bounds the damage but does not make the pin an identity proof. No
*compromise* is even required: any admitted workload can skip the honest
get-cert→broker path and run the attest flow itself. The attestation-api binds
whatever `REPORT_DATA` the caller asks for, and CDS checks only (a) and (b)
above — never that the claim reflects what the pod actually runs (the
`SO_PEERCRED` binding is enforced by get-cert, and CDS does not re-verify it). So
a malicious pod can assert **any allowlisted image set**, a victim workload's
included, and satisfy `c8s verify --workload-image <victim>`. What still holds:
it can never claim a **non-allowlisted** image, and image *integrity* is
untouched — everything that runs is independently allowlisted by nri-image-policy
/ policy-monitor.

**So the workload pin distinguishes honest workloads only** — it detects an
honest workload drifting from its expected images, not a lying one asserting
someone else's. Making the claim bind what the pod is measured/admitted to run,
enforced at `/attest`, is the real close, and
unimplemented (GAPS §Trust model).

The one surface still on an untrusted path is the **node-CVM** socket mount:
the broker socket sits on a host directory the webhook hostPath-mounts, so a
malicious *allowlisted* pod able to mount that directory read-write could swap
the socket file before get-cert connects. That is a PodSecurity /
filesystem-permission concern (the socket dir must be unwritable by untrusted
pods; overlaps THREAT_MODEL §Addressable), not a redirectable arg — see
the residual note under "Why a unix socket". Under kata the mount is a guest
bind-mount inside the measured VM, so it is not control-plane-supplied at all.

### Why a unix socket, not an HTTP/DNS endpoint

The broker is reached over a **unix socket** (a kernel filesystem path) in both
shapes — never a network/hostname endpoint. That is deliberate; an HTTP
endpoint addressed by name would forfeit three properties:

- **Co-location.** `SO_PEERCRED` works only across a same-kernel socket, so the
  broker get-cert reaches *is provably the one on its own node* — the real
  admission record for this pod (Corner 1). An HTTP call to another
  genuinely-attested node or pod cannot prove co-location: it would pass a
  measurement check yet answer for the wrong pod (the "any attested TEE passes"
  problem). This is also why authenticating the broker's RA-TLS cert would not
  help — a cert proves *measurement*, not that you reached the local broker.
  (Under kata there is one pod per guest, so co-location is free — but reusing
  the socket keeps get-cert on one compiled path in both shapes.)
- **DNS-immunity.** A kernel path has no name-resolution step. Cluster DNS is
  control-plane-configured, so a hostname endpoint would be redirectable
  *regardless of what value is baked in* — baking the name buys nothing. A unix
  socket sidesteps resolution entirely.
- **Non-redirectability.** get-cert bakes the socket path as a compiled
  constant (`workloadclaims.BrokerEndpoint`, in allowlisted/measured code), so
  the control plane cannot change *where* get-cert looks — the platform supplies
  only the socket mount, not the path. A network endpoint would be only as
  fixed as the arg carrying it.

Contrast with how get-cert reaches **CDS**: that *is* a DNS name
(`--cds-url=…svc:8443`), and RA-TLS defuses redirection to a CDS *lacking the
pinned measurement* (`--cds-measurements`). It does **not** bind the CDS's
operator-key governance — get-cert pins measurement only — so a correctly
measured CDS carrying the *wrong* operator keys still completes get-cert's
handshake; that mismatch is caught downstream by an external verifier pinning
the operator key (`docs/ratls.md`), which refuses the pod, not by
get-cert. The pattern: go over the network by name only when you can
authenticate the endpoint's measurement (CDS); stay on the kernel-local socket
when what you need is co-location, which attestation cannot prove (the broker).

The residual left is neither DNS nor attestation: the socket file lives on a
node path, so a malicious *allowlisted* pod that can `hostPath`-mount that
directory read-write could swap the socket before get-cert connects. That is a
PodSecurity / filesystem-permission hardening (the socket dir must be
unwritable by untrusted pods), not more crypto.

Note this is *not* the same as the socket's own permissions. The non-root
get-cert reaches the socket because the broker group-owns it
(`workloadclaims.BrokerSocketGID`, mode 0660) and the webhook puts the sidecar
in that group — that is reachability for the *file*. The swap vector is about
the *directory*: the installer keeps it root-owned and non-world-writable (mode
0711, see the install script), so an untrusted pod still cannot unlink/replace
the socket. Group-owning the socket for liveness does not open the swap.

---

## Corner 6 — what CDS actually trusts (it can't inspect the running container)

CDS cannot independently observe a pod's running image digests — no component
outside the pod can. So how is the claim trustworthy? The chain, weakest link
named:

- **The evidence proves the claim came from inside the TEE**, bound to the
  CSR key and challenge — not that it is ground truth about running images.
- **The code that produced it is get-cert, and get-cert is trusted because it
  is allowlisted/measured, not by fiat.** Under node-CVM the get-cert
  container runs only because nri-image-policy admitted its (allowlisted)
  image; under pod-CVM it is baked into the measured guest. Either way its
  integrity is rooted in the same allowlist/measurement the rest of the
  platform is.
- **The ground truth for "what runs" is the broker** — the admission record —
  not get-cert and not CDS. get-cert is a faithful conduit; the broker is the
  component that actually made the admit decision, so its answer *is* what was
  admitted (Corner 1 binds the caller to the right pod).
- **CDS's own backstop is the allowlist.** It treats the forwarded digest list
  as an untrusted proposal and re-checks every image against the allowlist
  store, so even a compromised reporter cannot smuggle an unallowlisted image
  (Corner 5).
- **But this chain assumes the honest get-cert.** A malicious admitted workload
  can skip get-cert and the broker entirely and assert any *allowlisted* image
  set — CDS re-checks allowlist membership and the list↔claim hash, but nothing
  binds the claim to what the pod actually runs (Corner 5). So this establishes
  trust for an *honest* workload's claim; it does not make the pin an identity
  proof against a lying one. That gap is unimplemented (GAPS §Trust model).

"Did get-cert reach the *real* broker" is no longer a control-plane-supplied
link: get-cert bakes one compiled Unix socket path for both shapes (Corner 5),
so the path is not an injected arg. What remains is the node-CVM socket-file
swap — a PodSecurity / filesystem-permission item, not attestation (and
under kata even that is gone, the mount being a measured guest bind-mount). So
the guarantee rests on trusting get-cert, but that trust is
allowlist/measurement-rooted, with the broker as the source of truth and the
allowlist as the floor beneath it.

---

## Corner 7 — who creates the socket, and why a hostile host can't inject one

A natural challenge: the socket is a filesystem object on the node — what stops
a malicious host from planting its own and answering for the broker?

**First, who actually creates it.** Not the c8s installer. The nri-image-policy
installer DaemonSet only lays down three things on the node: the plugin
*binary* (into `/opt/nri/plugins`), a *containerd drop-in* that registers it as
a pre-installed NRI plugin, and the *runtime directory*
(`mkdir -p` + `chmod 0711`). The socket itself is created at **runtime by the
plugin**: containerd launches it as a node process and `workloadclaims.ListenUnix`
calls `net.Listen("unix", …)` — that syscall materializes the socket. It
`os.Remove`s the path first, so any pre-existing (stale or planted) socket is
deleted before it binds its own. Under kata the same is true of `policy-monitor`
inside the guest. So: **the broker creates the socket, not the installer and not
the host.**

**The reframe that answers the challenge.** The socket is not a root of trust —
it is intra-TCB plumbing between two components that are *both already inside*
the measurement boundary (the broker and get-cert). Its integrity is *inherited*
from that boundary, not established by the socket. Which "host" can subvert it
splits cleanly:

- **The L0 hypervisor — defeated by hardware.** The runtime dir is under `/run`,
  which is **tmpfs (RAM)**, and under SEV-SNP / TDX the guest's RAM is
  hardware-encrypted. The L0 host physically cannot read, write, inject, or swap
  a socket in that memory. Under **kata** this is total: `policy-monitor`
  creates the socket inside the measured guest, there is exactly one pod per
  guest (no co-tenant), and the bind-mount is guest-internal — nothing outside
  the guest can reach it. Under **node-CVM** the whole node is the CVM and the
  socket sits in the node's encrypted tmpfs, so the L0 host is out the same way.
  A guest the host booted with a swapped plugin would not match the launch
  measurement, and CDS refuses to issue against an unpinned measurement.

- **The residual is a co-tenant, not the L0 host** (node-CVM only). The exposure
  is a *malicious allowlisted pod* — inside the node's TCB in the TEE sense, but
  not benign — that can `hostPath`-mount the socket directory **read-write** and
  swap the file. This is a PodSecurity / filesystem-permission problem, the same
  residual as "Why a unix socket" (overlaps THREAT_MODEL §Addressable). It is
  gated by: the dir is **root-owned `0711`** (untrusted pods cannot write it),
  get-cert's own mount is **read-only**, and get-cert dials a **compiled** path
  the control plane cannot redirect. It opens only if PodSecurity lets untrusted
  pods RW-mount host paths. (One nuance: the mount *source*
  `WorkloadClaimsHostDir` is operator-supplied, so a malicious operator could
  point it at a rogue dir — but the operator/webhook runs inside the node-CVM
  and is measured, so this reduces to "is the node's TCB intact", which the node
  launch digest attests. The plugin binary's on-disk integrity rests on the same
  node measurement + allowlist + guest lockdown, not on the socket.)

**And a subverted socket is bounded anyway.** Even granting the co-tenant swap,
get-cert is measured/allowlisted (CDS verifies its evidence) and CDS re-checks
every claimed digest against the allowlist. A rogue broker can never smuggle a
non-allowlisted image or escape the TCB; the worst it achieves is the
honest-workloads-only residual (Corner 5) — claiming *other allowlisted* images.

So the socket is trusted for the same reason everything else on the node is: the
launch measurement (guest under kata, node under node-CVM) and the allowlist —
never because the socket file itself is assumed authentic.

---

## Enablement

Always on for node-CVM: the chart wires the NRI broker socket, the webhook
mount, and the operator flag. get-cert is fail-closed on a broker error, so a
broken nri-image-policy blocks workload cert issuance node-wide — by design.

**Upgrade ordering.** Because get-cert fails closed on a broker error, roll
`nri-image-policy` (which creates the socket and serves the broker) **before or
with** the operator/webhook that injects `--workload-claims-broker`. If the
webhook starts injecting the flag while an old plugin (no broker socket) is
still running — or before the socket's host directory exists for the hostPath
mount — every newly admitted `cw` pod fails cert issuance until the plugin is
current. A chart upgrade that rolls both together is safe; a partial rollout is
not.

(The kata path is not yet chart-wired: the guest image must serve
`policy-monitor`'s broker socket via `--workload-claims-socket-dir` and
bind-mount that directory into pod containers at
`workloadclaims.SidecarSocketDir` before the chart injects
`--workload-claims-broker` for kata pods — a follow-up.) CDS verifies whatever
claims a request carries and stamps them on the leaf; relying parties enforce
them with `c8s verify --workload-image` (Corner 4).

## Audit pointers

| Concern | Where |
|---|---|
| Both digests (image-only + argv), broker protocol, peer-cred + cgroup binding | `pkg/workloadclaims/` (`Digest`, `ArgsDigest`, `containerLeaf`) |
| node-CVM broker (records `api.Container.Args`; shallowest-tracked resolution, eviction) | `internal/cmds/nri-image-policy/broker.go` |
| kata guest broker (records `process.args` from OCI spec; single-pod, same unix socket) | `internal/cmds/policymonitor/broker.go` |
| get-cert fetch → claim → CSR fold (both digests; empty-set handling) | `internal/cmds/getcert/run.go`, `pkg/attestclient/client.go` |
| get-cert leaf-embed (nonce-free attestation over the claims) + CDS guard | `pkg/attestclient/ratls.go` (`AttestationExtensionForClaims`), `internal/cmds/cds/attest.go` (`csrCarriesRATLSExtension`) |
| CDS verify tuple↔claim + allowlist gate + leaf embed | `internal/cmds/cds/attest.go`, `internal/issuer/sign.go` |
| verifier pin | `internal/cmds/verify/` (`--workload-image` / `--workload-init-image` / `--workload-spec`) |
