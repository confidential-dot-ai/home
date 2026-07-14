# c8s threat model

> **Release:** v0.1.0 · **Milestone:** operator-consolidation · **Last updated:** 2026-07-10 (v0.1.0).
> **Living document** — update it whenever a gate, default, or gap changes; a
> stale threat model is worse than none. Companion docs, treated as the same
> source of truth: `docs/GAPS.md` (the deferred-work register, issue-linked),
> `docs/pitfalls.md` (code-level gotchas), the c8s whitepaper §3 (adversary /
> asset model this section is lifted from), and the c8s-docs `architecture/
> threat-model.mdx` (public framing).
>
> **How this is organised** — following the seven questions every threat model
> should answer: what we protect (§1 Assets), who from (§2 Adversaries), how the
> assets connect (§3 Trust graph), what is enforced (§4 Gates), the threats and
> their status (§5 Catalog — Prevented / Mitigated / Addressable / Open /
> Accepted), what we assume (§6, including supply-chain and external trust
> roots), and what we deliberately do **not** defend against (§7 Non-goals).
> The detailed enforcement narrative — bootstrap mode, production direction,
> browser verification — follows in §8–§10.

---

## 1. Assets — what we protect

In priority order (whitepaper §3.1):

1. **Workload inputs and outputs** — tenant prompts, responses, request/response
   bodies in flight.
2. **Sensitive artifacts** — model weights, datasets, application secrets and
   credentials, workload code.
3. **Intermediate computation state** — KV cache, activations, anything derived
   from (1)/(2) while resident in TEE memory.

Infrastructure assets whose integrity the above depend on:

4. **The mesh CA private key** — signs every workload leaf; held only in attested
   CVM memory, never in a Kubernetes Secret.
5. **EAR issuance integrity** — the attestation tokens that gate CSR signing and
   handoff.
6. **The image-integrity allowlist** and the **launch-measurement reference
   values** — what the platform will admit and attest.
7. **Operator keys** and **per-session channel keys** (RA-TLS leaves, the
   browser over-encryption keys).

---

## 2. Adversaries — who we defend against

The design premise: **the host / infrastructure operator is adversarial, and the
TEE is the trust boundary.** "It works on a normal cluster" is not the bar.

| Party | Trusted? | Capability we assume |
|---|---|---|
| CPU/GPU hardware + firmware (AMD/Intel/NVIDIA) | Trusted (root of trust) | If the silicon vendor is compromised, the guarantees do not hold — this is not zero-trust (whitepaper §9.1). |
| Physical host operator (in its *physical* role) | Trusted | Not to mount memory-bus probing / DIMM substitution / JTAG. The same company is distrusted in its hypervisor role. |
| Code measured into the TEE (guest stack, CDS) | Trusted | Correct iff its launch measurement is pinned by the relying party. |
| Hypervisor / host OS / BIOS / drivers / kubelet / containerd | **Untrusted** | Full control of the node: can read/modify anything outside a CVM, schedule pods, set pod annotations, inject kernel cmdline (§5), serve its own TEE attestation on the pod network. |
| Kubernetes control plane / etcd | **Untrusted** | Sees only ciphertext and public material for the **TEE-held privates** — CDS mesh CA / EAR issuer / handoff signer, RA-TLS leaf keys, browser over-encryption session keys — which never enter etcd. Ordinary Kubernetes Secrets **are visible in plaintext** to whoever reads etcd: image-pull dockerconfigjson (`imagePullSecrets`, `kata.guestImage.pullerAuthSecret`), the webhook TLS `caBundle`, and any tenant workload Secrets. Attestation-gated application-secret release is deferred (§7). CRDs are not security inputs. |
| Pod-network attacker (compromised CNI, malicious sidecar, DNS hijack) | **Untrusted** | Can stand up its own genuine TEE attestation and try to impersonate CDS / a mesh peer at bootstrap. |
| Co-tenant workload | **Untrusted** | Multi-tenant isolation is not yet solved (§7). Node-as-CVM pods are only kernel-isolated. |
| Supply chain — CI (GitHub Actions), ghcr.io, npm/CDN, the fleet GitOps repo | **Partially trusted, unenumerated risk** | Produces the measurements, allowlists, and digests that make attestation meaningful — all from *outside* the TEE. See §5 (Open) and §6. |
| Privileged cluster operator holding a pinned operator key | Trusted with that key | Can rewrite the image-integrity allowlist. Keys are long-lived; revocation is coarse. |
| Out-of-cluster network attacker (browser path) | **Untrusted** | Can terminate outer TLS, run a genuine-but-attacker-operated LB, replay recorded evidence if the client downgrades freshness. |

---

## 3. Trust graph — how the assets connect

Think in dependencies, not a flat list. An edge means "trusts / is vouched for by".

```
  AMD KDS / Intel PCS ─────┐          (external: VCEK, cert chain, CRL, TDX collateral)
  (revocation, TCB info)   ▼
                    ┌─────────────────────────────────────────────┐
                    │ attestation-api  (per node, IN the TCB)      │
                    │  verifies hardware evidence                  │
                    │  ⚠ verdict is UNSIGNED — trust rests on      │
                    │    co-locating this in the same TCB          │
                    └───────────────────┬─────────────────────────┘
                                        │ verdict (signature_valid, report_data_match)
  operator key (pinned, ───┐            ▼
   host-supplied, not yet   │  ┌─────────────────────────────────────────┐
   in CDS's attestation) ───┼─▶│ CDS  (signing key in attested CVM memory)│
  image allowlist ──────────┘  │  EAR issuer + mesh CA signer (one proc)  │
                               └───┬───────────────────────┬─────────────┘
                     signs leaves  │        /handoff CA key │ (gated by cds.measurements)
                                   ▼                        ▼
                             ┌───────────┐            ┌────────────┐
   browser client ──▶ tls-lb │ RA-TLS    │◀──mTLS──▶ │  workload  │  weights / prompts /
   (pins measurement         │ mesh      │            │   (CVM)   │  KV-cache / secrets
    AND mesh CA)             └───────────┘            └────────────┘
                                   ▲ transitive trust: the client verifies the LB (attestation
                                   │ binds its mesh identity); the mesh vouches for its backends

  SUPPLY CHAIN (entirely OUTSIDE the TEE, yet defines what the TEE will accept):
    CI / ghcr.io ─▶ image digests ─▶ bootstrap allowlist (BAKED INTO the measurement)
    c8s-fleet@main ─▶ measurement pins · NRI allowlist · operator keys · digests
    kata build ─▶ unsigned ORAS artifact + prediction inputs ─▶ operator derives / pins launch digest
```

CRDs are not security inputs. `ConfidentialWorkload` is an operator UX/status
surface; a workload can be injected without a CR.

---

## 4. Gates — what is enforced today

| Gate | Enforced by | Source of truth |
|---|---|---|
| TEE evidence is valid | attestation-api and CDS | hardware evidence verification (verdict unsigned — see §6) |
| A CSR can be signed | CDS | EAR JWT, plus `cds.measurements` when configured |
| Image digest is allowed | nri-image-policy | CDS-served allowlist |
| Mesh peer cert chains to the mesh CA | ratls-mesh | mesh CA bundle (chain only; peer measurement **not** pinned — §5) |
| Workload is injection candidate | admission webhook | pod annotation `confidential.ai/cw` |
| LB attestation + session key are TEE-bound | `c8s cds-attest` sidecar | SNP report; the `report_data` transcript commits the session keys, nonce, mesh leaf and issuing CA, with per-session proof of possession of the leaf key (§10). Alternative `SHA-384(serving_leaf_spki \|\| nonce)` (`pq=false`, no PQ tunnel) |
| Inbound traffic to `confidential.ai/cw` pods is mesh-delivered only (**conditional defense-in-depth, not an invariant**) | ratls-mesh (always-on cw inbound guard) | `RATLS-MESH-CW` chain jumped from `FORWARD` position 1 drops all-protocol traffic to cw pod IPs; catches Service-VIP DNAT and excluded-ns sources on the paths where they cross FORWARD. **Preconditions**: kube-proxy in iptables mode (VIP DNAT'd *before* FORWARD), FORWARD hook traversed, `bridge-nf-call-iptables=1`. **Known bypasses**: kube-proxy IPVS/nftables (VIP rewrite in LOCAL_IN/LOCAL_OUT skips FORWARD); CNIs whose datapath skips FORWARD; same-node host-root delivery via `OUTPUT` — the last is inside our host-adversarial scope (§2). Verified paths: iptables-mode kube-proxy with Azure CNI and kubenet. See `cmd/ratls-mesh/README.md` §"Confidential-workload inbound guard". |
| Injection integrity survives webhook downtime | `failurePolicy: Fail` + `cw` label-integrity VAP | API-server-enforced; a pod cannot be admitted unmutated as plain runc |

**Positive controls worth naming** (they are easy to overlook as "just config"):
the mesh cw-inbound guard, the fail-closed webhook + VAP, and CDS self-provisioning
its serving cert via RA-TLS bound to its own SNP measurement. Do not "simplify"
these away.

---

## 5. Threat catalog

Status vocabulary: **Prevented** (attacker cannot, by construction) · **Mitigated**
(reduced, residual noted) · **Addressable** (a real threat *now*, with a committed
or designed fix — "threat today, not tomorrow") · **Open** (real now, no committed
fix) · **Accepted** (deliberate non-goal, §7). Deferred items link `docs/GAPS.md`
rather than restating it.

### Prevented / Mitigated

| Threat | Adversary | Status | Note / reference |
|---|---|---|---|
| Read a workload's memory | host / hypervisor | Prevented | SNP/TDX CVM; `kata-qemu-snp` per-pod attestation. **Only for `confidential.ai/cw` and GPU pods** — the default injected `kata-qemu` class is *not* confidential (see Open). |
| See the unpacked workload rootfs | host | Prevented | guest-pull + `shared_fs="none"`. Default image store is guest tmpfs (RAM). Opt-in for large images (`kata-qemu-scratch-wrapper.sh` attaches a `confai-scratch` disk): the store is a per-boot dm-crypt fs (AES-XTS-plain64, 512-bit random key held only in confidential-guest RAM, never persisted, reformatted every boot), so the host sees only ciphertext on the scratch block device. Host still brokers the network and observes the image ref/layers for anonymous pulls (metadata, not content); on the scratch path, image **integrity** is weaker than the dm-verity root — see §5 Addressable. |
| Substitute a tampered shim / QEMU / guest | host | Mitigated | yields a different launch measurement — caught **iff** measurements are pinned. Components digest-pinned in the chart. |
| Replay a captured operator write-token against a different payload | leaked-token holder | Mitigated | token bound to body (`pbh`), method (`htm`), path (`htu`), 5-min server cap. Residual: no `aud`/cluster binding — clusters pinning the *same* key accept each other's tokens (pin distinct keys per cluster). GAPS §Trust model. |
| MITM the CA-bundle read to inject a trust root | pod-network | Mitigated | `GET /ca` is unauthenticated by design; ratls-mesh accepts a new CA only if signed by an already-trusted CA. Client must chain it through attested evidence, never trust the TLS it arrived over. |
| Host reads container stdout on a locked guest | host | Prevented | locked OPA policy denies `ReadStreamRequest`/`ExecProcessRequest` (`kubectl logs` is empty by design). |
| Compromise CDS ⇒ decrypt past / in-flight traffic | whoever compromises CDS | Mitigated | a CDS-key compromise forges *forward* certs only; it does not decrypt past/in-flight traffic or CVM memory (whitepaper §5.6.3). |
| Impersonate the cluster to a browser client by copying its public mesh leaf / CA chain | allowed-measurement LB / out-of-cluster network | Mitigated | the attestation binding commits the exact mesh leaf and issuing CA into the `report_data` transcript and proves possession of the leaf key per session; there is no legacy or downgrade binding (§10). Residual: the proof is ECDSA (classical). |

### Addressable — threat now, fix planned

| Threat | Adversary | Planned fix | Reference |
|---|---|---|---|
| CDS's host-supplied startup inputs are not in its attestation — a control-plane swap-restart pins attacker-chosen values on any of them: (a) the **operator-keys** ConfigMap (`cds.operatorKeys`); (b) the **allowlist-seed** ConfigMap (`--allowlist-seed`; `internal/cmds/cds/seed.go` additively inserts every digest into the store before the server serves, no operator write-token, no signature); (c) the **CDS pod arguments** themselves (which select the seed path, the op-keys file, `--measurements`, and every other flag). Revocation of op-keys is coarse (no CRL/OCSP). | control plane / host | Commit the operator-key list, the allowlist seed, and the load-bearing CDS startup arguments to attested init data (HOST_DATA/initdata) **in one commit** — closing only one input leaves the swap-restart attack alive on the others. Move op-keys to a CA + short-lived operator certs (`x5c`), CA-based revocation. Interim: `c8s cds verify` surfaces pinned-key fingerprints over the attested serving cert. | pitfalls "Operator key-pinning"; GAPS §Trust model; decision 2026-07-01; #305; `internal/cmds/cds/seed.go` |
| Bootstrap allowlist is baked from whatever the floating `:main` tag resolved to at guest-build time; an unpinned `:main`-everywhere deploy can bake a seed that rejects the deployed CDS. | CI / whoever moves `:main` | Atomic floating-tag promotion (roll `:main`/`:latest` only after Docker **and** kata-guest-base succeed for one commit); `oras pull @digest` for `kata.guestImage`. Runtime mitigation: policy-monitor grow-only CDS refresh. | pitfalls "bootstrap allowlist … floating :main"; #306 |
| In-guest CDS allowlist refresh is **disabled on every default kata install**: policy-monitor fail-closed refuses to run without `C8S_CDS_MEASUREMENTS`, and no shipping path can deliver the pin — baking it is self-referential (CDS runs from the same guest image the pin would be baked into, so the value would change the launch measurement it pins) and per-pod cloud-init is host-controlled (a host-chosen pin defeats the point). Guests therefore enforce the baked seed alone; operator `c8s allowlist add` reaches host-side enforcement and CDS but **not running guests**. Also: the SNP launch digest covers the VMSA set, so even a correct pin is per-VM-shape (vCPU count). Stricter than ratls-mesh (which warns and proceeds on an empty pin) by intent — for the refresh, "any attested TEE" is not enough because the host can boot its own CVM from the same guest image and pass "attested" while serving an attacker-chosen allowlist, and grow-only merging is no defence when additions are the attack. | host / operator drift | Operator-signed allowlist entries verified in-guest against a baked operator public key (candidate design). Interim: the deliberate fail-closed posture — guests enforce the measured seed and nothing else. | kata-image-policy.md; GAPS §Trust model |
| GPU guest boots **kata's** GPU kernel with NVIDIA modules grafted from kata's rootfs — kernel/driver provenance is the kata release, not the c8s build. | supply chain | A steep GPU kernel flavor (`CONFIG_MODULES=y` + `CONFIG_MODULE_SIG_FORCE=y`, ephemeral build key) compiling/signing the NVIDIA modules. Interim: module loading locked after bring-up (`kernel.modules_disabled=1`). | pitfalls; GAPS §Confidential GPU; #292 |
| GPU CC mode is assumed correct on the host; no positive GPU attestation (SPDM / `nvidia-smi conf-compute`) reaches the relying party. | host | Wire SPDM / conf-compute attestation. Interim: locked guest fails closed on a non-CC GPU before the agent starts. | GAPS §Confidential GPU; #55 |
| Mesh peer verification checks the CA chain but does not pin the peer's measurement; leaf certs embed no verified measurement. On **TDX**, `Measurements` and `MinTCBVersion` set by the operator are **silently ignored** (`pkg/ratls/verify.go` `verifyTDXOnline` LIMITATION). | pod-network / co-tenant | Pin peer measurement; wire the TDX measurement/TCB path. | GAPS §Mesh; `pkg/ratls/verify.go:220`; #47 (peer pin), #303 (TDX) |
| In-guest mesh exempts **all** UID-0 egress (so attestation-service can reach AMD KDS) — a workload running as root egresses in plaintext, bypassing the mesh. | root workload | Scope the exemption to attestation-service, not all of UID 0. Workloads MUST run non-root meanwhile. | GAPS §Mesh; #308 |
| Kata guests bake `C8S_MESH_INBOUND_PASSTHROUGH=tcp:8443` so the front-door pods (tls-lb nginx, CDS RA-TLS) reach external certless clients — every kata guest therefore accepts inbound TCP:8443 **without mesh mTLS**, and any workload listening on 8443 in a kata pod is reachable without a mesh client cert. (Parser rejects mesh listener ports and non-tcp entries, and logs an audit line when active.) | pod-network / co-tenant | Per-workload rather than per-image passthrough (front doors in dedicated guests; workload guests rebuild with the variable emptied). | pitfalls "kata guests: inbound TCP port 8443 bypasses the mesh"; GAPS §Mesh and certificates |
| Post-start kill window: policy-monitor SIGKILLs a non-allowlisted container's init *after* kata-agent forks it (single-digit-ms, no network / no user-`execve`). Field regression 2026-07 (fixed): kata-agent's `create_sandbox` does `remove_dir_all` + `create_dir_all` on `/run/kata-containers`, silently detaching the boot-time inotify watch — the monitor logged "active, seed loaded" and made **zero decisions** on any subsequently created sandbox. Now watches in generations (Remove/Rename of the watch dir + periodic inode revalidation → re-Add + re-seed), so the single-digit-ms bound holds again. Any future in-guest watcher of a kata-agent-owned path must handle the same replacement (watch **liveness**, not just existence). | host presenting a bad image | BPF-LSM `security_bprm_check_security` hook (designed, not committed). | kata-image-policy.md G4; pitfalls "kata-agent replaces /run/kata-containers"; #309 |
| TDX per-workload measurement is present but **not consumed by any relying party**: the baked `rtmr3-measurer` daemon extends TDX RTMR[3] with each distinct deployed workload's image digest (`SHA-384("sha256:"+hex)`, dedup keyed on the digest so restarts/replicas do not double-extend the append-only register), but `/attest` does not yet expose a workload-scoped event log, no client-side DCAP verifier gates on RTMR[3], and the RA-TLS app channel is not bound to it. Today RTMR[3] holds a value nothing enforces; policy-monitor's baked-allowlist enforcement remains the only per-workload gate. SNP has no equivalent runtime-extend register — the measurer is TDX-only. Multi-workload pods extend in first-seen scan order (unstable across runs), so a verifier must account for ordering or the deployment stays one workload image per sandbox. | — (capability gap) | Trim the `/attest` event log to workload extends, wire client-side DCAP verification of the trimmed log, bind the RA-TLS app channel to the attested VM's RTMR[3]. | `internal/cmds/rtmr3measurer`; kata-guest-base `rtmr3-measurer.service` |
| Opt-in scratch disk for large-image kata workloads (dm-crypt AES-XTS-plain64, ephemeral per-boot key, backing `/run/kata-containers/image` when attached via `kata-qemu-scratch-wrapper.sh`) has **no integrity layer**. The host holds no key and the key is fresh per boot, so chosen-plaintext forgery and cross-boot replay are prevented; the image is digest-verified in-guest at unpack and that digest is what lands in RTMR[3]. What remains: (a) the host can corrupt scratch blocks (DoS), and (b) unlike the dm-verity root, image bytes are **not** re-verified at read — attestation covers *which image was deployed*, not *that every byte later served off scratch still matches it*. Small-image tmpfs path unaffected. | host | Authenticated dm-crypt (dm-integrity under dm-crypt) so host tamper of scratch blocks fails cryptographically at read. Do not claim continuous workload integrity in customer-facing statements meanwhile. | kata-guest-base `extra/usr/local/lib/c8s/scratch-setup.sh` |
| No operator↔chart capability handshake — a version-skewed operator silently mis-injects webhook-dependent features. | operator/chart skew | Operator reports its webhook feature set; render fails if the chart needs more. Interim: install preflights that the operator image *exists*. | GAPS §Operations; #310 |
| **CRL revocation is fail-open by default** (`attestation-service require_crl=false`); the in-process Go SNP path does no revocation check at all. A network adversary who blackholes the AMD CRL gets a revoked VCEK accepted. | network adversary | Ship `require_crl=true` by default / enforce revocation on the in-process path. | attestation-service `config.rs`; attestation-go; #301 |
| **Browser WASM verifier enforces fewer checks than the Go/Rust server verifiers** — `verify_snp` omits VMPL==0, debug-policy rejection, min-TCB, VEK validity, and CRL. A browser client would accept a DEBUG-enabled or non-VMPL-0 guest (host can read enclave memory) if its measurement is allow-listed. | LB operator / host | Bring the WASM `snp` path to parity with `verify_evidence`. | c8s-verify-js; attestation-wasm; #302 |
| **SMT- and migration-enabled guests are accepted** (`GuestPolicy{SMT:true, MigrateMA:true}`). SMT exposes cross-thread side channels; MigrateMA accepts live-migratable encrypted VMs. | host | Pin the guest policy (reject SMT / MigrateMA) or record an explicit accept. | attestation-go `validateOptions`; attestation-rs `snp/verify.rs`; #301 |
| Image policy gates the image *digest* only, not args/env/mounts/capabilities/pod-spec. | whoever controls the pod spec | Extend the NRI plugin to pod-spec fields. | GAPS §Image and pod spec; #49 |
| No image signing / SLSA / provenance anywhere; trust is digest-pinning only. A compromised Actions run or ghcr.io push could inject a component that attestation accepts once its digest is promoted/baked. | CI / registry | cosign/notation signing + SBOM (named as future work in deployment-scripts T21). | §6 supply-chain assumptions; #307 |

### Open — threat now, no committed fix (posture decisions)

| Threat | Adversary | Note |
|---|---|---|
| **An operator forgets to pin measurements.** `cds.measurements` and `ratlsMesh.measurements` ship empty, and the RA-TLS handshake then accepts *any* peer that produces a syntactically valid TEE attestation. An attacker who serves their own TEE attestation on the pod network can stand in for CDS at the bootstrap moment. | pod-network | **By design the operator must choose their measurements** — empty is not a bug, it is "pin nothing yet." **Mitigation**: both CDS and ratls-mesh log loud warnings when their allowlists are empty (including ratls-mesh host and in-guest modes), and ratls-mesh publishes `ratls_mesh_measurement_pinning=0` for alerting. **Real residual**: the shipped fleet overlays (`c8s-fleet` `hr.yaml`) leave these unset, so a GitOps "production" deploy runs accept-any unless the operator pins — an operational default, not a code gap. |
| The c8s-fleet GitOps repo is a co-equal trust anchor outside the TEE: a merge to `main` rewrites measurement pins, the NRI allowlist, operator keys, and image digests for every cluster. | fleet committer / compromised GitHub App | Access control reduces to git branch protection + the Flux GitHub App. Not currently modeled; the allowlist and promotion pipelines (CI + bot PATs + tag→digest resolution) are additional attack surface. |
| The default injected `kata-qemu` class (for un-annotated pods) provides VM isolation but **not** confidentiality — the host can read the pod's memory. Base install mode gives no per-pod confidentiality at all. | host | "Pod-as-CVM" is opt-in via `confidential.ai/cw` or a GPU request. Document so the "injection candidate" gate is not read as "everything is confidential." |
| Namespace exemptions (release ns, `kube-system`, `kube-public`, `kube-node-lease`) bypass injection and kata enforcement; `kube-system` also skips image policy. Host-namespace pods are exempt with no PSA floor, so any user with create-pod RBAC opts out via `hostNetwork:true`. | tenant with pod-create RBAC | RuntimeClass enforcement is a guardrail, not a boundary; the actual boundary is per-pod attestation. A cluster-wide PodSecurityAdmission floor is required to close the host-namespace bypass (#311). |
| `CopyFileRequest` is allowed by the guest OPA policy — the untrusted host can write files into a running guest (not path-scoped). | host | Deliberate deviation (`default-policy.rego`), but an in-guest attack surface worth stating. |
| A running external service mesh (Istio/Linkerd) alongside c8s injects **un-attested** proxies into the confidential path and breaks the model. | operator misconfig | Do not run a second mesh (c8s-docs limitations). |

### Escape hatches to keep out of production (Open, gated by warnings only)

`--evidence-fixture` (cds-attest serves fixed `report_data`, DEV ONLY), the `-debug`
guest variant (host `Exec`/`ReadStream`/`WriteStream` RPCs allowed), `--ratls-platform
""` (plaintext CDS), attestation-service `allow_debug=true` and empty `api_keys`
(unauthenticated `/verify`,`/attest`), and the c8s-verify client freshness
downgrade (`requireFreshness=false`, for recorded-evidence demos; the policy
always requires a non-empty measurement allowlist and a mesh-CA pin, §10). Each
is warned but not gated out of release builds; the freshness downgrade returns
`ok:true` with `warnings[]`, so **the embedding app must inspect `warnings[]`**
or the guarantee is void. Stock kata-guest-base builds now bake an empty `ghcr-auth.json`
(`{"auths":{}}`) — the c8s images are public, so anonymous guest-pull is the
default; a private-mirror build (pre-staged file) still bakes credentials into
the dm-verity root, so rotating them moves the launch measurement.

---

## 6. Assumptions

If any of these is false, the corresponding guarantee does not hold.

**Internal:**
1. **attestation-api is co-located in the same TCB and its `/verify` verdict is
   trustworthy** — the verdict is *unsigned* (`pkg/ratls/verify.go`), so whoever can
   MITM/impersonate the attestation-api URL forges "valid". This underpins the entire
   evidence gate.
2. The operator has pinned measurements where confidentiality matters (see §5 Open).
3. Operator private keys are custodied out of band (vault / HSM / hardware token);
   the pinned-key ConfigMap is host-supplied and not yet attested.
4. Guest RNG derives from the CPU (`RANDOM_TRUST_CPU`, no host virtio-rng); session
   keys, X25519/ML-KEM ephemerals, and the mesh CA key all draw from it.
5. The browser client supplies **both** a non-empty measurement allowlist and the
   mesh CA out of band; these pins plus the identity-bound attestation transcript
   authenticate the cluster. The only downgrade is `requireFreshness=false`
   (recorded-evidence demos), reported in `warnings[]` (§10).

**Supply-chain and external trust roots (load-bearing here):**
6. **Hardware root of trust** (AMD/Intel/NVIDIA) is sound — if the manufacturer is
   compromised the guarantees fail (not zero-trust). `attestation-{go,rs}` bundle the
   AMD ARK/ASK roots at build time; rotating a root means rebuilding every verifier
   (incl. the browser WASM).
7. **AMD KDS / Intel PCS** are reachable and authentic; stale-cache windows and the
   CRL fail-open default (§5 Addressable) are the residual.
8. **Kata reference measurements are operator-supplied, not signed or published by
   the build.** The shipped path is measured direct-kernel boot: steep compiles the
   bare `vmlinuz`, Kata osbuilder produces the dm-verity rootfs, and the launch digest
   covers OVMF + kernel + the exact Kata command line (including the verity root hash)
   + the boot-time VMSA set. The digest covers boot state only: the writable
   `/run` tmpfs, the in-guest-pulled workload images (tmpfs or the opt-in dm-crypt
   scratch store), and host-supplied runtime inputs (per-pod cloud-init user-data,
   `CopyFileRequest` writes) are not measured. `manifest.json` carries artifact
   hashes and prediction inputs, but no launch digest; the workflow publishes it
   with unsigned `oras push`.
   An operator must derive the digest separately with `sev-snp-measure` and supply it
   to the relevant verifier/chart allowlists, which default to empty. The build
   inputs are pinned, but the rootfs is not yet bit-for-bit reproducible
   (mkfs.ext4 writes a random UUID and timestamps), so an independent rebuild
   cannot corroborate the published verity root hash or launch digest; the
   per-build digest must be pinned as published. Build and pinning mechanics:
   `docs/kata-guest-base.md`.
9. **Host provisioning is correct and is not verified by c8s** — SNP enabled in
   BIOS/firmware, GPU CC mode on, vfio-pci binding clean, node labels honest
   (`--hardware-platform` is trusted, not probed). The node-level kata/containerd
   install (kata-deploy, sandbox-device-plugin) is privileged host-root and is
   **not** in the measured TCB — it is trusted operationally.
10. **CI and the fleet GitOps repo are trusted** to produce and distribute the guest
    artifacts, allowlists, image digests, and operator-supplied measurement pins that
    make attestation meaningful (§5 Open). The pinned upstream Kata runtime, its
    selected OVMF, and the confidential org's runners are supply-chain dependencies
    for the shipped direct-kernel boot path; an IGVM-for-QEMU patch is not
    load-bearing on this path. The node-as-CVM shape boots via upstream QEMU's
    IGVM support, a separate path not modeled here.

---

## 7. Non-goals

### Deferred this milestone (tracked, expected to close — see `docs/GAPS.md`)

- Pod-spec integrity beyond image digest; per-workload peer allowlists and measurement
  pinning in the mesh; attestation-gated application secret release (the whitepaper's
  Secrets Manager Proxy / wrapped-vs-direct key brokering); active/active CDS HA;
  multi-tenant isolation and federated multi-cluster control planes. Each has a
  tracking issue in GAPS.md — this list is intentionally a pointer, not a copy.

### Accepted / permanent non-goals (whitepaper §3.4, §9)

- **Side-channel attacks** (micro-architectural, timing, power). Note SMT-enabled
  guests are accepted today (§5 Addressable) which widens this surface.
- **Denial of service / availability** — a host can always refuse to schedule or
  can kill a CVM; we protect confidentiality and integrity, not uptime.
- **Application-layer vulnerabilities** in the tenant workload itself.
- **Application-layer extraction** — model distillation, dataset reconstruction from
  legitimate query access.
- **Physical attacks** — memory-bus interposers, DIMM substitution, JTAG (TEE.Fail
  2025, Battering RAM 2025, BadRAM 2024). Covered by the physical-host trust
  assumption in §2.
- **A compromised hardware manufacturer** — see §6(6).

---

## 8. Chart-managed bootstrap mode

The chart installs a self-contained certificate path served by a single CDS
binary:

- CDS verifies evidence and issues EAR tokens.
- CDS signs workload CSRs in-process with a chart-managed mesh CA generated
  inside CDS process memory. EAR validation and CSR signing happen in the same
  process, so there is no internal RA-TLS hop and no JWKS fetch between
  components.
- The default chart path does not store the mesh CA private key in a Kubernetes
  Secret or persistent volume. The persisted public CA bundle preserves
  verification of already-issued leaves across CDS restarts; it does
  not preserve issuance — a restart generates a new CA key, and workloads
  must re-bootstrap to trust new leaves. See docs/operator.md for the
  singleton-vs-handoff trade-off.
- The chart does not mount handoff private keys from Kubernetes Secrets.
  Attested CA handoff is in-process: CDS self-provisions its handoff signer EAR
  (signer key generated at startup, minted by its own EAR issuer — no external
  service to dial). It is opt-in via `cds.handoff.enabled=true`, which
  authorises peers whose launch digest is in `cds.measurements`; the chart
  fails to render if measurements is empty while handoff is enabled.
- `GET /ca` serves the public CA bundle without EAR authorization
  so ratls-mesh can poll trust anchors after its initial trust seed is
  established from the authenticated certificate issuance response.
  Chart-managed ratls-mesh accepts CA bundle updates only when each new CA is
  signed by an already trusted CA, so unauthenticated bundle reads cannot add
  unrelated trust roots. This is an acceptance path only: nothing currently
  produces such replacement bundles (§9).
- CDS's allowlist writes (`POST`/`PUT`/`DELETE /allowlist`) are authorized by an
  operator key whose public half is pinned in `cds.operatorKeys`, verified at the
  application layer (not TLS mTLS — the listener stays RA-TLS). The `c8s
  allowlist` CLI mints a short-lived JWT signed with the operator private key,
  carrying a `pbh` claim equal to base64url(SHA-256(request body)); CDS verifies
  the signature against its pinned keys and re-hashes the body against `pbh`
  before mutating. A captured token cannot be replayed against a different payload within
  its TTL. Anyone holding a pinned operator key can rewrite the image-integrity
  control. Keys are long-lived and CDS consults no CRL/OCSP, so revoking an
  operator means removing its public key from `cds.operatorKeys` and
  re-installing; protect operator keys accordingly. The pinned-key list is
  host-supplied config, read only at CDS start and not yet in CDS's attestation —
  an interim tradeoff, see `docs/pitfalls.md` (§5 Addressable).
  With `cds.operatorKeys` unset, writes are rejected and only reads are served.
  See `docs/decisions/2026-07-01-operator-cert-allowlist-write.md`.

### Endpoint surface (beyond the gates in §4)

- **`/attest`** enforces the `cds.measurements` launch-digest allowlist before
  issuing a leaf. **`/attest-key`** issues a TEE-bound EAR (no cert) for a
  caller-generated key — used by in-cluster components (CDS's handoff signer) — and
  is `protected` (requires valid TEE attestation) but **does not** consult
  `cds.measurements`. This asymmetry is intentional for in-cluster self-attestation;
  it means measurement pinning does not constrain this route. (Flagged for review —
  confirm whether `/attest-key` should also honor `cds.measurements`.)
- Unauthenticated reads: `GET /ca`, `GET /operator-keys`, `/.well-known/jwks.json`,
  `GET /allowlist`, `/healthz`, `/readyz`, `/metrics`. `/authenticate` is
  unauthenticated and mints an in-memory challenge (single-instance; lost on restart).
  None expose private material, but the served allowlist, CA bundle, and operator-key
  fingerprints are readable by anyone who reaches CDS and accepts its cert.

### Measurement pinning defaults

By default the chart pins no measurements. Two values control measurement
pinning and both ship empty:

- `cds.measurements`: the flat allowlist of SHA-384 hex launch digests
  permitted to call `/attest` and (when handoff is enabled) `/handoff`.
  Empty = no pinning, accept any TEE-attested caller.
- `ratlsMesh.measurements`: the launch digests mesh peers must present on
  RA-TLS handshakes (wired to ratls-mesh `--measurements`). Empty = accept any
  TEE-attested peer. CDS's RA-TLS peer cert is pinned separately, from
  `cds.measurements` (wired to `--cds-measurements`).

With both empty, the chart's RA-TLS handshakes accept any peer that
produces a syntactically valid TEE attestation. **The operator chooses these
values — empty means "not pinned yet", not a defect.** An attacker who can serve
their own TEE attestation on the cluster Pod network (compromised CNI,
malicious sidecar, DNS hijack) can stand in for CDS at the bootstrap moment.
Both CDS and ratls-mesh log loud warnings for empty measurement policies;
ratls-mesh also publishes `ratls_mesh_measurement_pinning=0` for alerting. These
signals do not make the accept-any policy safe: pin both values in production.

The chart sets `cds.sanValidation=false` because under chart routing CSRs
arrive without a matching TCP source IP, so CDS cannot compare the CSR node IP
SAN to the workload's TCP source IP. DNS SAN and CN validation still run; DNS
SANs are rejected unless explicitly allowed. Scheduled CA rotation is not wired:
chart-managed CDS generates one CA in process memory at startup. A process restart
generates an unrelated CA and requires mesh re-bootstrap; no `internal/issuer.CARotator`
production caller currently creates or publishes replacement bundles.

This is acceptable for demos, development, and environments that deliberately
place CDS inside the intended trust boundary. It is not the final whitepaper
production model by itself: chart-managed CDS still needs to run inside the
intended attested trust boundary, and measurement pinning is an explicit
configuration choice.

## 9. Production direction

The CDS-shaped model uses a signing key generated and held inside attested CVM
memory. Replicas join through attested key handoff. The Kubernetes control
plane only sees ciphertext and public material.

In that model:

- the mesh CA private key is not stored in Kubernetes Secrets;
- new replicas receive CA signing material only after both sides validate EAR
  measurements allowed for handoff. The signature chain is
  transitive: each EAR carries a `tee_public_key` (ECDSA), and that key
  signs a transcript including the ephemeral X25519 KEM public key. The
  X25519 key is therefore bound to the EAR via the ECDSA proof-of-possession,
  not directly;
- **scheduled CA rotation is a design target, not yet wired** — the
  `internal/issuer.CARotator` type exists but has no production caller; only the
  EAR signing-key rotator runs today. (Corrected: earlier text implied CA rotation
  already runs inside the active signer.)
- allowlists and policy are signed by an operator-held key. (The whitepaper's
  fuller design has CDS signing a Kettle-attested image manifest; Kettle is not
  shipped — today the operator key signs JWT write-tokens, not the manifest.)
- secret release is gated by workload attestation (designed; see GAPS §Trust model);
- recovery from total CDS outage means re-bootstrap and re-issue certificates.

### CDS is a stateful singleton until handoff is enabled

**Shipped today: a single-replica singleton.** (The whitepaper's target is an
active/active pair; this doc describes the present tense.) The CA private key
lives only in the running CDS process memory. A single-replica restart (Helm
upgrade, node drain, OOMKill, HPA replacement) generates a fresh CA whose public
key is not signed by anything ratls-mesh already trusts; the continuity check in
`pkg/ratls/cdsclient.continuityCABundle` rejects it, and every workload
must re-run initial CDS provisioning to converge.

The handoff endpoint (`/handoff`) closes this when the chart enables
`cds.handoff.enabled=true`: CDS generates an ECDSA handoff signer key in
process at startup and self-provisions its EAR via its own EAR issuer (no
external service to dial). No operator key file or Kubernetes Secret is
involved (the alternative — mounting a Secret-backed PEM — would put
CA-adjacent material into etcd, which the design forbids). Active/active
deployments can then handoff the active CA key to a joining replica without
re-issuing workload certs.

Until the operator turns handoff on, run CDS with `replicas: 1`
and `strategy: Recreate` (the chart defaults), guard it with a PDB, and
treat any restart as a planned re-bootstrap event. To turn handoff on,
set `cds.handoff.enabled=true` and pin `cds.measurements` to CDS's launch
digest — the same flat allowlist authorises `/handoff` (setting
handoff.enabled without measurements fails chart render). Then scale up
freely.

## 10. Browser / out-of-cluster verification (c8s-verify)

The `c8s cds-attest` sidecar (proxied by the tls-lb nginx front-end) exposes a browser-facing surface over plain HTTPS so an
out-of-cluster client (the `c8s-verify-js` library, or `TEErminator`) can verify
the Load Balancer's TEE measurement and cluster identity, and open a
post-quantum over-encrypted channel to its enclave.
The wire contract is `c8s-verify-js/PROTOCOL.md`.

- `GET /.well-known/c8s/cds-cert.pem` — unauthenticated discovery for the mesh
  CA / LB cert chain. The verifier does not trust this standalone response; it
  verifies the exact chain committed by the attestation bundle.
- `GET /.well-known/c8s/attestation?nonce=`
  — raw SEV-SNP evidence whose domain-separated `report_data` transcript commits
  the X25519 and ML-KEM-768 session keys, 32-byte client nonce, exact mesh leaf,
  and issuing mesh CA. The leaf also signs the transcript, proving possession
  of the corresponding private key. The client verifies the hardware signature,
  a non-empty launch-measurement allowlist, the transcript, the leaf chain to a
  pinned mesh CA, and the proof signature before deriving the channel. Copying
  a victim cluster's public certificate chain is insufficient without its leaf
  private key. There is no legacy or downgrade binding. A separate binding mode
  exists
  (`?pq=false`, `report_data = SHA-384(serving_leaf_spki || nonce)`) where the
  attestation commits to the LB's outer TLS leaf instead of an over-encryption
  key, supplying the SPKI binding but no PQ tunnel — a different trust decision.
  It authenticates a cluster only if the client also validates the served leaf
  against a cluster-specific anchor (e.g. chains it to the pinned mesh CA).
- `POST /.well-known/c8s/handshake` + over-encrypted application records —
  X25519 + ML-KEM-768 → HKDF-SHA256 → AES-256-GCM (`pkg/overenc`). The **entire**
  request is sealed — method, path, headers, and body — so a TLS-terminating proxy
  in front of the LB sees no path or `Authorization` header, and cannot read or
  forge application traffic even though it terminates the outer TLS. The channel
  terminates inside the LB CVM.

The tls-lb nginx serves the static `cds-cert.pem`/`mesh-ca.pem` and reverse-proxies the dynamic `/.well-known/c8s/` paths to the sidecar on loopback.

Trust is transitive from the identity-bound LB: the user verifies the
LB measurement and pinned cluster identity; the verified LB implementation uses
the in-cluster RA-TLS mesh for backend pods. **The client must pin both a non-empty
measurement allowlist and the mesh CA** — a measurement alone proves "genuine
audited code on real silicon", not "*my* cluster". The proof uses ECDSA, so cluster
authentication is classical. X25519 + ML-KEM-768 provides hybrid session-key
confidentiality; this path does not claim post-quantum authentication.

**Client-side responsibilities** (all supplied out of band by
the embedding app): the SDK **fails closed** with a typed error taxonomy
(`nonce_mismatch`, `report_data_mismatch`, `measurement_denied`, `invalid_cert`,
`identity_binding`, …). The policy rejects an empty measurement allowlist, a
missing `meshCaPem`, and any version or binding other than the identity-bound
ones above. The only downgrade is `requireFreshness=false` (recorded-evidence
demos), which reduces the freshness check to a `warnings[]` entry the embedding
app must inspect. The WASM verifier's bare-`snp` path also omits several checks the
Go/Rust verifiers enforce (§5 Addressable). Distributing a JS/WASM verifier over
npm/CDN means the origin that ships the SPA also ships the verifier, and the PQ half
rides a pre-1.0 `mlkem-wasm` dependency — supply-chain trust roots for this path.

The sidecar's `--evidence-fixture` flag serves recorded evidence for demos/tests and is
**DEV ONLY**: its `report_data` is fixed and does not bind a live session key, so
clients must run with freshness enforcement downgraded. Production uses
`--attestation-api-url`, where each session gets a fresh report bound to its
key and nonce.
