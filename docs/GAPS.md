# c8s gaps

These are known gaps after the operator consolidation milestone. They are
listed here so demos and reviews do not confuse bootstrap convenience with the
final security model.

## Trust model

- Chart-managed CDS runs as a singleton and keeps the active CA key in memory.
- CDS allowlist persistence is off by default (`cds.persistence.enabled=false`). A restart without a surviving adoption peer resets the served allowlist to the install seed and loses operator-added digests (`c8s allowlist add`) — workloads using them are denied ~30s later. Planned CA-adoption rolls now transfer the complete allowlist in the encrypted handoff snapshot, with a documented concurrent-write race. See `docs/operator.md` "Operator-added allowlist entries across restarts".
- Active/active CDS remains unimplemented. Attested handoff plus a singleton RollingUpdate provides active/standby restart continuity; per-pod EAR keys still block simultaneous serving.
- Application-secret release is not implemented (tracked at [#46](https://github.com/confidential-dot-ai/c8s/issues/46)).
- Per-workload measurement allowlists are not enforced at `/attest` (tracked at [#57](https://github.com/confidential-dot-ai/c8s/issues/57)).
- Allowlist writes are authorized by pinned, long-lived operator public keys (`cds.operatorKeys`), verified at the app layer. Revocation is coarse — no CRL/OCSP, so revoking one operator means removing its key and re-installing. Write tokens are bound to body, method, and path, with a server-enforced 5-minute maximum validity, but carry no `aud`/cluster binding: clusters that pin the **same** operator key accept each other's captured tokens within that window, so pin distinct keys per cluster. Handoff now commits the canonical key-set hash into requester and issuer REPORTDATA and requires an exact match, preventing policy substitution between replicas. The general CDS serving attestation still does not commit this list (or the seed and startup flags), and because the keys are public the handoff commitment is not proof of operator private-key possession. `c8s cds verify` reports pinned-key fingerprints over the attested serving connection. Longer term: commit all startup policy to attested init data and move to a CA + short-lived operator certificates. See `docs/pitfalls.md` and `docs/decisions/2026-07-01-operator-cert-allowlist-write.md`.
- The c8s infrastructure images are not pinned into NRI policy by default (tracked at [#51](https://github.com/confidential-dot-ai/c8s/issues/51)).
- The in-guest CDS allowlist refresh is disabled on every default kata install:
  it fail-closed-refuses to run without `C8S_CDS_MEASUREMENTS`, and no shipping
  path can deliver that pin — baking it is self-referential (CDS runs from the
  same guest image the pin would be baked into, so the value would change the
  measurement it pins) and per-pod cloud-init is host-controlled (a host-chosen
  pin defeats the point). Guests enforce the measured seed plus nothing; operator
  `c8s allowlist add` reaches host-side enforcement and CDS but not running
  guests. Also note the SNP launch digest covers the VMSA set, so even a correct
  pin is per-VM-shape (vCPU count). Candidate fix is operator-signed allowlist
  entries verified in-guest against a baked operator public key.
- **TDX measurement scope is MRTD-only.** The attestation-api surfaces MRTD as
  the normalized `claims.launch_digest`, and c8s applies `policy.Measurements`
  to it just as it applies the same allowlist to SNP LAUNCH_DIGEST. That pins
  the TDX guest's initial contents, but it does not pin RTMR[0..3], including
  the per-workload RTMR[3]. `MinTCBVersion` also remains SNP-only because the
  c8s TDX verify request has no minimum-TCB policy field. Callers must not treat
  an MRTD match as an RTMR or workload-identity verdict.

## Mesh and certificates

- Mesh peer verification checks the CA chain but does not pin peer measurement (tracked at [#47](https://github.com/confidential-dot-ai/c8s/issues/47)).
- Leaf certificates do not embed a verified TEE measurement (tracked at [#47](https://github.com/confidential-dot-ai/c8s/issues/47)).
- SPIFFE-style URI SANs are not implemented (tracked at [#47](https://github.com/confidential-dot-ai/c8s/issues/47)).
- Strict/permissive mTLS modes are not configurable (tracked at [#47](https://github.com/confidential-dot-ai/c8s/issues/47)).
- Per-workload `allowedPeers` policy is not enforced (tracked at [#47](https://github.com/confidential-dot-ai/c8s/issues/47)).
- The in-guest mesh exempts all UID-0 egress so attestation-service can reach
  AMD KDS, so a workload running as root egresses in plaintext and bypasses the
  mesh. Workloads MUST run non-root; the exemption should be scoped to
  attestation-service rather than all of UID 0.

## Image and pod spec

- The NRI plugin gates image digest, not args, env, mounts, capabilities, or
  other pod-spec fields (tracked at [#49](https://github.com/confidential-dot-ai/c8s/issues/49)).

## Confidential GPU

- GPU pods on SNP are pinned to a single vCPU
  (`default_vcpus = default_maxvcpus = 1`) to keep the SNP launch digest
  stable; CPU hotplug cannot raise it at runtime. A deliberate default, not a
  hard limit — any fixed count works if the reference measurement is
  re-predicted (`docs/kata-gpu.md` "Raising the vCPU pin"); TDX needs no pin.
  Note this caps vCPUs, not GPUs: a pod can request multiple GPUs of one
  model (each cold-plugs behind its own PCIe root port, up to
  `kata.gpu.guestImage.pcieRootPort`).
- The `<tag>-nvidia` guest is the c8s rootfs (in-guest stack, locked policy,
  measured, manifest published — parity with the non-GPU guest), but it boots
  **kata's GPU kernel** with the NVIDIA modules/userland grafted from kata's
  digest-pinned GPU rootfs (`kata-guest-base/scripts/build.sh` Step 6): the
  confos kernel has `CONFIG_MODULES=n` and cannot load the driver. Remaining
  hardening: a confos GPU kernel flavor (`CONFIG_MODULES=y` +
  `CONFIG_MODULE_SIG_FORCE=y`, ephemeral build-time key) compiling and
  signing the NVIDIA open GPU kernel modules, replacing the graft — needs
  GPU hardware in CI to validate. Until then the guest locks module loading
  after driver bring-up (`nvidia-gpu-ready.service`,
  `kernel.modules_disabled=1`).
- GPU attestation (SPDM / `nvidia-smi conf-compute`) is not wired — GPU CC mode
  is assumed correct on the host. The locked guest fails closed on a non-CC
  GPU (`nvidia-gpu-ready` refuses and powers the VM off before the kata-agent
  starts; the `-debug` guest tolerates it with a warning), but no positive
  GPU attestation is surfaced to the relying party.
- Host GPU provisioning (vfio-pci binding, GPU CC mode, BAR resize) is out of
  scope — assumed done by the host-provisioning system before c8s installs.
- TEE node labelling is declarative: the install labels kata nodes from the
  operator's `--hardware-platform` flag (`cmd/c8s/tee_label.go`) with no
  verification against host facts — a wrong declaration surfaces only as
  runtime failures. First-class host inventory ("confidential metal") that
  knows and attests each machine's TEE capability at provisioning time is the
  eventual replacement for flag-trusting labels.
- Node-as-CVM GPU is a separate mechanism (drivers baked into the node guest OS,
  measured into the node launch digest); this puller/runtime is pod-as-CVM only.

## Confidential kata guest (TDX)

- **Scratch-disk integrity.** The encrypted image store
  (`scratch-setup.service`) is dm-crypt with no integrity layer. Not an
  app-swap/code-injection vector: the host holds no key so it cannot forge
  chosen plaintext (AES-XTS), a fresh per-boot key plus reformat kills
  cross-boot replay, and the image is digest-verified in-guest before unpack
  (the digest that lands in RTMR[3]). What remains: the host can corrupt
  scratch blocks (a DoS), and unlike the dm-verity root fs the image store is
  verified only at unpack, not continuously at execution — attestation covers
  which image was *deployed*, not that every byte later served off scratch
  still matches it. Close with dm-integrity (authenticated dm-crypt) before
  asserting continuous workload integrity in customer-facing claims or a
  security audit.
- **qemu scratch wrapper is a shim.** Kata has no per-sandbox scratch-disk
  knob, so `kata-guest-base/scripts/kata-qemu-scratch-wrapper.sh` wraps the
  qemu launch to attach the disk (host-config helper, deliberately not wired
  into the build). Follow-up: a first-class attach (kata runtime or a CDI
  device) so disk lifecycle and GC are managed, not wrapper-owned.
- **RTMR[3] workload measurement is write-only today.** The measurer extends
  the register, but no client-side verifier consumes it yet. The extend
  convention is pinned by `pkg/rtmr3` (golden vectors in its tests); the
  eventual verifier MUST build on that package. Multi-image pods extend in
  first-seen order — see `docs/kata-guest-base.md` "Per-workload RTMR[3]
  measurement".
- **Reproducible `root_hash` assumes the host re-lay toolchain.** The
  versions used are recorded in `manifest.json` (`relay_toolchain`) and can
  be pinned fatal via `REPRO_E2FSPROGS_VERSION`/`REPRO_CRYPTSETUP_VERSION`,
  but CI does not pin them yet and the re-lay is not containerized.
- **Attestation trust-model follow-ups** for the TDX workload path:
  client-side DCAP verification, RA-TLS binding of the app channel to the
  attested VM, `/attest` eventlog trim, and the non-public `/verify`
  endpoint.

## Operations

- Chart-managed CDS is not highly available by default. Restart continuity ships via CA adoption + RollingUpdate (active/standby); true active/active is blocked by per-pod EAR signing keys (design: [decisions/2026-07-14-cds-active-active-ear-jwks.md](decisions/2026-07-14-cds-active-active-ear-jwks.md); scope: [decisions/2026-07-14-cds-active-active-scope.md](decisions/2026-07-14-cds-active-active-scope.md)).
- Multi-tenancy isolation has no complete design (tracked at [#56](https://github.com/confidential-dot-ai/c8s/issues/56)).
- Federation and multi-cluster orchestration remain fleet-level concerns.
- No operator↔chart capability handshake: the chart renders webhook-dependent
  features (e.g. GPU class injection) without knowing whether the deployed
  operator binary implements them, so a version-skewed operator silently
  mis-injects. `c8s install` preflights that the operator image *exists* at
  the install tag, but existence is not capability — the handshake (operator
  reports its webhook feature set; the render fails if the chart needs more)
  is not built. See `docs/pitfalls.md` "GPU webhook injection needs an
  operator image that has the GPU code".

## Browser / out-of-cluster verification

- The `c8s cds-attest` sidecar browser-facing endpoints (`/.well-known/c8s/attestation`,
  `handshake`, `tunnel`) and the post-quantum over-encryption channel
  (`pkg/overenc`) are implemented behind the tls-lb nginx front-end (chart flag
  `tlsLb.attest.enabled`); the matching browser client is
  `c8s-verify-js` (contract in `c8s-verify-js/PROTOCOL.md`).
- The sidecar's live evidence path requires `--attestation-api-url`; per-session
  binding of the over-encryption key into a fresh hardware report is enforced
  there. The `--evidence-fixture` path is DEV ONLY (fixed `report_data`).
- The over-encryption binding is identity-bound: `report_data` commits the
  session keys, nonce, exact mesh leaf, and issuing mesh CA, with per-session
  proof of possession of the leaf key. There is no legacy or downgrade binding.
  The proof is ECDSA, so cluster authentication is not post-quantum.
- An optional CDS-issued EAR over the bundle (`ear` field) is defined in the
  contract but not yet populated by the LB.
- The over-encrypted tunnel is not streaming yet. The sidecar buffers each
  sealed request and each upstream response into a single tunnel envelope; HTTP
  chunked transfer from the upstream does not bypass that buffering. Today this
  means uploads are limited by the sidecar's request-record cap and upstream
  responses over 32 MiB fail instead of being forwarded. Large transfers need
  application-level range/chunk APIs or a future streaming tunnel protocol with
  multiple encrypted records.

## Testing / coverage gaps

Measured with `go test ./... -cover`. The packages below stay at low or zero
coverage by necessity, not neglect: their remaining code paths need real
infrastructure (containerd, a cluster, root, raw sockets) or fault injection
that would require adding test seams to production code. They are listed so a
low coverage number is not mistaken for an untested risk that a quick unit test
could close.

- `internal/containerd` (0%) — the tag-to-digest resolver and `StopContainer`
  require a live containerd socket; the concrete `Resolver` exposes no interface
  seam to mock. Needs an integration test against a real/embedded containerd.
- `cmd/get-cert`, `cmd/nri-image-policy`, `cmd/policy-monitor`, `cmd/ratls-mesh`
  (0%) — thin `main()` → `os.Exit` shims; all logic lives in (and is tested via)
  `internal/cmds/*`. Not meaningfully unit-testable.
- `internal/cmds/ratlsmesh` (~49%) — the bulk is Linux-only `*_linux.go` code
  (iptables/ipset, netlink, `SO_ORIGINAL_DST`, raw sockets) requiring root and a
  configured host; only the pure logic and error paths are unit-tested.
- `cmd/c8s` (~42%) — cobra command wiring and the real-listener startup path.
- `internal/version`, `pkg/resources` — declarations only (no executable
  statements), so coverage is not applicable.
- Residual uncovered branches across otherwise well-covered packages: daemon
  ticker/select loops, signal handlers, real-listener `run()` entrypoints, and
  `crypto/rand`/marshal failure branches that cannot be triggered deterministically
  without injecting faults into non-test source.
- Cross-CVM mesh CA handoff cannot be exercised end-to-end on a single-node
  cluster: a CDS on one CVM handing its CA to a **differently-measured** CDS on a
  second CVM, and `/handoff` **rejecting** a peer whose launch measurement is not
  in `cds.measurements`, both need a second, independently-measured confidential
  VM. The measurement-gating logic is unit-tested with synthetic measurements;
  the two-CVM path itself needs multi-node confidential infrastructure in CI.
