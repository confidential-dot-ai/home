# c8s gaps

These are known gaps after the operator consolidation milestone. They are
listed here so demos and reviews do not confuse bootstrap convenience with the
final security model. Each bullet links to the tracking issue.

## Trust model

- Chart-managed CDS runs as a singleton and keeps the active CA key in memory (tracked at [#18](https://github.com/confidential-dot-ai/c8s/issues/18)).
- Active/active CDS replica handoff is opt-in via `cds.handoff.enabled`; it is off by default (tracked at [#18](https://github.com/confidential-dot-ai/c8s/issues/18)).
- Application-secret release is not implemented (tracked at [#46](https://github.com/confidential-dot-ai/c8s/issues/46)).
- Per-workload measurement allowlists are not enforced at `/attest` (tracked at [#57](https://github.com/confidential-dot-ai/c8s/issues/57)).
- Allowlist writes are authorized by pinned, long-lived operator public keys (`cds.operatorKeys`), verified at the app layer. Revocation is coarse — no CRL/OCSP, so revoking one operator means removing its key and re-installing. Write tokens are bound to body, method, and path, with a server-enforced 5-minute maximum validity, but carry no `aud`/cluster binding: clusters that pin the **same** operator key accept each other's captured tokens within that window, so pin distinct keys per cluster. The pinned-key list is host-supplied config, read only at CDS start; `c8s cds verify` now reports the pinned-key fingerprints (fetched from `GET /operator-keys` over a connection bound to the attested serving cert), but the list is still not committed to CDS's attestation (HOST_DATA/initdata) — a verifier sees what CDS claims, not what was measured. Longer term: a CA + short-lived operator certificates (single-file cert+key credentials, CA-based revocation). See `docs/pitfalls.md` and `docs/decisions/2026-07-01-operator-cert-allowlist-write.md`.
- The c8s infrastructure images are not pinned into NRI policy by default (tracked at [#51](https://github.com/confidential-dot-ai/c8s/issues/51)).

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
  steep kernel has `CONFIG_MODULES=n` and cannot load the driver. Remaining
  hardening: a steep GPU kernel flavor (`CONFIG_MODULES=y` +
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

## Operations

- Chart-managed CDS is not highly available by default (broker side tracked at [#75](https://github.com/confidential-dot-ai/c8s/issues/75)).
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
  `cds-cert.pem`, `handshake`) and the post-quantum over-encryption channel
  (`pkg/overenc`) are implemented behind the tls-lb nginx front-end (chart flag
  `tlsLb.attest.enabled`); the matching browser client is
  `c8s-verify-js` (contract in `c8s-verify-js/PROTOCOL.md`).
- The sidecar's live evidence path requires `--attestation-api-url`; per-session
  binding of the over-encryption key into a fresh hardware report is enforced
  there. The `--evidence-fixture` path is DEV ONLY (fixed `report_data`).
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
