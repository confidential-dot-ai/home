# c8s

[![CI](https://github.com/confidential-dot-ai/c8s/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/confidential-dot-ai/c8s/actions/workflows/ci.yml)
[![License: AGPL-3.0](https://img.shields.io/badge/License-AGPL--3.0-blue.svg)](LICENCE)

**c8s is confidential Kubernetes.** It runs Kubernetes workloads inside
hardware-backed Trusted Execution Environments, so that the data they process
(model weights, prompts, responses, datasets, credentials) stays encrypted in
memory the entire time it is in the cluster, and that property is
cryptographically provable to a third party over the network.

Encryption at rest and in transit are solved problems. Encryption **in use**
is not: the moment a workload runs, its secrets sit in plaintext memory,
readable by whoever operates the machine underneath it. Confidential computing
closes that gap. Modern CPUs (AMD SEV-SNP, Intel TDX) can run a virtual
machine whose memory is encrypted with keys held by the hardware, measure
exactly what booted into it, and sign that measurement so a remote party can
verify it. The infrastructure operator, the hypervisor, and the Kubernetes
control plane no longer need to be trusted: they schedule the workload, but
they cannot see inside it.

c8s applies that model to Kubernetes end to end, following five principles at
every layer:

1. **Encrypt the runtime.** Workloads run in hardware-encrypted memory.
2. **Measure the code.** The hardware computes a launch digest over exactly
   what booted.
3. **Bind identity to measurement.** Certificates issue only after the
   measurement verifies.
4. **Verify before connecting.** Peers require attestation-rooted identity
   before any traffic flows.
5. **Secure the egress.** All traffic is encrypted to verified destinations.

c8s is built by [Confidential AI](https://confidential.ai) as the substrate
for private AI: inference, fine-tuning, training, and agents where the
infrastructure operator never sees the data. The platform itself is
workload-agnostic: anything that runs on Kubernetes can run confidentially.

## Links

- [confidential.ai](https://confidential.ai), the company behind c8s
- [Documentation](https://confidential.ai/docs/c8s), the full user-facing docs
- [Whitepaper](https://confidential.ai/docs/whitepapers/c8s), the c8s architecture paper (also on [arXiv](https://arxiv.org/abs/2604.26974))
- [Setting up a confidential VM](https://confidential.ai/docs/c8s/tutorials/azure-e2e), an end-to-end tutorial from bare cloud account to verified confidential workload
- [c8s-verify](https://github.com/confidential-dot-ai/c8s-verify-js), verify a c8s cluster from a browser
- [attestation-rs](https://github.com/confidential-dot-ai/attestation-rs), the TEE evidence verification service c8s uses
- [Threat model](docs/THREAT_MODEL.md), what c8s defends against and what it assumes

## Features

- **Hardware-attested workload identity.** The Certificate Distribution
  Service (CDS) verifies TEE attestation evidence (AMD SEV-SNP, Intel TDX) and
  signs workload certificates with a mesh CA whose key never leaves the TEE.
  No verified measurement, no certificate.

- **RA-TLS mesh.** A transparent L4 proxy wraps traffic between workloads in
  mutual TLS rooted in hardware attestation. Plaintext never crosses the pod
  boundary.

- **Two confidential shapes.** Run the whole node as one confidential VM
  (node-as-CVM), or run every pod as its own confidential VM (pod-as-CVM, via
  Kata Containers). See [Architecture](#architecture).

- **Measured boot end to end.** Node images boot via IGVM with dm-verity;
  confidential pods boot a sealed guest image whose launch digest covers the
  entire in-guest security stack.

- **Container image allowlisting.** Every image is enforced against a
  CDS-served digest allowlist: an NRI plugin on the host in base mode, an
  in-guest `policy-monitor` under Kata, where the host cannot tamper with it.

- **Fail-closed admission.** A mutating webhook injects certificate sidecars
  and Kata RuntimeClasses; a ValidatingAdmissionPolicy rejects anything that
  escapes injection. The bootstrap ordering fails closed, never open.

- **Confidential GPUs.** NVIDIA GPU passthrough into confidential pods on
  SEV-SNP and TDX hosts, with GPU CC mode. The attestation service already
  verifies NVIDIA GPU and NVSwitch evidence; wiring it into the c8s
  certificate flow end to end is still open, see
  [Known gaps](#known-gaps-and-open-items).

- **Verifiable from a browser.** A challenge-response protocol and a
  post-quantum over-encrypted channel let end users verify the cluster with
  no special client, via [c8s-verify](https://github.com/confidential-dot-ai/c8s-verify-js).

- **One-command install.** `c8s install` brings all of this to an existing
  cluster (vanilla Kubernetes or RKE2, including AKS confidential node pools).

## Architecture

The most consequential choice in c8s is the unit of trust and attestation.
c8s supports both answers.

### Node-as-CVM

The entire Kubernetes node is one confidential VM. Pods are ordinary
containers inside it. A verifier checks the node's launch digest; everything
on the node is inside that one boundary, including the kubelet. This is the
simplest and densest shape, and the only one available on managed services
without nested virtualization (for example Azure AKS).

```text
                             NODE-AS-CVM
              one launch digest covers the whole node

════════════ TEE boundary (SEV-SNP / TDX encrypted memory) ════════════

  ┌────────────── Kubernetes node = one confidential VM ──────────────┐
  │                                                                   │
  │   ┌─────────┐   ┌─────────┐   ┌─────────┐      ┌───────────────┐  │
  │   │  pod A  │   │  pod B  │   │  pod C  │  ... │ kubelet, CNI, │  │
  │   │ (runc)  │   │ (runc)  │   │ (runc)  │      │ containerd    │  │
  │   └─────────┘   └─────────┘   └─────────┘      └───────────────┘  │
  │                                                                   │
  │   measured boot: IGVM + UKI + dm-verity node image                │
  └───────────────────────────────────────────────────────────────────┘

═══════════════════════════════════════════════════════════════════════

  HOST / HYPERVISOR (untrusted)
  the cloud or bare-metal operator sees only ciphertext
```

### Pod-as-CVM

Each pod is its own confidential VM (via the Kata `kata-qemu-snp` or
`kata-qemu-tdx` runtime). The node is just a launchpad and is fully
adversarial. Every pod carries its own launch digest, so each workload
proves its exact state to a verifier independently, and tenants on the same
node are isolated from each other by hardware memory encryption. The
security services each pod relies on (attestation, mesh, image policy) are
baked into the measured guest image, out of the host's reach.

```text
                              POD-AS-CVM
               every pod carries its own launch digest

════════════ TEE boundary (per-pod SEV-SNP / TDX encrypted memory) ═══════════

  ┌────── kata-qemu-snp/tdx CVM ──────┐  ┌────── kata-qemu-snp/tdx CVM ──────┐
  │ CDS                               │  │ workload                          │
  │   RA-TLS serving cert             │  │   + get-cert sidecar              │
  │   (SNP / TDX evidence)            │  │   (leaf cert from CDS)            │
  │                                   │  │                                   │
  │ baked into the measured image:    │  │ baked into the measured image:    │
  │   attestation-service, ratls-mesh │  │   attestation-service, ratls-mesh │
  │   policy-monitor                  │  │   policy-monitor                  │
  └───────────────────────────────────┘  └───────────────────────────────────┘

══════════════════════════════════════════════════════════════════════════════

  HOST (adversarial)
  ┌──────────────┐  ┌─────────────┐  ┌───────────────────┐  ┌─────────────┐
  │ c8s operator │  │ kata-deploy │  │ kata-image-puller │  │ containerd  │
  │ + webhook    │  │             │  │                   │  │ + kata shim │
  └──────────────┘  └─────────────┘  └───────────────────┘  └─────────────┘
```

In short: node-as-CVM is the all-or-nothing model (verify the node once,
trust everything on it), pod-as-CVM is the mutual-distrust model (the
platform and the workloads do not trust each other, and each pod attests
independently). The full comparison, including density, latency, and platform
support, is in the
[docs](https://confidential.ai/docs/c8s/runtime/pod-vs-node-cvm) and
[docs/install-flows.md](docs/install-flows.md).

## Quickstart

Install c8s onto an existing cluster. The full walkthrough is
[docs/QUICKSTART.md](docs/QUICKSTART.md); the hosted version with
provisioning guides is at
[confidential.ai/docs/c8s](https://confidential.ai/docs/c8s/install/installation).

### Prerequisites

- A Kubernetes cluster (vanilla or RKE2) with platform-admin permissions.
- Nodes with the TEE hardware for your chosen shape: an AMD SEV-SNP or Intel
  TDX host for pod-as-CVM, or SEV-SNP / TDX confidential VMs as nodes for
  node-as-CVM
  (see the [CVM setup guide](https://confidential.ai/docs/c8s/tutorials/azure-e2e)).
- Helm 3, `kubectl`, and `crane` on PATH.
- Go 1.26+ to build the CLI.

### Install

```sh
# Build and install the c8s CLI
git clone https://github.com/confidential-dot-ai/c8s
cd c8s
make install

# Label the node that will run CDS
kubectl label node <cds-node> role=cds

# Install the platform (base mode) and point the bundled TLS load balancer
# at your workload
c8s install --namespace c8s-system \
  --workload-ref vllm=<namespace>/deployment/<vllm-deployment>:8000 \
  --upstream vllm
```

`--workload-ref` adopts an existing workload as a confidential workload and
resolves its images into the bootstrap allowlist (see
[existing workload adoption](docs/operator.md#existing-workload-adoption)).
If you would rather not trust install-time digest resolution, pass
`--resolve-digests=false` and allowlist the digests yourself — see
[Managing the image allowlist](#managing-the-image-allowlist).

### Opt workloads in

Application teams opt in by annotating their pod templates:

```yaml
metadata:
  annotations:
    confidential.ai/cw: api
```

The annotation value (`api` here) is a workload id you choose; the
certificate SAN and the `c8s-<id>` headless Service are derived from it.

The webhook injects `c8s get-cert` as a native sidecar, which fetches an
attestation-bound certificate from CDS and renews it. Certificates land in
`/etc/c8s/certs`.

### Pod-as-CVM

`--kata` installs the Kata runtime and enforces it: every in-scope workload
pod becomes a confidential VM, and non-Kata pods are rejected at admission.

```sh
c8s install --kata --namespace c8s-system \
  --workload-ref vllm=<namespace>/deployment/<vllm-deployment>:8000 \
  --upstream vllm
```

See [docs/kata.md](docs/kata.md) for the runtime details and
[docs/DEMO.md](docs/DEMO.md) for a minimal demo flow.

### Production notes

- **Pin measurements.** The chart's RA-TLS handshakes accept any TEE-attested
  peer until you pin `cds.measurements` and `ratlsMesh.measurements` to the
  expected launch digests. Leave them empty only on a trusted network. See
  [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md).

- **Pin operator keys.** Pass `--operator-keys` at install time or allowlist
  writes stay disabled. Leaving writes disabled and re-deploying CDS on every
  allowlist change works too, but each restart mints a fresh mesh CA, forcing
  downstream consumers onto a new root of trust. See
  [Managing the allowlist](#managing-the-image-allowlist).

### A note on QEMU

- **Pod-as-CVM needs no host QEMU.** kata-deploy ships the kata-static
  payload, which bundles the TEE-capable QEMU builds that `kata-qemu-snp`
  and `kata-qemu-tdx` use. Do not point Kata at a distro QEMU.

- **Node-as-CVM needs QEMU 10.1 or newer, built with `--enable-igvm`.**
  Booting a measured node image via IGVM requires upstream QEMU's IGVM
  support, which most distributions do not ship yet. Check for it with
  `qemu-system-x86_64 -object igvm-cfg,help`.

## Verifying a cluster from outside

Anyone can verify that a c8s endpoint really terminates inside attested
hardware, without trusting the operator's word for it.

Browsers cannot inspect TLS certificates mid-handshake, so RA-TLS alone is
not browser-verifiable. The [c8s-verify](https://github.com/confidential-dot-ai/c8s-verify-js)
npm package instead runs a challenge-response protocol: the client
sends a fresh nonce, the TEE returns a hardware-signed attestation report
binding that nonce and an ephemeral public key, and all further traffic flows
over a post-quantum over-encrypted channel (ML-KEM) inside the regular TLS
session. A malicious TLS-terminating proxy in front of the real endpoint
cannot forge it. The wire contract is
[PROTOCOL.md](https://github.com/confidential-dot-ai/c8s-verify-js/blob/main/PROTOCOL.md).

Operators and CLIs can verify directly: `c8s cds verify` checks a CDS's
attestation and reports the operator keys it pins.

## Components

| Component | Description | Docs |
|---|---|---|
| [`cmd/cds`](cmd/cds/) | Certificate Distribution Service - verifies TEE attestation evidence, issues EAR tokens, and signs workload CSRs with an in-process mesh CA | [operator docs](docs/operator.md) |
| [`cmd/c8s`](cmd/c8s/) | Operator and install CLI for CRDs, status mirroring, webhook injection, and the embedded Helm chart | [operator docs](docs/operator.md) |
| [`cmd/get-cert`](cmd/get-cert/) | CLI tool and init-container for TEE-attested certificate provisioning | [README](cmd/get-cert/README.md) |
| [`cmd/ratls-mesh`](cmd/ratls-mesh/) | Transparent L4 proxy wrapping inter-node K8s traffic in RA-TLS | [README](cmd/ratls-mesh/README.md) |
| [`cmd/nri-image-policy`](cmd/nri-image-policy/) | NRI plugin enforcing container image digest allowlists | - |

## Libraries

| Package | Description |
|---|---|
| [`pkg/ratls`](pkg/ratls/) | RA-TLS library for hardware-attested mTLS (AMD SEV-SNP, Intel TDX) |
| [`pkg/ratls/cdsclient`](pkg/ratls/cdsclient/) | CDS attestation client for certificate provisioning |
| [`pkg/attestclient`](pkg/attestclient/) | High-level client for the CDS attestation flow |
| [`pkg/attestationclient`](pkg/attestationclient/) | Low-level HTTP client for the attestation-api |
| [`pkg/allowlistclient`](pkg/allowlistclient/) | CRUD client for the CDS allowlist API |
| [`pkg/allowlist`](pkg/allowlist/) | Allowlist types and JSON parsing |
| [`pkg/types`](pkg/types/) | Shared request/response types |
| [`pkg/issuerapi`](pkg/issuerapi/) | Certificate issuer API types |
| [`pkg/earsigner`](pkg/earsigner/) | EAR token-signing key lifecycle, rotation, and JWKS serving |
| [`pkg/certutil`](pkg/certutil/) | Certificate utility functions |

## Repository layout

```text
api/               CRD types
cmd/               Binaries: cds, c8s, get-cert, ratls-mesh, nri-image-policy
internal/          Operator, webhook, attestation, mesh CA, embedded Helm chart
pkg/               Public Go libraries (see Libraries above)
kata-guest-base/   Confidential guest image recipe for pod-as-CVM
docs/              Design docs, threat model, pitfalls, gaps
samples/           Example manifests
scripts/           Dev and CI helpers
test/              Docker-compose integration tests
```

## Build

Requires Go 1.26+.

```bash
# Build the c8s binary for the container images (linux/amd64)
make build

# Build and install the c8s CLI for your host platform, onto PATH
make install

# Run tests
make test

# Lint (format check + vet)
make lint

# Clean build artifacts
make clean
```

## Managing the image allowlist

CDS serves the image-digest allowlist that `nri-image-policy` (host) and
`policy-monitor` (in-guest) enforce on every node. The `c8s allowlist`
command reads and mutates it. CDS has no public ingress, so reach it over a
port-forward; the CLI verifies CDS's attestation, so the localhost hop is
fine.

```sh
kubectl port-forward -n c8s-system svc/c8s-cds 8443:8443 &

# Reads are unauthenticated
c8s allowlist export --url https://localhost:8443 > allowlist.json
c8s allowlist diff allowlist.json --url https://localhost:8443

# Writes are signed with the operator key
c8s allowlist add sha256:<digest> registry.example.com/app@sha256:<digest> \
  --url https://localhost:8443 --operator-key operator.key
c8s allowlist upload allowlist.json \
  --url https://localhost:8443 --operator-key operator.key
```

For reads, pass `--measurements` to pin CDS's launch digest; an empty set
accepts any attested CDS (unsafe outside dev). An `https://` URL is verified
via TEE attestation — a direct CDS endpoint through its RA-TLS serving cert,
or a tls-lb front door through its `/v1/discovery` document (the CLI detects
which).

Writes are authorized by an operator EC keypair whose **public** half CDS
pins at install time. Generate one and pin it:

```sh
openssl ecparam -name prime256v1 -genkey -noout -out operator.key
openssl ec -in operator.key -pubout -out operator.pub

c8s install --operator-keys operator.pub   # plus your other install flags
```

Installing without `--operator-keys` leaves allowlist writes disabled, and
`c8s install` refuses that on the default path unless you pass `--force` to
acknowledge. Supply the private key to the CLI by flag (`--operator-key`) or
environment (`C8S_OPERATOR_KEY`). Write tokens are short-lived and bound to
the request body, so a captured token cannot be replayed against a different
payload. `c8s cds verify` reports the key fingerprints a CDS actually pins.

Two caveats worth knowing before production: revocation is currently coarse
(remove the key from `cds.operatorKeys` and re-install), and the pinned-key
list is not yet covered by CDS's attestation. See
[docs/GAPS.md](docs/GAPS.md) and [docs/pitfalls.md](docs/pitfalls.md). For
GitOps consumers, `c8s render-values --operator-keys operator.pub` embeds the
PEM content (the chart value takes content, never a file path); the chart
wiring is described in [docs/operator.md](docs/operator.md).

## Docker images

All images are published to GHCR on push to `main` and on `v*` release tags:
per-role image names remain stable, but each image copies the same multi-mode
`c8s` binary and sets an appropriate entrypoint.

| Image | Base | Notes |
|---|---|---|
| `ghcr.io/confidential-dot-ai/c8s-operator` | distroless | Multi-mode `c8s` binary for operator/install and non-node roles |
| `ghcr.io/confidential-dot-ai/cds` | distroless | |
| `ghcr.io/confidential-dot-ai/get-cert` | distroless | |
| `ghcr.io/confidential-dot-ai/ratls-mesh` | debian-slim | Needs iptables |
| `ghcr.io/confidential-dot-ai/nri-image-policy` | debian-slim | |

The chart also deploys `ghcr.io/confidential-dot-ai/attestation-api`, the TEE
evidence verification service, which is built and published from
[attestation-rs](https://github.com/confidential-dot-ai/attestation-rs).

## Known gaps and open items

c8s is built around a strong threat model, and we would rather list the holes
than let you discover them. The canonical, always-current list is
[docs/GAPS.md](docs/GAPS.md); hard-won operational lessons are in
[docs/pitfalls.md](docs/pitfalls.md). Highlights:

- **Measurements are not pinned by default.** Until `cds.measurements` and
  `ratlsMesh.measurements` are set, the mesh accepts any attested peer. Fine
  for demos, mandatory homework for production.

- **CDS is a singleton by default.** The mesh CA key lives only in CDS process
  memory; a restart mints a new CA and workloads re-bootstrap. Active/active
  handoff exists behind `cds.handoff.enabled`.

- **Mesh peers are verified by CA chain, not per-peer measurement.** Leaf
  certificates do not embed the verified measurement, there are no
  SPIFFE-style URI SANs, and per-workload peer policy is not enforced yet.

- **The image allowlist gates digests only.** Args, env, mounts, and
  capabilities are not yet part of the enforced policy.

- **Root workloads can bypass the in-guest mesh.** UID-0 egress is exempted
  so the attestation service can reach AMD KDS. Run workloads as non-root.

- **Pod-as-CVM picks one CPU TEE per install.** Both SEV-SNP and TDX are
  supported, but `--hardware-platform` selects one for the whole cluster;
  mixed SNP+TDX clusters are not. Pod-as-CVM is also unavailable on Azure,
  which does not expose nested virtualization.

- **GPU attestation is not wired end to end.** GPU passthrough into
  confidential pods works, and a locked guest fails closed on a non-CC GPU.
  [attestation-rs](https://github.com/confidential-dot-ai/attestation-rs)
  already verifies NVIDIA GPU and NVSwitch evidence (SPDM via NRAS,
  nonce-bound to the CPU TEE evidence), but c8s does not yet collect GPU
  evidence in the guest or require it at certificate issuance, so no
  positive GPU attestation reaches the relying party.

- **The browser over-encryption channel is not streaming yet.** Requests and
  responses are buffered per envelope; responses over 32 MiB fail rather than
  stream.

- **Operator key revocation is coarse.** No CRL/OCSP; revoking an operator
  key means removing it and re-installing.

## Roadmap

The direction of travel, beyond closing the gaps above:

- **Encrypted volumes.** Persistent storage encrypted with keys that release
  only to attested workloads.

- **Key management system.** Attestation-gated secret release, so application
  secrets are brokered to workloads only after their measurement verifies.

- **IGVM support for Kata.** Move the per-pod runtime's measured boot to
  IGVM, unifying pod-as-CVM and node-as-CVM on one measured-boot format.

- **Encrypted RDMA.** Encrypted GPU-to-GPU and node-to-node RDMA for
  confidential multi-node training and inference.

## Standing on the shoulders of the community

c8s exists because a lot of excellent open work came before it, and we want
to be loud about that:

- [Kata Containers](https://github.com/kata-containers/kata-containers) is
  the foundation of our pod-as-CVM shape: the runtime, kata-deploy, and the
  guest tooling are outstanding engineering, and the maintainers have built
  something genuinely rare: VMs with the operational feel of containers.

- [Confidential Containers](https://github.com/confidential-containers)
  pioneered the confidential pod model that c8s builds on, including the
  guest-pull design that keeps container images out of the host's hands.

- The [Confidential Computing Consortium](https://confidentialcomputing.io/)
  and the wider ecosystem (the AMD SEV-SNP and Intel TDX stacks, the IGVM
  format, OVMF, and the NVIDIA confidential computing work) provide the
  hardware and firmware bedrock all of this stands on.

Where we fix or extend something upstream, we aim to contribute it back.

## Contributing and security

Please, before you open an issue or a PR, read
[CONTRIBUTING.md](CONTRIBUTING.md). It is short, and it explains the
contribution terms (you sign the CLA on your first PR), the review bar, our
policy on LLM-assisted contributions, and the requirement that commits be
signed.

And before you report anything security-shaped, read
[SECURITY.md](SECURITY.md). c8s is trust infrastructure: attestation
bypasses, policy bypasses, and certificate mis-issuance are security issues.
**Do not open public issues for them.** Email
[security@confidential.ai](mailto:security@confidential.ai) instead.

For anything else: [hello@confidential.ai](mailto:hello@confidential.ai).

## Licence

c8s is licensed under the [GNU Affero General Public License v3.0](LICENCE).
Contributions are accepted under the terms in
[CONTRIBUTING.md](CONTRIBUTING.md).

## Related repositories

- [`confidential-dot-ai/c8s-verify-js`](https://github.com/confidential-dot-ai/c8s-verify-js) - browser-side cluster verification library (npm: `c8s-verify`)
- [`confidential-dot-ai/attestation-rs`](https://github.com/confidential-dot-ai/attestation-rs) - TEE attestation evidence verification service (publishes the `attestation-api` image)
- [`confidential-dot-ai/deployment-scripts`](https://github.com/confidential-dot-ai/deployment-scripts) - Ansible roles for deploying these components
