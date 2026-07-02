# Confidential

> The AI confidential compute platform.

Confidential runs AI workloads (inference, training, agents) inside hardware-encrypted Trusted Execution Environments (TEEs). Data and code stay private during processing, can't be tampered with, and both claims are cryptographically verifiable without trusting Confidential.

Deploy code unchanged. Get end-to-end privacy, enhanced security, and full verifiability with negligible performance overhead.

## Use Cases

- **Private inference** — guarantee data privacy during inference. Customer prompts, responses, and model interactions are never visible to the provider or their infrastructure.
- **Weight protection** — protect proprietary weights from extraction during inference or fine-tuning. Weights never leave hardware-enforced secure enclaves.
- **Private training** — train on sensitive data and cryptographically prove exactly what data was used.
- **Agent security** — agents run inside TEEs with hardware-enforced credential isolation. Tokens and API keys never exist in plaintext outside a TEE.
- **Multi-agent trust** — agents verify each other's identity and code via cryptographic attestation before establishing trust.
- **Regulatory verifiability** — prove to regulators that the audited model is what's actually running in production via verifiable attestation.

## Performance

TEE overhead is minimal. Benchmarks comparing identical workloads inside TEE-enabled vs regular VMs show ~1.5% overhead. The largest overhead observed across any stage was 2.08%.

| Metric           | TEE Environment | Regular Environment | Difference |
| ---------------- | --------------- | ------------------- | ---------- |
| Execution Speed  | 5.16 kHz        | 5.26 kHz            | -1.90%     |
| Runtime Duration | 89.46s          | 87.78s              | +1.91%     |
| CPU Utilization  | 26.61%          | 26.23%              | +1.45%     |
| Memory Usage     | 19.02 GB        | 18.87 GB            | +0.80%     |

Tested on AMD EPYC with SEV-SNP using cryptographic proving workloads (STARK proofs via zkVM) — among the most compute-intensive workloads possible. If overhead is negligible here, it's negligible for typical AI workloads.

Full benchmark details: [TEE Performance on CPUs](https://confidential.ai/blog/tee-performance-cpus)

## How To Use Confidential

- **Confidential Cloud** — hosted TEE-backed infrastructure. On-demand inference, GPU and CPU VMs, attested CI/CD builds, and a private agents API. No code changes. [Cloud](https://confidential.ai/cloud) · [Pricing](https://confidential.ai/pricing)
- **Enterprise / Licensed** — deploy Confidential's modular software stack on your own infrastructure. Use the full platform or specific pieces. On-prem, bare metal, all major clouds. [Contact sales](mailto:hello@confidential.ai).

## Confidential Cloud Services

### [Confidential Inference](https://confidential.ai/confidential-inference)

Pay-per-token private inference. OpenAI-compatible API. Drop-in replacement for existing providers. 4% lower token throughput vs non-confidential; negligible impact on Time to First Token.

Token pricing:

{{inference_pricing_table}}

### [Confidential VMs](https://confidential.ai/confidential-vms)

Dedicated TEE-backed VMs. Single-GPU pass-through on all GPUs, protected PCIe on H100, multi-GPU pass-through with encrypted NVLink on B200 and B300.

GPU VMs (per GPU-hour):

{{gpu_vms_table}}

CPU VMs (per core-hour + per GB-hour RAM):

{{cpu_vms_table}}

### [Attested Builds (Kettle)](https://confidential.ai/attested-builds)

Attested CI/CD inside TEEs with cryptographic provenance. SLSA Build L3. GitHub integration. Base rate $0.008 per vCPU-minute; runners scale linearly.

{{attested_builds_table}}

### [Confidential Agents](https://confidential.ai/confidential-agents)

Spin up a private, isolated agent environment in under 15 seconds. Each instance ships with the OpenClaw runtime and a bundled OpenAI-compatible inference gateway, accessible over SSH. Invisible to everyone, including Confidential.

## Components

Confidential is a set of independent, composable components. Use them all or integrate individual pieces into your existing stack. For licensing, [contact sales](mailto:hello@confidential.ai).

- **Attestation Service** — Generates and verifies TEE attestation reports. Trust anchor for the platform. Supports AMD SEV-SNP (VCEK/VLEK), Intel TDX, and NVIDIA CC. Continuous re-attestation with automatic certificate revocation. Public verification API and CLI.
- **Certificate Distribution Service (CDS)** — Gates secret and certificate distribution on attestation. Workloads prove what they're running before receiving secrets. Optional certificate authority and TEE registry. Integrates with existing secret stores (e.g. HashiCorp Vault).
- **Build Pipeline (Kettle)** — Produces attested builds: runs builds inside a TEE with cryptographic proof of inputs, environment, and outputs. Verifiable chain from git commit to running code without needing deterministic compilers. Achieves SLSA Build L3 through hardware enforcement.
- **Networking & Application Services** — All networking runs inside TEEs. API gateway, multi-recipient hybrid encryption (payloads encrypted to multiple attested TEEs for reliability), firewalls, DDoS protection, load balancing. Internal mTLS with attestation-rooted certificates.
- **Oblivious HTTP Gateway** — OHTTP-compatible gateway in a TEE paired with a third-party relay. Separates client identity from request content. No single party learns both who is asking and what they're asking.
- **Control Plane** — Orchestration, scheduling, and autoscaling inside a TEE. Telemetry extracted from within the encrypted boundary. Optional ZK proofs verify scaling decisions without exposing per-process data. Supports on-prem, bare metal, and cloud (CPU and GPU).
- **Hardened VM Image** — Minimal, hardened base OS for all workloads. No unnecessary services or debugging tools in production. Measured as part of TEE launch. SELinux, seccomp filters, network isolation.
- **SDKs (Client and Server)** — Client SDK handles encryption, attestation verification, and CDS certificate negotiation. Server SDK handles attestation report generation and TEE-side encryption. Verification API and CLI for programmatic and manual checks.

### Adoption Patterns

- **Attestation only:** Attestation service + SDKs — for teams adding TEE verification to existing deployments.
- **Security layer:** Attestation + CDS + build pipeline — for organizations needing the cryptographic verification layer.
- **Full platform:** All components end-to-end — equivalent to the hosted platform, deployed on your infrastructure.

## Enterprise

Confidential works with AI labs and infrastructure providers. Components are modular and designed for existing bespoke infrastructure. [Contact sales](mailto:hello@confidential.ai) to scope an engagement.

**Three-phase engagement:**
1. **Discovery** (free) — Understand your architecture and threat model. Outcome: gap analysis and pilot scope.
2. **Pilot** (1-4 months) — Deploy components on your infrastructure. Architectural deep dive, integration design, deployment, cryptographic verification. If closing the trust boundary requires components that don't exist yet, we build them. No strings attached — license or walk away.
3. **Production** — Full deployment with ongoing support. On-prem, bare metal, all major clouds.

## Documentation

{{docs_index}}

## Blog

{{blog_index}}

## Company

- [Team](https://confidential.ai/team): The people building Confidential.
- [Careers](https://confidential.ai/careers): Open positions at Confidential.
- [Email](mailto:hello@confidential.ai): hello@confidential.ai

## Full Documentation

- [llms-full.txt](https://confidential.ai/llms-full.txt): Complete content from all pages — entire site in one file.
