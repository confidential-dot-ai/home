# Confidential — Full Documentation

> The AI confidential compute platform. Complete content from all pages.

## TLDR

Confidential runs AI workloads (inference, training, agents) inside hardware-encrypted Trusted Execution Environments (TEEs). Data and code stay private during processing, can't be tampered with, and both claims are cryptographically verifiable without trusting Confidential. Deploy code unchanged — no performance penalty (~1.5% overhead on CPUs, max 2.08% observed).

**Use Confidential two ways:**
- **Confidential Cloud** — hosted TEE-backed infrastructure: pay-per-token inference, GPU and CPU VMs, attested CI/CD builds (Kettle), and a Confidential Agents API for spinning up private agent environments.
- **Enterprise / Licensed** — deploy the modular component stack on your own infrastructure (on-prem, bare metal, all major clouds).

**Components:** Attestation service, CDS (attestation-gated secrets), attested build pipeline (SLSA L3), TEE networking (mTLS + multi-recipient hybrid encryption), OHTTP gateway, control plane (with optional ZK proofs), hardened VM image, client/server SDKs. All modular — use individually or together.

**Enterprise model:** Discovery (free) → Pilot (1-4 months, deploy on your infra) → Production. On-prem, bare metal, all major clouds.

**Key benchmarks (AMD EPYC, SEV-SNP, cryptographic proving workloads):**

| Metric           | TEE     | Regular | Difference |
| ---------------- | ------- | ------- | ---------- |
| Execution Speed  | 5.16 kHz | 5.26 kHz | -1.90%    |
| Runtime Duration | 89.46s  | 87.78s  | +1.91%     |
| CPU Utilization  | 26.61%  | 26.23%  | +1.45%     |
| Memory Usage     | 19.02 GB | 18.87 GB | +0.80%   |

**Contact:** [hello@confidential.ai](mailto:hello@confidential.ai)
