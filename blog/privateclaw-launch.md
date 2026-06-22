# PrivateClaw launches on Confidential: E2E Private AI Agents

Your OpenClaw host can read every conversation you have with your AI agent.

That's true for almost every hosted agent on the market. A provider runs the VM. A provider runs the inference. The providers, in theory and in practice, see your prompts and the model's responses.

For some workloads, that's fine. For proprietary code, patient data, financial docs, or anything legal, it's a problem.

[PrivateClaw](https://privateclaw.dev) fixes it. And it runs on Confidential's stack.

## What it is

PrivateClaw is a managed [OpenClaw](https://docs.openclaw.ai/getting-started) instance with end-to-end encryption you can verify yourself.

One command:

```
$ ssh privateclaw.dev
```

That's the install. SSH in, get a dedicated Confidential VM. There's a free tier.

## What "verify yourself" means

Most "private AI" products are policy promises. "We won't look at your data."

PrivateClaw is a cryptographic one. The host can't look at your data, and you can verify this.

Two TEEs, connected privately:

1. **Your VM** runs in a TEE, an AMD SEV-SNP confidential virtual machine. Memory is hardware-encrypted. The cloud provider can't read it.
2. **Inference** runs in a separate TEE. Prompts are encrypted in transit and during processing.

The [verification CLI](https://github.com/confidential-dot-ai/privateclaw-cli) is open source. Run it from your VM and confirm the properties yourself in seconds.

## The Confidential stack underneath

PrivateClaw is what the Confidential platform is built for. The components doing the work:

- **Confidential VMs (CPU and GPU)** provide the hardware-encrypted execution environments for the agent's VM and the inference endpoint.
- **Attestation Service** generates the cryptographic proof that the code running is the code that was built. The PrivateClaw verify CLI wraps this for end users.
- **Networking inside TEEs** keeps the path from VM to inference endpoint inside the encrypted boundary the whole way.
- **Hardened VM image** is the base OS. Minimal, measured, no debugging tools in production.

Overhead is negligible. Our [benchmarks](/blog/tee-performance-cpus) on SEV-SNP show ~1.3% across CPU-heavy workloads, and ~4% token throughput overhead for inference.

## Why this is the start, not the end

OpenClaw is the first hosted agent. Qwen is the first model. More of both are coming.

The pattern generalizes. Any agent that handles sensitive context wants the same thing: hardware-isolated execution, attested inference, credentials that never exist in plaintext outside the TEE. The Confidential stack provides all of it.

If you're building agents and the trust boundary matters, the same components are available to you. [Read the docs](/docs/confidential-agents-api) or [get in touch](mailto:hello@confidential.ai).

## Try it

```
$ ssh privateclaw.dev
```

Free tier available.
