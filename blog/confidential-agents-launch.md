# Confidential Agents

Today we launch Confidential Agents, the world's first verifiably private, secure agent runtime. Both the agents and their inference run in Trusted Execution Environments (TEEs), completely and verifiably encrypted.

[Sign up for the beta here](https://forms.gle/QkfCfAjvDcujZLzB6).

## The Problem

Two things are true when it comes to building AI agents.

1. The more data an agent can read and modify, the more useful it becomes.
2. The more data an agent can read and modify, the more dangerous it becomes.

An agent worth running has your codebase, your patient records, your trading book, your legal files. The industry's best security measures simply gate access, but every party in the agent stack—the host, the inference provider, and the software vendor—can still read that data.

Consider a hedge fund running an agent over its proprietary trading book on a frontier model. It signs a privacy agreement with the inference provider, but it can't *prove* the provider never saw its alpha. In principle, all data remains accessible. Providers simply promise not to look.

Confidential Agents is the first agent architecture where clients can verify that the hosting provider and inference provider all *can't* see your data.

## Closing the gap with TEEs

A Trusted Execution Environment (TEE) is a hardware-enforced boundary where the hypervisor and host only ever see ciphertext. The CPU itself encrypts memory with a per-CVM (confidential VM) key, locking the hypervisor and host out. A cryptographic measurement is sent to the client, which verifies that they're accessing compute within a TEE. This closes the host threat: even with full control of the machine, the operator reads noise, and the client can verify it.

Verifiability comes from the **attestation report**. The CVM (for both the agent *and* inference) generates a signed report proving that they are running in TEEs and that the software matches the audited build.

The client verifies that report against AMD's and NVIDIA's public key chains *before it sends anything*. Trust is established cryptographically, up front, with a mere 4–8% hit to throughput (tokens / second).

## Securing the agentic stack

Every agent has three ingredients, and each has an attack surface. Each is closed through TEEs.

- **Data.** The sensitive prompts and documents that agents receive. TLS protects the data en route to your compute, but once inside, it's vulnerable to a malicious hypervisor or host that can read your instance's RAM. TEEs prevent this by encrypting RAM, so the host sees only ciphertext.
- **Runtime.** The agent harness that's reading data and making tool calls. [Attested builds](/blog/kettle-attested-builds), powered by TEEs, enables you to verify what software is running so it can be audited for security purposes.
- **Intelligence.** Sensitive data is fed into large language models on inference hosts. The inference provider sees your sensitive data in the form of prompts. The GPU TEE closes this gap, similarly to the CPU TEE.

When all three are sealed, no party in the stack — host, inference, or software vendor — can see your data, and every claim is verifiable to the client.

## What a TEE won't do

A TEE doesn't make a model smarter, and it doesn't follow your data out the door. The seal covers the agent's three ingredients—data, runtime, and intelligence—and stops exactly there. The moment your agent calls an external tool, a third-party API, or an MCP server, that data crosses the boundary by design, and whatever is on the other side may see it in plaintext. Many real agent attacks have landed here, and TEEs are not built to solve it. What confidential computing gives you is a clean, provable line: everything inside is sealed, and every step outside is a deliberate decision, made with your eyes open.

## Try it out

If your agent touches data that matters, the trust boundary is paramount to the product. Confidential Agents is how you close it.

[Sign up for the beta here](https://forms.gle/QkfCfAjvDcujZLzB6), or visit our API docs [here](/docs/confidential-agents-api) to learn more.
