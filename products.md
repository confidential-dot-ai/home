# Products

Confidential AI is a stack of licensed software for running private AI on your infrastructure. Prompts, weights, data, and agent state stay encrypted in memory while they run, and every result carries a cryptographic attestation of what ran and where.

The stack is built in layers. Confidential Metal and Confidential Kubernetes are the foundation; Confidential Inference and Confidential Agents are private AI workloads you run on top of them. License the pieces you need and run them on your own hardware or any major cloud. Confidential AI also runs all of these layers on the Confidential Cloud.

```
┌────────────────────────────────────────────────────────┐
│     Confidential Inference  /  Confidential Agents     │
│            private AI you run on the stack             │
╞════════════════════════════════════════════════════════╡
│             Confidential Kubernetes  (C8s)             │
│        one CVM becomes a platform you can scale        │
╞════════════════════════════════════════════════════════╡
│                   Confidential Metal                   │
│          hardware becomes a CVM you can trust          │
╞════════════════════════════════════════════════════════╡
│   TEE hardware: AMD SEV-SNP / Intel TDX / NVIDIA CC    │
└────────────────────────────────────────────────────────┘
```

## Confidential Metal

The foundation for bare metal. Confidential Metal turns on confidential computing on CC-capable hardware: software that sets the BIOS and a hardened host image carrying the right TEE firmware and kernel parameters. On top of that it provides the machinery to launch CVMs you can fully measure and verify, a hardened guest image measured from firmware all the way to user space, with that measurement bound to an attested build and the attestation library baked in.

Managed clouds like GCP and Azure already hand you measurable CVMs; Confidential Metal brings the same guarantees to your own bare metal.

```
┌────────────────────────────────────────────────┐
│                Host: CC enabled                │
│        BIOS + TEE firmware, host image         │
└────────────────────────────────────────────────┘
                        │  launches
                        ▼
╔════════════════════════════════════════════════╗
║                Confidential VM                 ║
║                                                ║
║              hardened guest image              ║
║        measured: firmware to user space        ║
║          attestation library built in          ║
╚════════════════════════════════════════════════╝
                        │
                        ▼  attestation
┌────────────────────────────────────────────────┐
│          measured, attested, trusted           │
└────────────────────────────────────────────────┘
```

## Confidential Kubernetes

One CVM is not a service. Confidential Kubernetes (C8s) turns it into a platform you can host and scale on, with confidentiality spanning the whole cluster. Every workload gets an attested identity, all traffic between components is encrypted, and the control plane stays outside the boundary, so an operator can run your workloads without ever seeing them. C8s builds on the measurable CVMs and CC-enabled hardware that Confidential Metal provides on bare metal (and that GCP and Azure provide in the cloud).

```
┌──────────────────────────────────────────────────────┐
│    Control plane   (untrusted, outside boundary)     │
└──────────────────────────────────────────────────────┘
                           │  schedules
╔══════════════════════════════════════════════════════╗
║                                                      ║
║       [ Pod CVM ]   [ Pod CVM ]   [ Pod CVM ]        ║
║          attested identity, encrypted mesh           ║
║                                                      ║
║          CDS - root of trust, issues certs           ║
║                                                      ║
╚══════════════════════════════════════════════════════╝
            hardware-enforced trust boundary            
```

## Confidential Inference

Private inference you run on top of your own confidential stack. It serves open-weight models behind an OpenAI-compatible API as a drop-in replacement: switch one base URL and your prompts, responses, and the model weights stay encrypted in CVM memory, with an attestation on every response. Deploy it on Confidential Kubernetes and it inherits the guarantees of the layers beneath it.

```
┌──────────────────────────────────────────────────┐
│                     Your app                     │
│                swap one base URL                 │
└──────────────────────────────────────────────────┘
                         │  OpenAI-compatible API
                         ▼
╔══════════════════════════════════════════════════╗
║                  TEE model pool                  ║
║      prompts + weights encrypted in memory       ║
╚══════════════════════════════════════════════════╝
                         │
                         ▼  response + attestation
┌──────────────────────────────────────────────────┐
│                     Your app                     │
└──────────────────────────────────────────────────┘
```

## Confidential Agents

Private, isolated environments for your AI agents, running on top of your confidential stack. Each agent runs in its own Confidential VM with hardware-encrypted memory, ready over SSH in seconds and preloaded with an agent runtime and attested inference. The code, data, and keys inside stay invisible to the infrastructure they run on. Treat each one as disposable: spin it up for a task, run it, throw it away.

```
┌────────────────────────────────────────────────┐
│              You hold the SSH key              │
└────────────────────────────────────────────────┘
                        │  ssh
                        ▼
╔════════════════════════════════════════════════╗
║                   Agent CVM                    ║
║                                                ║
║       agent runtime + attested inference       ║
║     code, data, keys invisible to the host     ║
╚════════════════════════════════════════════════╝
```

## How they fit together

Confidential Metal produces trustworthy CVMs. Confidential Kubernetes turns them into a platform that can host and scale a real service. Confidential Inference and Confidential Agents are the private AI workloads that run on top. License the whole stack and run it yourself, from the metal up, on your own hardware or any major cloud.

## Or let us run it for you

Confidential Inference and Confidential Agents are also available as a managed service on our own cloud: we operate the entire stack so you get private AI behind an API without running any of it yourself. See [Cloud](/cloud), or [contact sales](mailto:hello@confidential.ai) to scope a deployment.
