# Confidential Agents

Spin up a private, isolated environment for your AI agent in under 15 seconds. Each instance comes preloaded with an agent runtime and inference, ready over SSH, and is completely invisible to everyone except you, including us.

[Sign up for the beta here](https://forms.gle/QkfCfAjvDcujZLzB6).

## Up and running in under 15 seconds

Call the API and you're SSH'd into a ready environment in under fifteen seconds. No waiting, no manual provisioning. Treat agent environments as disposable, spin one up for every task, run it, throw it away.

## Completely private, even from us

Each instance runs inside a Confidential VM with hardware-enforced memory encryption. The code, data, and agent state inside are invisible to us, to other customers, and to the infrastructure operators we run on. You hold the SSH key; we have no way to look inside.

## Agents, preloaded

Every instance launches with the OpenClaw agent runtime installed and ready to go. Additional agents available soon.

## Confidential inference, included

Every instance gets attested inference out of the box, open-weight models served from the TEE pool, with no separate setup. See [Confidential Inference](/confidential-inference) for the model lineup.

## How it works

1. `POST /v1/instances` with your SSH public key.
2. Poll `GET /v1/instances/{name}` until `status` is `ready`.
3. `ssh <name>.<organization>.confidential.ai`, run your workload inside the TEE.
4. `DELETE /v1/instances/{name}` when done.

```bash
curl -sS -X POST https://api.confidential.ai/v1/instances \
  -H "Authorization: Bearer $CA_API_KEY" \
  -H "Content-Type: application/json" \
  -d "{\"public_key\": \"$(cat ~/.ssh/id_ed25519.pub)\", \"agent\": \"openclaw\"}"
```

See the [Agents API reference](/docs/api/confidential-agents) for the full request and response surface.

## Get access

API keys are issued per organization. [Contact us](mailto:hello@confidential.ai) to request access, and see the [Agents API reference](/docs/api/confidential-agents) for the full endpoint surface.
