# Allowlist and capabilities

How c8s decides which container images may run, which commands they may run
with, and — for future key-management integration — which secret paths they may
read and write. This document complements
[`kata-image-policy.md`](kata-image-policy.md) (where enforcement happens inside
a kata guest) and [`ratls.md`](ratls.md) (how the allowlist is bound into
attestation).

> **Trust model.** The host, hypervisor, and Kubernetes control plane are
> untrusted; the trust boundary is the TEE. The image *reference* a pod presents
> (`docker.io/vllm/vllm-openai:v0.6.3`) is chosen by the untrusted host and is
> not bound to the bytes that run. The image *digest* is. So every trust decision
> in this design keys on the digest — the reference is a label for humans, never
> a lookup key.

## The model

The allowlist has two layers.

- **Floor** — `digests`: a `digest -> image-label` map. An image whose digest is
  in the floor may run, **by digest alone**, regardless of its command line. The
  measured guest seed and the standalone/injected c8s components (cds, get-cert,
  the operator, ratls-mesh, nri-image-policy, the tls-lb, the containerd-prep
  helper) live here. Floor entries carry no process or path policy.

- **Workloads** — `workloads`: named entries, each pinning an init/main
  container set. Every container binds a **digest** to the process policy
  (`command`, `args`) and path policy (`paths`) permitted for those bytes. The
  entry name is operator-chosen; the entry `label` and per-container `image` are
  informational. Policy is always resolved by container digest.

The floor answers "may these bytes run at all"; the workload layer answers "and
with what command line, and what filesystem access". A digest may appear in the
floor, in one workload entry, or in several — see [union
semantics](#a-digest-may-run-many-ways).

### Document shape

```json
{
  "schema": "c8s.allowlist/v1",
  "digests": {
    "sha256:<cds>":       "ghcr.io/confidential-dot-ai/cds",
    "sha256:<get-cert>":  "ghcr.io/confidential-dot-ai/get-cert"
  },
  "workloads": {
    "vllm-llama": {
      "label": "docker.io/vllm/vllm-openai:v0.6.3",
      "initContainers": [],
      "containers": [
        {
          "digest": "sha256:<vllm>",
          "image":  "docker.io/vllm/vllm-openai:v0.6.3",
          "command": { "policy": "exact", "argv": ["python3"] },
          "args":    { "policy": "exact", "argv": ["-m", "vllm.entrypoints.openai.api_server", "--model", "/models/llama-3.1-8b"] },
          "paths":   { "policy": "deny" }
        }
      ]
    }
  }
}
```

`schema` is the format identity. It is the first field of the canonical
serialization, so it is covered by the attested seed digest (below) and a
verifier pins the exact format. It also makes a malformed or foreign body fail
loud instead of parsing as an empty (and therefore deny-all or, worse,
allow-nothing-changed) allowlist.

## Process policy: command and args

An image digest already pins the image's baked `ENTRYPOINT`/`CMD` — they are in
the OCI config the digest covers. So a process policy does not restate the
image's defaults; it constrains what a pod may **run** for those bytes. This
matters because an image with an overridable entrypoint can otherwise be pointed
at an arbitrary command — credential extraction, a reverse shell — while keeping
an allowlisted digest.

The two policy fields mirror the Kubernetes container fields an operator already
sets: `command` overrides the image `ENTRYPOINT`, `args` overrides `CMD`.

### What the enforcers see

The enforcers that gate container start (the host NRI plugin, and the in-guest
policy-monitor under kata) observe the container's **effective argv**: the OCI
`process.args`, which is the already-merged result of the image config and any
pod-spec `command`/`args` override. They do not see the override as an override,
and they do not fetch the image config. Policy is matched against that effective
argv:

- **`command`** is matched as an exact **prefix** of the argv (it may be several
  tokens — `/docker-entrypoint.sh nginx`, `/bin/sh -c`, `python3`).
- **`args`** governs the **remainder** of the argv after the command prefix.

Each field is one of:

| policy  | `command` (a prefix)                     | `args` (the remainder)          |
|---------|------------------------------------------|---------------------------------|
| `exact` | argv must **start with** its `argv`      | the remainder must **equal** its `argv` |
| `any`   | no prefix constraint                     | the remainder is unconstrained  |
| `deny`  | the whole argv must be empty (see below) | there must be **no** remainder  |

So the boundary between the two is `len(command.argv)` when `command` is `exact`,
and `0` when it is `any` — which makes every combination well-defined: `command
exact + args any` pins the executable and lets flags vary; `command exact + args
exact` pins the whole argv; `args deny` means "no arguments beyond the command".

An absent policy normalizes to `deny`, so a minimally specified container is
maximally restrictive. `command: deny` requires an empty argv and therefore can
never start (a workload that wants any argv should say `command: any`); `lint`
flags it. Because `command`/`args` map 1:1 to the Kubernetes fields, `derive` (on
its own branch) reads them straight off a pod spec, and `inspect-image` shows an
image's baked `ENTRYPOINT`/`CMD` so an operator can see what to pin.

### A digest may run many ways

A single digest can appear under several containers — in one entry or across
entries — each with a different policy. Admission at the per-container gate is
the **union**: the container is admitted if its effective argv satisfies *some*
allowing container's command and args policy. This is deliberate. A shared base
image (busybox, a distroless runtime) is legitimately invoked with different
command lines by different workloads; the operator allowlists each invocation,
and any of them may run those bytes.

The precision this trades away: at the single-container gate the effective policy
for a digest is the union of every entry that lists it, because the host controls
which pod pairs a digest with which argv. `lint` surfaces this — it warns when one
entry widens a shared digest to `any`, because that becomes the effective
container-level policy for the digest everywhere. The narrower, entry-scoped
guarantee is recovered at [cert issuance](#where-its-enforced).

## Path policy (`paths`)

`paths` grants filesystem access for a coming key-management integration: a
workload attests, and a secret broker releases material into paths the workload
is entitled to.

```json
"paths": { "policy": "allow", "read": ["/secrets/model/**"], "write": ["/secrets/session"] }
```

- `deny` (default) grants nothing; `any` is unconstrained; `allow` lists `read`
  and `write` globs.
- A `write` grant implies create and update.
- Paths are absolute and clean (no `.`/`..`); the only wildcard is a trailing
  `/**` (subtree). These rules exist so a grant cannot be widened by path
  trickery once an enforcer consumes it.

**No enforcer consumes `paths` yet.** It is carried, validated, canonicalized,
and attested (it is part of the seed digest), so the schema and the operator
tooling are ready — but it grants nothing until the secret-release component
exists. When that component lands, a grant's subject must be bound to the
**attested workload digest**, never to a self-asserted image reference, or any
allowlisted workload could claim another's grant. The field is inert-with-a-spec
by design; it is not a live capability.

## Where it's enforced

Three independent points enforce, at different strengths:

1. **Host NRI plugin** (`nri-image-policy`), at CreateContainer, per container.
   Resolves the image digest and checks the effective argv against the allowlist
   index. Fail-closed before the allowlist first loads. Runs on the untrusted
   side of the TEE boundary for kata pods, so it is defense-in-depth there, and
   the primary gate for non-kata (base-mode) pods.

2. **In-guest policy-monitor** (under kata), watching each new container's
   `config.json`. This is the load-bearing gate for confidential pods: the host
   is untrusted, guest-pull is forced, and a violation is a SIGKILL of the
   container. It reads the digest and `process.args` and applies the same index.

3. **CDS at cert issuance**, in `verifyWorkloadClaims`. A pod's identity binds
   its role-partitioned init/main digest set. CDS requires every claimed digest
   to be allowlisted (floor or workload) and, when the set includes workload
   digests, requires it to **match a single workload entry's set exactly** — the
   combination gate — after excluding the c8s-injected containers.

### What each layer can and cannot promise

Per-container digest+argv admission holds at all three points. **Combinations**
("only this init+main set may run together") can only be checked where the whole
set is visible atomically, which is issuance — and there the set is the one the
workload *claims*. NRI and policy-monitor see containers one at a time and cannot
detect a *missing* container, so they cannot enforce a combination. The honest
guarantee is therefore: **per-container digest + argv everywhere; combination
gating at identity issuance.** Making a combination itself attested (so it gates
container start, not just issuance) is the RTMR3 per-workload-measurement path
tracked in [`THREAT_MODEL.md`](THREAT_MODEL.md); it is out of scope here.

### The injected-container carve-out

c8s injects two init containers into every confidential pod — `c8s-cert`
(get-cert) and `c8s-cert-wait`. The combination gate must exclude them, or every
workload's expected set would have to enumerate c8s's own sidecars. The exclusion
pins the injected container by **name and its measured get-cert digest**: a
container named `c8s-cert` whose digest is not the measured get-cert digest is
treated as a workload container, not skipped. Name alone is not identity — the
host writes the container-name annotation — so the digest pin is what makes the
carve-out sound. get-cert itself is a floor digest (in the measured seed) and
runs with per-pod dynamic arguments, which is exactly why standalone/injected
images are digest-only: their argv is not fixed and must not be argv-policed.

## Distribution and trust

CDS serves the allowlist over an RA-TLS channel that consumers pin to CDS's
launch measurement. The document body is not itself signed; its integrity in
transit is the attested channel, and its provenance is the **seed digest** and
the **operator-key-set digest** that CDS binds into its serving certificate's
config-claims (`ratls.ConfigClaims`, see [`ratls.md`](ratls.md)). A verifier
pins those with `c8s cds verify`. The canonical serialization
(`allowlist.Canonical`) is deterministic — fixed field order, sorted map keys,
sorted container and path lists — so any holder of an equivalent document
reproduces the same digest.

Writes are authorized by an operator EC key. The `c8s allowlist` CLI mints a
short-lived token bound to the exact method, path, and body (so a captured token
cannot be replayed against a different payload) and CDS verifies it against the
operator public keys it pins. The same operator keys authorize floor and workload
writes alike.

### Refresh, floor, and anti-rollback

Consumers poll `GET /allowlist` and refresh on a changed version (the ETag
counter). The two layers refresh differently, because they have different
failure modes:

- The **floor is additive**. A digest, once served, is never dropped by a
  consumer; a CDS outage or a stale read degrades to "the same set or larger,
  never smaller", never to "open". In-guest this floor is anchored by the
  measured baked seed, so enforcement starts at t=0 offline.

- The **workload policy overlay swaps wholesale, gated by a monotonic epoch**
  (the version counter). A consumer applies a pulled overlay only if its version
  is greater than the last applied, and ignores a regression. This matters
  because workload policy can *tighten* (narrow `args`, revoke a `paths` grant);
  a plain additive merge would let a host that withholds an update keep a laxer
  policy live forever. Epoch-gated replacement makes a withheld or rolled-back
  update fail toward the last-known-good policy, not toward the laxest one. The
  high-water-mark is process-local, so this rejects rollback only within a
  consumer's lifetime: after a restart (a fresh CVM, for the in-guest monitor)
  the first version seen is trusted and state re-syncs from CDS. A reboot-durable
  guarantee needs an attested freshness / monotonic-counter mechanism the host
  cannot reset — a tracked follow-on.

## Bootstrap

The floor is rendered by the chart from resolved component digests and handed to
CDS as the seed (`--allowlist-seed`). Standalone/injected components are
digest-only floor entries — the default bootstrap has an empty `workloads` map.
This is correct precisely because those components have no fixed argv to pin
(get-cert's arguments are per-pod; cds runs with its own flag set), and forcing
them into workload entries would invite a policy that denies them their own
command line and bricks the platform on its first boot.

The guest-baked seed remains a flat `sha256_digests` list — it is the floor,
measured into the SNP launch digest, and keeping it digest-only means a policy
change never requires a guest-image rebuild.

## CLI

`c8s allowlist` reads and mutates the allowlist. Reads are unauthenticated (the
RA-TLS channel provides integrity); writes are signed with the operator key you
supply via `--operator-key` (or `C8S_OPERATOR_KEY`). Persistent flags: `--url`,
`--measurements`/`--measurements-file` (RA-TLS pins), `--timeout`,
`--operator-key`, `-o text|json`, `--insecure`.

```
c8s allowlist
  list                              floor table + workload summary
  export [file]                     write the full canonical document
  diff <file> [--exit-code]         entry/field diff vs the live allowlist
  add <digest> <image>              add a floor digest
  remove <digest>...                remove floor digests (warns on component-floor images)
  upload <file>                     replace the whole allowlist (diff-first, required-components guard)
  lint <file|-> [--online] [--strict]
  inspect-image <ref>               show an image's digest + baked entrypoint/cmd

  workload list | get <name>
  workload apply <file|-> [--dry-run]
  workload edit <name>
  workload delete <name>...
```

### Editing and applying

Whole entries are the unit of a write. `apply` and `edit` replace an entire entry
and show the field diff first; nothing field-merges, so no command can silently
clobber a sibling field. `edit <name>` is the fetch → `$EDITOR` → lint → diff →
confirm loop, and the signed write is always a separate, reviewed `apply`.

### Footguns the CLI removes

- **No raw `""`/`"*"` on the command line.** Policies are keywords (`deny`,
  `any`) or an argv captured verbatim after `--`; the tri-state sentinels live
  only inside files. Nothing can be shell-globbed or silently emptied.
- **The wrong shape errors, never half-works.** `workload delete` takes names;
  `remove` takes `sha256:` digests; a mixup fails validation instead of partially
  applying.
- **Signed writes are diff-first and lint-first.** `upload`/`apply` run the
  offline lint (errors block, warnings need `--force`) and print the diff before
  the write.

### lint

`lint` catches the semantic traps before a write: an entry that admits nothing
(both lists empty), a `command: deny` container that can never start, a
shared digest whose union is widened to `any` by some entry, a digest that is
floor-listed while also carrying a workload policy — the floor admits it by
digest alone, so the argv/paths policy is silently not enforced — tag-form labels
(which can move under the operator), and a summary of how many `any` policies a
document carries. `--online` cross-checks digests against the registry with
`crane`; `--strict` turns warnings into a non-zero exit for CI.

## Operator credentials

Generating an operator key and pinning its public half is unchanged; see the
README and [`operator.md`](operator.md). Rotating the pinned set rolls CDS, and
the pinned set's digest is attested, so a verifier detects a changed write policy.
The path grants (`paths`) will, when their enforcer lands, be managed with the
same `workload edit`/`apply` flow and bound to the attested workload digest.
