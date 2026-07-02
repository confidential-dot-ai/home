# c8s-docs Style Guide

How we write the c8s documentation. The goal: docs an experienced infra/Kubernetes engineer
can navigate fast, trust completely, and copy-paste from — even if they've never touched
confidential computing before. For *how the site is wired* and the source-of-truth rules, see
[`CLAUDE.md`](./CLAUDE.md).

Two standing principles behind everything below:

1. **The source code is authoritative.** Never document a flag, default, name, or behavior you
   haven't verified against `../c8s` (or the relevant Lunal repo). Prose that drifts from the
   code is worse than no prose.
2. **Be concrete.** Lead with the command, the manifest, the exact term. Prefer a runnable
   example over a paragraph describing one.

---

## 1. Audience

Write for an **experienced Kubernetes / infrastructure engineer who is new to confidential
computing.** Assume fluency with: pods, nodes, DaemonSets, CRDs, Helm, `kubectl`, ingress,
TLS, container registries and digests. Do **not** assume familiarity with: TEEs, attestation,
measured boot, SEV-SNP/TDX, RA-TLS, CVMs, IGVM. Introduce those the first time they appear.

The reader's recurring question is *"is my data actually protected, and how do I prove it?"*
Answer it. The threat model (host is adversarial) is the spine of the product — keep it visible.

---

## 2. Voice and tone

**Default voice: direct, second-person, confident, security-first — and a little opinionated.**
This is the established voice; preserve it. It's the voice of an engineer who has thought hard
about the threat model and will tell you the truth.

- **Second person.** Address the reader as "you". Use imperative mood for steps ("Run", "Set",
  "Verify").
- **Active, present tense.** "The CDS verifies the report and issues a leaf." Not "The report
  will be verified by the CDS."
- **Opinionated where it earns it.** State the strong position and why. The site already does
  this well — keep that spine:
  > "The design assumption is simple and uncompromising: **the host is adversarial.**"
  > "This page is the honest list of what the current milestone does **not** do."
- **Honest about gaps.** Never oversell. If something isn't enforced, say so plainly and link
  to the workaround or the limitation. Trust is the product.
- **Concise.** Cut throat-clearing ("It is important to note that…", "Simply…", "In order
  to…"). Short sentences. One idea per sentence.

### Tone carve-outs

- **CLI reference (`install/cli-reference.mdx`): neutral, reference register.** No
  editorializing, no "you", no opinion. Just flag, type, default, effect — terse and uniform.
  This section is looked up, not read.
- **Tutorials (`tutorials/**`): warmer and more relaxed.** A guiding, slightly conversational
  hand is welcome here — you're walking someone through an end-to-end run. You may say "we'll",
  set expectations ("this takes a few minutes"), and reassure. Keep the security framing, but
  lighten the formality.

### Avoid

- Marketing fluff and superlatives ("blazing-fast", "seamless", "revolutionary").
- Hedging that undercuts authority ("might", "should probably") when you actually know.
- Whitepaper-speak in user docs — the paper's tone is academic; the docs are operational.
- Apologizing for the product, or burying a real limitation in qualifiers.

---

## 3. Page structure

- **Frontmatter is required:** `title` and `description` only (both used by Fumadocs).
  - `title`: sentence case, concise, no trailing period. It *is* the page H1.
  - `description`: one or two real sentences (shown in sidebar cards and `<meta>`). Make it
    say what the page delivers, not "This page describes…".
- **No `# H1` in the body.** Start at `##`. Don't skip levels (`##` → `###`, not `## ` → `####`).
- **Headings: sentence case**, no terminal punctuation, descriptive enough to scan. Phrase
  them as the question the reader has or the task they're doing ("Why pod-as-CVM is not
  available on Azure", "Install in base mode"), not bare nouns where a task is meant.
- **Lead with the point.** First paragraph states what this page is for and the one thing to
  take away. Then details. Don't make readers scroll for the command.
- **Match the page type** (below). Don't mix a conceptual essay into a how-to.

### Page-type patterns

| Type | Where | Shape |
| --- | --- | --- |
| **Concept / architecture** | `architecture/**`, `runtime/**`, `attestation/**` | Prose + ASCII diagram + comparison tables. Explain the *why* and the trust implications. |
| **How-to / install** | `install/**` | Prereqs → numbered `<Steps>` with copy-paste commands → verification → troubleshooting/`<details>`. |
| **Tutorial** | `tutorials/**` | End-to-end narrative, warmer tone, `<Steps>`, expected output shown, `JourneyNav` at the foot. |
| **Reference** | `install/cli-reference.mdx`, allowlist/CDS API tables | Neutral, exhaustive, table-driven. Gated against source — keep in sync. |

---

## 4. Terminology and capitalization

Use these exact forms. Source spelling beats the whitepaper every time. When an acronym first
appears on a page, expand it once: "Trusted Execution Environment (TEE)". After that, the
acronym alone.

| Term | Use exactly | Notes / not |
| --- | --- | --- |
| Product name | **c8s** | Always lowercase, even at sentence start. Bold on first mention per page (`**c8s**`). Not "C8s", "C8S", "c8S". |
| Confidential Kubernetes | "confidential Kubernetes" | Lowercase descriptor. |
| CDS | **CDS** (Certificate Distribution Service) | The trust root. Not "cds" in prose. |
| RA-TLS | **RA-TLS** (Remote-Attestation TLS) | Not "raTLS", "RATLS", "ra-tls". |
| EAR | **EAR** (Entity Attestation Result) | An ES256 JWT the CDS issues. (Keep this expansion unless source says otherwise.) |
| TEE | **TEE** (Trusted Execution Environment) | |
| CVM | **CVM** (confidential VM) | |
| SEV-SNP | **AMD SEV-SNP** (first use), **SEV-SNP** after | Not "SEV/SNP", "sev-snp". |
| TDX | **Intel TDX** (first use), **TDX** after | |
| GPU CC | "NVIDIA Confidential Computing (CC mode)" | Not shipped — see roadmap rules. |
| Deployment shapes | **Pod-as-CVM**, **Node-as-CVM** | Hyphenated, capitalized as shown. Not "pod-level CVM" (that's whitepaper). |
| Modes | **base mode**, **Kata mode** | Lowercase "base"/"mode"; **Kata** capitalized (project name). |
| Allowlist | **allowlist** | One word. Not "allow-list" or "allow list". |
| Measurement | "launch measurement" / "measurement" | The SHA-384 launch digest. |
| Components (code names) | `c8s operator`, `attestation-api`, `ratls-mesh`, `nri-image-policy`, `policy-monitor`, `get-cert`, `cds-attest` | Lowercase, code-formatted as identifiers; match the source exactly. |
| CRD | `ConfidentialWorkload` (short name `cwl`), group `confidential.ai`, version `v1alpha2` | |
| Runtime classes | `kata-qemu`, `kata-qemu-snp`, `kata-clh` | Code-formatted; exact. |
| Annotations / labels | `confidential.ai/cw`, `confidential.ai/c8s-injected`, … | Always code-formatted and exact. |
| Namespace | `c8s-system` | Default install namespace. |

- **Kubernetes nouns** stay lowercase as the project does them: pod, node, namespace,
  container, control plane, kubelet, containerd. Capitalize only proper nouns (Kubernetes,
  Kata, Helm, Azure, Vercel, NVIDIA, AMD, Intel).
- **Don't invent synonyms.** One concept, one name, everywhere. If the code calls it
  `get-cert`, the docs call it `get-cert` — not "the cert helper".

---

## 5. Mechanics

- **Spelling: US English** ("behavior", "authorize", "canceled"). Matches code (`allowlist`,
  `authorization`).
- **Oxford comma:** yes.
- **Em dashes** for asides — like this — no spaces around a true em dash in prose; the existing
  pages use spaced em dashes (` — `), so match that for consistency.
- **Numbers:** spell out zero–nine in prose; numerals for 10+ and for anything with a unit,
  flag, or version (`3 nodes`, `8443`, `v1alpha2`, `6h`). Always numerals in commands/tables.
- **Bold** for first-use key terms and UI/identity names you want to anchor (`**mesh CA**`).
  Don't bold whole sentences. *Italics* sparingly, for genuine emphasis.
- **Identifiers are always code-formatted:** flags (`--single-node`), files
  (`cli-reference.mdx`), env vars (`C8S_DIR`), values (`role=cds`), ports (`8443`), digests,
  paths. Never leave a flag or filename in plain prose.

---

## 6. Code blocks and shell examples

Code examples are the heart of these docs — make them correct and copy-paste-ready.

- **Always tag the language:** ` ```bash `, ` ```yaml `, ` ```json `, ` ```go `, ` ```text `.
- **Commands are copy-pasteable.** No leading `$` prompt (it breaks copy). Show output
  separately if needed, in its own block or with a comment.

  ````md
  ```bash
  c8s install --single-node
  ```
  ````

- **Placeholders:** use `<ANGLE_BRACKETS>` for values the user must replace, and say what they
  are right after the block. Be consistent (`<NODE_IP>`, `<NAMESPACE>`). Don't mix `$VAR` and
  `<VAR>` styles for user-supplied values.
- **Multi-step procedures** use `<Steps>`/`<Step>`, one logical action per step, with the
  command in the step and a one-line "what this does / how you know it worked" after it.
- **Show verification.** After an install/run step, show how the user confirms success
  (`kubectl get pods -n c8s-system`, expected status). This is a security product — "it should
  work" isn't enough; show the check.
- **YAML manifests:** complete enough to apply, minimal enough to read. Annotate the
  c8s-specific lines (e.g. the `confidential.ai/cw` annotation) in prose, not with inline noise.
- **Keep flags/defaults exact.** If you write a default (`--leader-elect` is `true`,
  `--port` is `8443`), it must match source. When in doubt, check `../c8s`.

---

## 7. Callouts

Use Fumadocs `<Callout>` deliberately — they're signposts, not decoration. One or two per page
at most; if everything is a callout, nothing is.

| Type | Use for | Example |
| --- | --- | --- |
| `type="info"` | Helpful context, orientation, "new here?" pointers. | The site's intro "this walks you end-to-end" note. |
| `type="warn"` | Gotchas, footguns, and **production requirements**. | "The default chart pins **no** measurements — fine for demos, mandatory to set for production." |
| `type="error"` | Genuinely dangerous / breaking actions only. | Flipping `kata.enabled` on a live cluster; running a second service mesh alongside c8s. |

**Roadmap / not-yet-shipped (decided policy: shipped-first, roadmap quarantined).** Don't put
unimplemented features in the happy path. When you must mention one at its point of relevance,
use a short, clearly-labeled callout and link to [Limitations](./content/docs/limitations.mdx):

```md
<Callout type="info">
  **Planned, not yet shipped.** GPU confidential computing (NVIDIA CC mode) is out of scope for
  the current milestone. See [Limitations](/docs/c8s/limitations).
</Callout>
```

The full gap list lives on the Limitations page and tracks `../c8s/docs/GAPS.md`. Keep it honest
and current.

---

## 8. Diagrams (ASCII-first)

- **Default to ASCII art in a fenced block** (` ```text `) for new diagrams — trust boundaries,
  component layouts, flows, sequences. It diffs cleanly, needs no tooling, and matches the
  whitepaper's house style. Study `../whitepapers/c8s-whitepaper/whitepaper-md.md` and the
  `ascii-diagrams` skill for the conventions (double walls `╔═╗` for the CVM/trust boundary,
  single boxes for ordinary components, `─►`/`┈►` for solid/optional flows).
- Keep ASCII diagrams **narrow enough to read** in the content column (~80 cols); align boxes
  on a monospace grid; add a one-line italic caption under it explaining the takeaway.
- **Committed SVGs** (`public/diagrams/*.svg`) are reserved for the existing polished "hero"
  diagrams. Reference them with descriptive alt text:
  `![Base-mode certificate flow: the workload requests a challenge, generates evidence bound
  to its CSR, and the CDS verifies it before signing a leaf.](/diagrams/cert-flow-base.svg)`.
  Don't generate new SVGs for routine diagrams — reach for ASCII.
- There is **no `<Mermaid>` component** (the README is wrong). Don't author Mermaid.

---

## 9. Links and cross-references

- **Internal links use absolute site paths:** `[threat model](/docs/c8s/architecture/threat-model)`
  and `#anchor` for sections. Not relative `../` paths, not `.mdx` extensions.
- **There is no link checker** in CI — broken internal links pass the build. **Verify every
  link by hand**: confirm the target page exists (`content/docs/...`) and the anchor matches a
  real heading. Re-check anchors when you rename a heading.
- **Cross-link generously but purposefully.** This is a journey-structured site; when you name
  a concept defined elsewhere (CDS, allowlist, RA-TLS), link its home page on first use.
- **External links:** whitepaper at `/papers/c8s.pdf`; upstream projects (Kata, Fumadocs)
  linked to their canonical sites. Don't link to the GitHub web UI for repo operations — that's
  a `gh` concern, not a docs one.
- When prose depends on a specific source behavior, it's fine (encouraged) to be precise about
  the component/flag so a reader can grep the code — but link to the *docs* page for the
  concept, not to source files (those move).

---

## 10. Before you call it done

- [ ] Every flag, default, name, and behavior **verified against `../c8s`** (or relevant repo).
- [ ] Terminology matches §4 exactly (casing, hyphenation, one name per concept).
- [ ] New page added to its folder's `meta.json` `pages`; frontmatter `title` + `description`
      present; no `# H1` in body.
- [ ] Code blocks are language-tagged and copy-paste-ready; verification steps shown.
- [ ] Internal links and anchors checked by hand (no link checker will catch them).
- [ ] If a `c8s` CLI flag changed: `cli-reference.mdx` updated and
      `C8S_DIR=/workspace/c8s npm run check:flags` passes.
- [ ] Not-yet-shipped features kept out of the happy path; roadmap items labeled and linked to
      Limitations.
- [ ] `npm run typecheck && npm run lint && npm run build` all pass.
