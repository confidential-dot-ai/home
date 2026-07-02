---
name: attested-builds-terminology
description: The Kettle build feature is branded "Attested Builds" (not "Attestable Builds"); when to keep the word "attestable"
metadata:
  type: project
---

The Kettle build product/feature is branded **"Attested Builds"** across the site (page `/attested-builds`, docs series `/docs/attested-builds/`). It was renamed from "Attestable Builds" on 2026-07-02; old URLs 301-redirect via `redirects()` in `website/next.config.ts`.

**Why:** Standardizes on the term already used in the newer blog post (`blog/kettle-attested-builds.md`) and the Kettle whitepaper title.

**How to apply:** Rename the *feature/product noun phrase* "attestable build(s)" → "attested build(s)". But KEEP the word "attestable" when used as a plain adjective meaning *able to be attested* — e.g. "attestable image", "attestable measurement/digest", "the CVM is itself attestable". Also KEEP it in `docs/kettle-whitepaper.md` §3.3 and its citations, which deliberately reference the academic term (the cited CCS'25 paper is titled "Attestable Builds"). The `pricing.md` heading is `## Attested Builds`, and `website/lib/llms.ts` extracts its table by that exact string — keep them in sync.
