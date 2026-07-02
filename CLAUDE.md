# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Repository Overview

Public-facing content and website for **Confidential AI** (formerly Lunal), an AI confidential compute platform. The repo has two layers: markdown content files at the root, and a Next.js website in `website/` that renders them.

## Commands

```bash
# Development (from website/)
cd website && npm run dev       # Start dev server at localhost:3000
cd website && npm run build     # Production build (also validates all pages render)
cd website && npm run lint      # ESLint

# No test suite exists.
```

## Architecture

The site has **two content systems** in one Next.js app:

### Marketing content (repo root `.md`)

Markdown files at the repo root are the source of truth for the marketing pages. The website reads them at build time.

- Top-level `.md` files: `README.md` (home), `cloud.md`, `pricing.md`, `products.md`, `team.md`, `confidential-*.md`, `attestable-builds.md`
- `blog/` — Blog posts
- `careers/` — Careers page

Rendered with `react-markdown`. **Docs are no longer here** — see below.

### Docs (`website/content/docs/**`, Fumadocs MDX)

All documentation lives inside the app as **MDX** with `meta.json` sidebar ordering, served by **Fumadocs** at `/docs`:

- `content/docs/index.mdx` — the docs hub (the "From zero to verified, in four steps" `<FourSteps />` block + section cards)
- `content/docs/c8s/**` — the c8s platform docs (migrated from the standalone c8s-docs site)
- `content/docs/concepts/**`, `whitepapers/**`, `attestable-builds/**`, `api/**` — the rest, re-architected from the old repo-root `docs/`

Authoring voice/terminology/formatting: `STYLE_GUIDE.md` at the repo root.

### Website (`website/`)

Next.js 16 + React 19 + Tailwind 4. Marketing pages use `react-markdown`; docs use Fumadocs. Route groups keep them separate:

- **`app/(marketing)/`** — marketing pages, wrapped by the left `components/sidebar.tsx`. Each page calls `getMarkdownContent("<name>.md")` and renders `components/markdown-page.tsx` (remark-gfm, rehype-raw, rehype-slug; internal links become `<Link>`s). Marketing prose is styled via the `.prose` class in `app/globals.css`.
- **`app/docs/`** — Fumadocs `DocsLayout` (`app/docs/layout.tsx`) + the MDX renderer (`app/docs/[[...slug]]/page.tsx`). `source.config.ts` + `lib/source.ts` load the content collection; `content/docs/**` is generated into `.source/` by `fumadocs-mdx` (gitignored). Search: `app/api/search/route.ts`.

**Theme:** light-default with a dark toggle. The pre-paint script in `app/layout.tsx` sets both `data-theme` (home tokens) and the `.dark` class (Fumadocs' dark tokens + `dark:` utilities). `app/globals.css` maps Fumadocs' `--color-fd-*` tokens onto the home palette so docs and marketing share one theme and one `ThemeToggle`. Fumadocs' own `next-themes` is disabled.

**Navigation / sidebar overtake:** on marketing routes the left rail is `components/sidebar.tsx`; on `/docs/**` the Fumadocs docs tree "overtakes" it, with a **back-to-site** banner (`components/docs-sidebar-extras.tsx`) pinned at the top.

**Diagrams:** committed docs SVGs are dark-palette; a recolored `*-light.svg` sits beside each, and `components/diagram.tsx` (wired as the `img` MDX component) swaps them per theme via a no-JS `.dark` CSS rule. `source.config.ts` disables Fumadocs' image import so `/diagrams/*.svg` paths stay literal.

**Redirects:** in `next.config.ts` — legacy marketing redirects (`/components`, `/enterprise`, `/agents-api`) plus 301s for docs URLs moved during the re-architecture (e.g. `/docs/intro-to-tees` → `/docs/concepts/intro-to-tees`).

**CLI flag gate:** `scripts/check-flags.ts` (+ `lib.ts`, `ai-flag-review.ts`) keep `content/docs/c8s/install/cli-reference.mdx` in sync with the `c8s` Go source; enforced by `.github/workflows/flag-completeness.yml` (needs `C8S_REPO_TOKEN` to check out `../c8s` in CI). `.github/workflows/ci.yml` runs typecheck/lint/build. Both run from the `website/` subdir.

**LLM text:** `lib/llms.ts` builds `/llms.txt` and `/llms-full.txt` from the marketing `.md`, the Fumadocs docs tree, and `blog/`/`careers/`.

### Adding a page

**Marketing page:**
1. Create `<name>.md` at the repo root
2. Create `website/app/(marketing)/<name>/page.tsx` following an existing page (call `getMarkdownContent`, render `MarkdownPage`)
3. Add it to `SECTIONS` in `website/components/sidebar.tsx`

**Docs page:**
1. Create `website/content/docs/<section>/<name>.mdx` with `title` + `description` frontmatter (no `# H1` — the frontmatter title *is* the H1)
2. Add its file stem to that folder's `meta.json` `pages` array, or it won't appear in the sidebar
3. MDX components available: `Card(s)`, `Tab(s)`, `Step(s)`, `Accordion(s)`, `Callout`, `JourneyNav`, `FourSteps` (see `components/mdx.tsx`)

## TEE Content Reading Path

Docs are a progressive reading path for TEE knowledge:
1. `/docs/concepts/intro-to-tees` — Accessible high-level introduction
2. `blog/secure-ai-needs-tees.md` — AI-specific argument (links to the intro for general background)
3. `/docs/concepts/confidential-computing-primer` — Deep technical series (assumes virtualization and cryptography knowledge)

General TEE education lives under `/docs/concepts`. AI-specific TEE content lives in the blog. Avoid duplicating TEE fundamentals across both — link instead.

## Formatting Conventions

**Internal links:** Use root-relative paths (`/docs/`, `/cloud.md`). Keep link text concise (WCAG/SEO).

**Email links:** Use linkified text like `[Contact us](mailto:hello@confidential.ai)`, not bare addresses.

**Headings:** H1 for page title, H2 for major sections, H3 for subsections.

## Commit Message Style

Lowercase, descriptive, action-oriented. Examples:
- `add cloud and pricing pages to website navbar`
- `move careers and team to footer alongside social icons`
