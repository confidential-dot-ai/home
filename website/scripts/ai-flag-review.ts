/**
 * Advisory, non-blocking semantic review of the CLI reference using a lightweight
 * model (Claude Haiku 4.5). The deterministic gate in check-flags.ts already
 * guarantees the *set* of flags matches; this catches what a set-diff cannot —
 * stale default values, descriptions that drifted from the source help text, and
 * incorrect required markers.
 *
 * Skips cleanly (exit 0, no output file) when ANTHROPIC_API_KEY is absent, so the
 * workflow never fails on a missing secret.
 *
 *   ANTHROPIC_API_KEY=… C8S_DIR=/path/to/c8s npm run ai:flags
 */
import { readFileSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import Anthropic from '@anthropic-ai/sdk';
import {
  extractSourceFlags,
  resolveC8sRoot,
  CLI_REFERENCE_MDX,
} from './lib.ts';

const MODEL = 'claude-haiku-4-5';

const INSTRUCTIONS = `You are a precise technical-documentation reviewer for the c8s CLI.

You are given (1) the DOCUMENTED CLI reference (markdown tables) and (2) the AUTHORITATIVE
flag registrations extracted from the c8s Go source (one line per flag, showing the real
default value and help string).

Report ONLY concrete, actionable discrepancies where the docs and source disagree:
- a documented default value that differs from the source default;
- a documented description that no longer matches the source help string in a way that
  misleads;
- a required/optional marker that is wrong.

Rules:
- Do NOT restate flags that match. Do NOT invent issues. Do NOT comment on flags absent from
  one side (a separate deterministic check handles set membership).
- Be terse. Group by command. Cite the flag as \`--name\`.
- Output GitHub-flavored markdown.
- If you find nothing, output exactly: No discrepancies found.`;

async function main(): Promise<void> {
  const apiKey = process.env.ANTHROPIC_API_KEY;
  const outPath = process.env.AI_REVIEW_OUT;

  if (!apiKey) {
    // eslint-disable-next-line no-console
    console.log('ANTHROPIC_API_KEY not set — skipping advisory AI review.');
    return;
  }

  const c8sRoot = resolveC8sRoot();
  const docsRoot = process.cwd();
  const docText = readFileSync(join(docsRoot, CLI_REFERENCE_MDX), 'utf-8');
  const source = extractSourceFlags(c8sRoot);

  const sourceDump = source
    .map(
      (s) =>
        `### c8s ${s.command}\n` +
        s.flags.map((f) => `- --${f.name}  ::  ${f.line}`).join('\n'),
    )
    .join('\n\n');

  const client = new Anthropic({ apiKey });
  const resp = await client.messages.create({
    model: MODEL,
    max_tokens: 1500,
    // The instructions + documented reference are static across a run, so cache them.
    system: [
      { type: 'text', text: INSTRUCTIONS },
      {
        type: 'text',
        text: `DOCUMENTED CLI REFERENCE (target):\n\n${docText}`,
        cache_control: { type: 'ephemeral' },
      },
    ],
    messages: [
      {
        role: 'user',
        content: `AUTHORITATIVE source flag registrations:\n\n${sourceDump}`,
      },
    ],
  });

  const body = resp.content
    .filter((b): b is Anthropic.TextBlock => b.type === 'text')
    .map((b) => b.text)
    .join('\n')
    .trim();

  const clean = body === 'No discrepancies found.';
  const comment =
    `### 🤖 CLI flag review (Claude Haiku 4.5)\n\n` +
    (clean
      ? 'No semantic discrepancies between the documented flags and the c8s source. ✅'
      : body) +
    `\n\n<sub>Advisory only — the deterministic flag-completeness check is the gate.</sub>`;

  // eslint-disable-next-line no-console
  console.log(comment);
  if (outPath) writeFileSync(outPath, comment);
}

main().catch((err) => {
  // Advisory step: never fail the build on an API/SDK error.
  // eslint-disable-next-line no-console
  console.warn(`AI review skipped due to error: ${(err as Error).message}`);
});
