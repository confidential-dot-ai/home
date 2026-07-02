/**
 * Deterministic gate: fail if the CLI reference does not document exactly the
 * flags the c8s source registers. Run by the flag-completeness GitHub Action and
 * locally with `npm run check:flags`.
 *
 *   C8S_DIR=/path/to/c8s npm run check:flags
 *
 * Exits non-zero when any command has undocumented ("missing") or stale ("extra")
 * flags. Writes a summary table to $GITHUB_STEP_SUMMARY when running in CI.
 */
import { appendFileSync } from 'node:fs';
import {
  extractSourceFlags,
  extractDocFlags,
  diffFlags,
  resolveC8sRoot,
} from './lib.ts';

function main(): number {
  const c8sRoot = resolveC8sRoot();
  const docsRoot = process.cwd();

  const source = extractSourceFlags(c8sRoot);
  const docs = extractDocFlags(docsRoot);
  const diffs = diffFlags(source, docs);

  const totalSource = source.reduce((n, s) => n + s.flags.length, 0);
  const totalMissing = diffs.reduce((n, d) => n + d.missing.length, 0);
  const totalExtra = diffs.reduce((n, d) => n + d.extra.length, 0);
  const pass = totalMissing === 0 && totalExtra === 0;

  const lines: string[] = [];
  lines.push('## c8s CLI flag completeness');
  lines.push('');
  lines.push(`Source: \`${c8sRoot}\` · ${totalSource} flags across ${source.length} commands.`);
  lines.push('');
  lines.push(pass ? '✅ **Documentation is complete and current.**' : '❌ **Documentation is out of sync.**');
  lines.push('');
  lines.push('| Command | Documented | Missing (in source, undocumented) | Stale (documented, not in source) |');
  lines.push('| --- | --- | --- | --- |');
  for (const d of diffs) {
    const missing = d.missing.length ? d.missing.map((f) => `\`--${f}\``).join(', ') : '—';
    const extra = d.extra.length ? d.extra.map((f) => `\`--${f}\``).join(', ') : '—';
    lines.push(`| \`c8s ${d.command}\` | ${d.ok} | ${missing} | ${extra} |`);
  }
  const report = lines.join('\n');

  // eslint-disable-next-line no-console
  console.log(report);
  if (process.env.GITHUB_STEP_SUMMARY) {
    appendFileSync(process.env.GITHUB_STEP_SUMMARY, report + '\n');
  }

  if (!pass) {
    // eslint-disable-next-line no-console
    console.error(
      `\nFlag check failed: ${totalMissing} undocumented, ${totalExtra} stale. ` +
        `Update ${'content/docs/c8s/install/cli-reference.mdx'}.`,
    );
    return 1;
  }
  return 0;
}

process.exit(main());
