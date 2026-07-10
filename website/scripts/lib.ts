/**
 * Shared logic for the CLI flag-completeness check.
 *
 * `extractSourceFlags` parses flag registrations out of the c8s Go source;
 * `extractDocFlags` parses the documented flag tables out of the CLI reference
 * MDX. Both bucket flags by command so the checker can diff per command.
 *
 * The mapping below is the single place to update if the c8s source layout
 * changes — keep it in sync with the repo.
 */
import { readFileSync } from 'node:fs';
import { join } from 'node:path';

export interface SourceFlag {
  name: string;
  /** The trimmed Go registration line — context for the AI review. */
  line: string;
  file: string;
}

export interface CommandSource {
  command: string;
  flags: SourceFlag[];
  /** Files that were scanned (for diagnostics). */
  files: string[];
}

interface CommandSpec {
  command: string;
  /** Source files (relative to the c8s repo root) that register this command's flags. */
  files: string[];
  /**
   * Extra files scanned for constant definitions only (not flag registrations).
   * Use when a command registers a flag via a Go constant defined elsewhere —
   * e.g. render-values registers `--cvm-mode` via `flagCvmMode`, which is defined
   * in install.go.
   */
  constFiles?: string[];
  /**
   * When true, also match standard-library `flag` package registrations
   * (`fs.String("name", …)`). Only nri-image-policy uses the stdlib flag package;
   * the rest use cobra/pflag `*Var` registrations.
   */
  stdlib?: boolean;
}

/**
 * Command → source files. The ratls-mesh `in-guest readiness-check` subcommand
 * (in_guest_linux.go) is an internal guest helper and is intentionally NOT part
 * of the operator-facing CLI surface documented in the reference.
 */
export const C8S_COMMANDS: CommandSpec[] = [
  { command: 'install', files: ['cmd/c8s/install.go'] },
  { command: 'uninstall', files: ['cmd/c8s/uninstall.go'] },
  // render-values reuses install's flag vars; --cvm-mode is registered via the
  // flagCvmMode constant defined in install.go, so scan it for constants.
  {
    command: 'render-values',
    files: ['cmd/c8s/render_values.go'],
    constFiles: ['cmd/c8s/install.go'],
  },
  { command: 'operator', files: ['cmd/c8s/operator.go'] },
  { command: 'cds', files: ['internal/cmds/cds/cmd.go'] },
  // cds-attest is a separate top-level command (the tls-lb attestation +
  // over-encryption sidecar), not a `cds` subcommand — its flags live in cdsattest.
  { command: 'cds-attest', files: ['internal/cmds/cdsattest/cmd.go'] },
  // Persistent flags live in cmd.go; the write subcommands (add/remove/upload)
  // register their own flags in write.go. read.go registers none.
  {
    command: 'allowlist',
    files: ['internal/cmds/allowlist/cmd.go', 'internal/cmds/allowlist/write.go'],
  },
  { command: 'verify', files: ['internal/cmds/verify/verify.go'] },
  { command: 'get-cert', files: ['internal/cmds/getcert/run.go'] },
  { command: 'ratls-mesh', files: ['internal/cmds/ratlsmesh/main.go'] },
  {
    command: 'nri-image-policy',
    files: ['internal/cmds/nri-image-policy/main.go'],
    stdlib: true,
  },
];

/** The MDX file documenting the CLI, relative to the website root. */
export const CLI_REFERENCE_MDX = 'content/docs/c8s/install/cli-reference.mdx';

// pflag `*Var` / `*VarP` registrations. First arg is `&variable`; the flag name
// (second arg) may be a string literal OR a Go constant identifier (e.g. cvm-mode
// is registered as `flagCvmMode`), so capture both forms.
const PFLAG_VAR = new RegExp(
  String.raw`\.(?:String|Bool|Int|Int8|Int16|Int32|Int64|Uint|Uint8|Uint16|Uint32|Uint64|Float32|Float64|Duration|StringSlice|StringArray|IntSlice|IP|Count|BytesHex)Var[P]?\(\s*&[A-Za-z0-9_.]+\s*,\s*(?:"([a-z][\w-]*)"|([A-Za-z_]\w*))\s*,`,
  'g',
);

// Standard-library `flag` package (and pflag non-Var): name is the first string arg.
const STDLIB_FLAG = new RegExp(
  String.raw`\.(?:String|Bool|Int|Int64|Uint|Uint64|Float64|Duration)[P]?\(\s*"([a-z][\w-]*)"\s*,`,
  'g',
);

// `const flagCvmMode = "cvm-mode"` / `flagX = "x"` — resolve constant flag names.
const STRING_CONST = /\b([A-Za-z_]\w*)\s*=\s*"([a-z][\w-]+)"/g;

/** Parse `const name = "value"` flag-name constants out of a source file. */
function collectConsts(src: string): Map<string, string> {
  const consts = new Map<string, string>();
  let cm: RegExpExecArray | null;
  STRING_CONST.lastIndex = 0;
  while ((cm = STRING_CONST.exec(src)) !== null) consts.set(cm[1], cm[2]);
  return consts;
}

function extractFromFile(
  absPath: string,
  relPath: string,
  stdlib: boolean,
  consts: Map<string, string>,
): SourceFlag[] {
  const src = readFileSync(absPath, 'utf-8');

  const found = new Map<string, SourceFlag>();
  const add = (name: string | undefined, line: string) => {
    if (name && !found.has(name)) {
      found.set(name, { name, line: line.trim(), file: relPath });
    }
  };

  for (const line of src.split('\n')) {
    const trimmed = line.trim();
    if (trimmed.startsWith('//')) continue;

    PFLAG_VAR.lastIndex = 0;
    let m: RegExpExecArray | null;
    while ((m = PFLAG_VAR.exec(line)) !== null) {
      const literal = m[1];
      const ident = m[2];
      add(literal ?? (ident ? consts.get(ident) : undefined), line);
    }

    if (stdlib) {
      STDLIB_FLAG.lastIndex = 0;
      while ((m = STDLIB_FLAG.exec(line)) !== null) add(m[1], line);
    }
  }
  return [...found.values()];
}

/**
 * Parse flag registrations out of the c8s Go source. Throws if a command yields
 * zero flags — that almost always means the source moved and the config above is
 * stale, which we want to surface loudly rather than silently pass.
 */
export function extractSourceFlags(c8sRoot: string): CommandSource[] {
  return C8S_COMMANDS.map((spec) => {
    // Build a constant map spanning the command's files plus any constFiles, so a
    // flag registered via a constant defined in another file still resolves.
    const consts = new Map<string, string>();
    for (const rel of [...spec.files, ...(spec.constFiles ?? [])]) {
      const abs = join(c8sRoot, rel);
      try {
        for (const [k, v] of collectConsts(readFileSync(abs, 'utf-8'))) {
          if (!consts.has(k)) consts.set(k, v);
        }
      } catch (err) {
        throw new Error(
          `cannot read ${abs} for command "${spec.command}": ${(err as Error).message}\n` +
            `Update C8S_COMMANDS in scripts/lib.ts if the c8s source layout changed.`,
        );
      }
    }

    const flags = new Map<string, SourceFlag>();
    for (const rel of spec.files) {
      const abs = join(c8sRoot, rel);
      let fileFlags: SourceFlag[] = [];
      try {
        fileFlags = extractFromFile(abs, rel, Boolean(spec.stdlib), consts);
      } catch (err) {
        throw new Error(
          `cannot read ${abs} for command "${spec.command}": ${(err as Error).message}\n` +
            `Update C8S_COMMANDS in scripts/lib.ts if the c8s source layout changed.`,
        );
      }
      for (const f of fileFlags) if (!flags.has(f.name)) flags.set(f.name, f);
    }
    if (flags.size === 0) {
      throw new Error(
        `extracted 0 flags for command "${spec.command}" from ${spec.files.join(', ')}. ` +
          `The source layout or registration pattern likely changed — update scripts/lib.ts.`,
      );
    }
    return {
      command: spec.command,
      files: spec.files,
      flags: [...flags.values()].sort((a, b) => a.name.localeCompare(b.name)),
    };
  });
}

export interface CommandDoc {
  command: string;
  flags: string[];
}

// First-cell long flag in a markdown table row, e.g. `| `--namespace` | … |`.
const TABLE_FLAG = /--[a-z][\w-]*/;

/**
 * Parse the documented flags out of the CLI reference MDX. Sections are delimited
 * by `{/* flags:<command> *␣/}` markers; within a section, flag names are read
 * from the first cell of each table row only (so flags mentioned in descriptions,
 * like `helm --skip-crds`, are ignored).
 */
export function extractDocFlags(docsRoot: string): CommandDoc[] {
  const text = readFileSync(join(docsRoot, CLI_REFERENCE_MDX), 'utf-8');
  const marker = /\{\/\*\s*flags:([a-z-]+)\s*\*\/\}/g;

  const sections: { command: string; start: number }[] = [];
  let m: RegExpExecArray | null;
  while ((m = marker.exec(text)) !== null) {
    sections.push({ command: m[1], start: m.index });
  }

  return sections.map((sec, i) => {
    const end = i + 1 < sections.length ? sections[i + 1].start : text.length;
    const body = text.slice(sec.start, end);
    const flags = new Set<string>();
    for (const line of body.split('\n')) {
      if (!line.trimStart().startsWith('|')) continue; // table rows only
      const firstCell = line.split('|')[1] ?? '';
      if (/^[\s-]*$/.test(firstCell)) continue; // separator / empty
      const hit = firstCell.match(TABLE_FLAG);
      if (hit) flags.add(hit[0].slice(2)); // store bare name (no leading `--`)
    }
    return { command: sec.command, flags: [...flags].sort() };
  });
}

export interface CommandDiff {
  command: string;
  missing: string[]; // in source, not documented  → gate failure
  extra: string[]; // documented, not in source → gate failure (stale)
  ok: number; // count documented correctly
}

export function diffFlags(
  source: CommandSource[],
  docs: CommandDoc[],
): CommandDiff[] {
  const docByCmd = new Map(docs.map((d) => [d.command, new Set(d.flags)]));
  return source.map((s) => {
    const documented = docByCmd.get(s.command) ?? new Set<string>();
    const sourceNames = new Set(s.flags.map((f) => f.name));
    const missing = [...sourceNames].filter((n) => !documented.has(n)).sort();
    const extra = [...documented].filter((n) => !sourceNames.has(n)).sort();
    const ok = [...sourceNames].filter((n) => documented.has(n)).length;
    return { command: s.command, missing, extra, ok };
  });
}

/** Resolve the c8s checkout location (CI sets C8S_DIR; default ./_c8s, then /workspace/c8s). */
export function resolveC8sRoot(): string {
  const candidates = [
    process.env.C8S_DIR,
    join(process.cwd(), '_c8s'),
    '/workspace/c8s',
  ].filter(Boolean) as string[];
  for (const c of candidates) {
    try {
      readFileSync(join(c, 'go.mod'));
      return c;
    } catch {
      /* try next */
    }
  }
  throw new Error(
    `c8s checkout not found. Set C8S_DIR to the c8s repo root (looked in: ${candidates.join(', ')}).`,
  );
}
