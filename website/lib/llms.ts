import fs from "fs";
import path from "path";

const CONTENT_ROOT = path.resolve(process.cwd(), "..");
const WEBSITE_ROOT = process.cwd();
const DOCS_ROOT = path.join(WEBSITE_ROOT, "content", "docs");
const SITE_URL = "https://confidential.ai";

const EXCLUDED_ROOT_FILES = new Set(["CLAUDE.md"]);
// Docs are handled separately (Fumadocs content tree); blog/careers still live
// at the repo root as plain markdown.
const CONTENT_SUBDIRS = ["blog", "careers"];

export interface ContentFile {
  relPath: string;
  url: string;
  fullUrl: string;
  title: string;
  content: string;
}

function readRepoFile(relPath: string): string {
  const resolved = path.resolve(CONTENT_ROOT, relPath);
  if (
    !resolved.startsWith(CONTENT_ROOT + path.sep) &&
    resolved !== CONTENT_ROOT
  ) {
    throw new Error(`Path traversal: ${relPath}`);
  }
  return fs.readFileSync(resolved, "utf-8");
}

function readWebsiteFile(relPath: string): string {
  return fs.readFileSync(path.resolve(WEBSITE_ROOT, relPath), "utf-8");
}

function relPathToUrl(relPath: string): string {
  if (relPath === "README.md") return "/";
  let url = "/" + relPath.replace(/\.md$/, "");
  url = url.replace(/\/README$/, "");
  return url;
}

function extractTitle(content: string, fallback: string): string {
  const match = content.match(/^#\s+(.+?)$/m);
  if (!match) return fallback;
  return match[1].trim().replace(/\*\*/g, "").replace(/\*/g, "");
}

function sortContentFiles(files: string[]): string[] {
  return files.sort((a, b) => {
    const aIsReadme = path.basename(a) === "README.md";
    const bIsReadme = path.basename(b) === "README.md";
    if (aIsReadme && !bIsReadme) return -1;
    if (!aIsReadme && bIsReadme) return 1;
    return a.localeCompare(b);
  });
}

function walkDir(dirRelPath: string): string[] {
  const dirAbs = path.resolve(CONTENT_ROOT, dirRelPath);
  if (!fs.existsSync(dirAbs)) return [];

  const entries = fs.readdirSync(dirAbs, { withFileTypes: true });
  const files: string[] = [];
  const subdirs: string[] = [];

  for (const entry of entries) {
    const childRelPath = path.join(dirRelPath, entry.name);
    if (entry.isFile() && entry.name.endsWith(".md")) {
      files.push(childRelPath);
    } else if (entry.isDirectory()) {
      subdirs.push(childRelPath);
    }
  }

  const result: string[] = [];
  result.push(...sortContentFiles(files));
  for (const subdir of subdirs.sort()) {
    result.push(...walkDir(subdir));
  }
  return result;
}

// ── Docs (Fumadocs MDX tree under website/content/docs) ─────────────

/** Strip a leading YAML frontmatter block, returning { title, body }. */
function parseFrontmatter(raw: string): { title?: string; body: string } {
  const m = raw.match(/^---\n([\s\S]*?)\n---\n?/);
  if (!m) return { body: raw };
  const titleMatch = m[1].match(/^title:\s*(.+)$/m);
  let title = titleMatch?.[1]?.trim();
  if (title && /^["'].*["']$/.test(title)) title = title.slice(1, -1);
  return { title, body: raw.slice(m[0].length) };
}

/** File path relative to content/docs → site URL. */
function docsRelToUrl(rel: string): string {
  let url = "/docs/" + rel.replace(/\.mdx?$/, "");
  url = url.replace(/\/index$/, "");
  return url.replace(/\/$/, "");
}

/** Walk the docs tree; index files first within a folder, then alphabetical. */
function walkDocs(dirAbs: string, relPrefix: string): string[] {
  if (!fs.existsSync(dirAbs)) return [];
  const entries = fs.readdirSync(dirAbs, { withFileTypes: true });
  const files: string[] = [];
  const subdirs: string[] = [];
  for (const entry of entries) {
    const rel = relPrefix ? `${relPrefix}/${entry.name}` : entry.name;
    if (entry.isFile() && /\.mdx?$/.test(entry.name)) files.push(rel);
    else if (entry.isDirectory()) subdirs.push(rel);
  }
  files.sort((a, b) => {
    const ai = /(^|\/)index\.mdx?$/.test(a);
    const bi = /(^|\/)index\.mdx?$/.test(b);
    if (ai && !bi) return -1;
    if (!ai && bi) return 1;
    return a.localeCompare(b);
  });
  const result = [...files];
  for (const sub of subdirs.sort()) {
    result.push(...walkDocs(path.join(dirAbs, path.basename(sub)), sub));
  }
  return result;
}

function discoverDocs(): ContentFile[] {
  return walkDocs(DOCS_ROOT, "").map((rel) => {
    const raw = fs.readFileSync(path.join(DOCS_ROOT, rel), "utf-8");
    const { title, body } = parseFrontmatter(raw);
    const url = docsRelToUrl(rel);
    const resolvedTitle = title ?? extractTitle(body, rel);
    return {
      // Synthetic repo-relative path so buildDocsIndex's `docs/` filter + depth
      // math keep working with the new tree.
      relPath: "docs/" + rel,
      url,
      fullUrl: SITE_URL + url,
      title: resolvedTitle,
      content: `# ${resolvedTitle}\n\n${body.trim()}`,
    };
  });
}

export function discoverContent(): ContentFile[] {
  const rootEntries = fs.readdirSync(CONTENT_ROOT, { withFileTypes: true });
  const rootFiles: string[] = [];
  for (const entry of rootEntries) {
    if (
      entry.isFile() &&
      entry.name.endsWith(".md") &&
      !EXCLUDED_ROOT_FILES.has(entry.name)
    ) {
      rootFiles.push(entry.name);
    }
  }

  const result: ContentFile[] = sortContentFiles(rootFiles).map((relPath) => {
    const content = readRepoFile(relPath);
    const url = relPathToUrl(relPath);
    return {
      relPath,
      url,
      fullUrl: SITE_URL + url,
      title: extractTitle(content, relPath),
      content,
    };
  });

  // Docs (Fumadocs tree).
  result.push(...discoverDocs());

  // Blog + careers (repo-root markdown).
  for (const subdir of CONTENT_SUBDIRS) {
    for (const relPath of walkDir(subdir)) {
      const content = readRepoFile(relPath);
      const url = relPathToUrl(relPath);
      result.push({
        relPath,
        url,
        fullUrl: SITE_URL + url,
        title: extractTitle(content, relPath),
        content,
      });
    }
  }

  return result;
}

export function buildLlmsFullText(): string {
  const intro = readWebsiteFile("content/llms-full-intro.md").trim();
  const sections = discoverContent().map((f) => f.content.trim());
  return [intro, ...sections].join("\n\n---\n\n") + "\n";
}

function extractTableAfter(filePath: string, marker: string): string {
  const content = readRepoFile(filePath);
  const escaped = marker.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
  const markerPattern = new RegExp(escaped, "m");
  const markerMatch = content.match(markerPattern);
  if (!markerMatch || markerMatch.index === undefined) {
    throw new Error(`Marker not found in ${filePath}: ${marker}`);
  }

  const afterMarker = content.slice(markerMatch.index + markerMatch[0].length);
  const lines = afterMarker.split("\n");

  const tableLines: string[] = [];
  let foundTable = false;
  for (const line of lines) {
    if (line.trim().startsWith("|")) {
      tableLines.push(line);
      foundTable = true;
    } else if (foundTable) {
      break;
    }
  }

  if (tableLines.length === 0) {
    throw new Error(`No table found after "${marker}" in ${filePath}`);
  }
  return tableLines.join("\n");
}

function buildPagesIndex(files: ContentFile[]): string {
  return files
    .filter((f) => !f.relPath.includes("/"))
    .map((f) => `- [${f.title}](${f.fullUrl})`)
    .join("\n");
}

function buildBlogIndex(files: ContentFile[]): string {
  return files
    .filter(
      (f) => f.relPath.startsWith("blog/") && f.relPath !== "blog/README.md",
    )
    .map((f) => `- [${f.title}](${f.fullUrl})`)
    .join("\n");
}

function buildDocsIndex(files: ContentFile[]): string {
  return files
    .filter((f) => f.relPath.startsWith("docs/"))
    .map((f) => {
      const segments = f.relPath.split("/");
      const depth = Math.max(0, segments.length - 2);
      const indent = "  ".repeat(depth);
      return `${indent}- [${f.title}](${f.fullUrl})`;
    })
    .join("\n");
}

export function buildLlmsText(): string {
  const template = readWebsiteFile("content/llms-template.md");
  const files = discoverContent();

  const substitutions: Record<string, string> = {
    "{{gpu_vms_table}}": extractTableAfter("pricing.md", "**GPU VMs**"),
    "{{cpu_vms_table}}": extractTableAfter("pricing.md", "**CPU VMs**"),
    "{{inference_pricing_table}}": extractTableAfter(
      "pricing.md",
      "## Confidential Inference",
    ),
    "{{attested_builds_table}}": extractTableAfter(
      "pricing.md",
      "## Attested Builds",
    ),
    "{{pages_index}}": buildPagesIndex(files),
    "{{blog_index}}": buildBlogIndex(files),
    "{{docs_index}}": buildDocsIndex(files),
  };

  let result = template;
  for (const [key, value] of Object.entries(substitutions)) {
    if (!result.includes(key)) {
      throw new Error(
        `Template placeholder ${key} not found in llms-template.md`,
      );
    }
    result = result.split(key).join(value);
  }

  const leftover = /\{\{[^}]+\}\}/.exec(result);
  if (leftover) {
    throw new Error(`Unsubstituted placeholder: ${leftover[0]}`);
  }

  return result;
}
