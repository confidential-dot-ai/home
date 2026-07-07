import fs from "fs";
import path from "path";

const CONTENT_ROOT = path.resolve(process.cwd(), "..");
const WEBSITE_ROOT = process.cwd();
const SITE_URL = "https://confidential.ai";

const EXCLUDED_ROOT_FILES = new Set(["CLAUDE.md"]);
const CONTENT_SUBDIRS = ["blog", "careers", "docs"];

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

export function discoverContent(): ContentFile[] {
  const allFiles: string[] = [];

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
  allFiles.push(...sortContentFiles(rootFiles));

  for (const subdir of CONTENT_SUBDIRS) {
    allFiles.push(...walkDir(subdir));
  }

  return allFiles.map((relPath) => {
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
