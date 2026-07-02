import fs from "fs";
import path from "path";
import { getMarkdownContent } from "@/lib/markdown";
import { MarkdownPageWithToc } from "@/components/markdown-page-with-toc";
import type { TocItem } from "@/components/table-of-contents";

export const metadata = { title: "Docs" };

const DOCS_ROOT = path.resolve(process.cwd(), "..", "docs");

const SECTIONS: { title: string; href: string; file: string }[] = [
  { title: "Introduction to TEEs", href: "/docs/intro-to-tees", file: "intro-to-tees.md" },
  { title: "Confidential Computing Primer", href: "/docs/confidential-computing-primer", file: "confidential-computing-primer/README.md" },
  { title: "C8s: Confidential Kubernetes", href: "/docs/c8s-whitepaper", file: "c8s-whitepaper.md" },
  { title: "Kettle: Attested Builds", href: "/docs/kettle-whitepaper", file: "kettle-whitepaper.md" },
  { title: "Attested Builds", href: "/docs/attested-builds", file: "attested-builds/README.md" },
  { title: "Zero Knowledge", href: "/docs/zk", file: "zk.md" },
  { title: "Confidential Agents API", href: "/docs/confidential-agents-api", file: "confidential-agents-api.md" },
];

function buildDocsToc(): TocItem[] {
  return SECTIONS
    .filter((s) => fs.existsSync(path.join(DOCS_ROOT, s.file)))
    .map((s) => ({ id: "", text: s.title, level: 3, href: s.href }));
}

export default function DocsPage() {
  const content = getMarkdownContent("docs/README.md");
  const extraTocItems = buildDocsToc();
  return (
    <MarkdownPageWithToc
      content={content}
      extraTocItems={extraTocItems}
      insertAfterId="documentation-sections"
    />
  );
}
