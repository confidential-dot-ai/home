import { getMarkdownContent } from "@/lib/markdown";
import { MarkdownPageWithToc } from "@/components/markdown-page-with-toc";

export const metadata = { title: "Careers" };

export default function CareersPage() {
  const content = getMarkdownContent("careers/README.md");
  return <MarkdownPageWithToc content={content} />;
}
