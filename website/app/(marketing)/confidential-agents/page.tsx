import { getMarkdownContent } from "@/lib/markdown";
import { MarkdownPageWithToc } from "@/components/markdown-page-with-toc";

export const metadata = { title: "Confidential Agents" };

export default function ConfidentialAgentsPage() {
  const content = getMarkdownContent("confidential-agents.md");
  return <MarkdownPageWithToc content={content} />;
}
