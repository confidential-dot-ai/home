import { getMarkdownContent } from "@/lib/markdown";
import { MarkdownPage } from "@/components/markdown-page";

export const metadata = { title: "Attestable Builds" };

export default function AttestableBuildsPage() {
  const content = getMarkdownContent("attestable-builds.md");
  return <MarkdownPage content={content} />;
}
