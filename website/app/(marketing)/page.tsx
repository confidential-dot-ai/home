import { getMarkdownContent } from "@/lib/markdown";
import { MarkdownPage } from "@/components/markdown-page";

export default function HomePage() {
  const content = getMarkdownContent("README.md");
  return <MarkdownPage content={content} />;
}
