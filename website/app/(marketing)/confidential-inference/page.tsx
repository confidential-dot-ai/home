import { getMarkdownContent } from "@/lib/markdown";
import { MarkdownPage } from "@/components/markdown-page";

export const metadata = { title: "Confidential Inference" };

export default function ConfidentialInferencePage() {
  const content = getMarkdownContent("confidential-inference.md");
  return <MarkdownPage content={content} />;
}
