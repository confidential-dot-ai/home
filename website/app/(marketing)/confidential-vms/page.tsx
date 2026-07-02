import { getMarkdownContent } from "@/lib/markdown";
import { MarkdownPage } from "@/components/markdown-page";

export const metadata = { title: "Confidential VMs" };

export default function ConfidentialVmsPage() {
  const content = getMarkdownContent("confidential-vms.md");
  return <MarkdownPage content={content} />;
}
