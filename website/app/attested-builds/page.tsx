import { getMarkdownContent } from "@/lib/markdown";
import { MarkdownPage } from "@/components/markdown-page";

export const metadata = { title: "Attested Builds" };

export default function AttestedBuildsPage() {
  const content = getMarkdownContent("attested-builds.md");
  return <MarkdownPage content={content} />;
}
