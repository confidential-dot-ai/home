import { getMarkdownContent } from "@/lib/markdown";
import { MarkdownPageWithToc } from "@/components/markdown-page-with-toc";

export const metadata = { title: "Pricing" };

export default function PricingPage() {
  const content = getMarkdownContent("pricing.md");
  return <MarkdownPageWithToc content={content} />;
}
