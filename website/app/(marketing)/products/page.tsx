import { getMarkdownContent } from "@/lib/markdown";
import { MarkdownPageWithToc } from "@/components/markdown-page-with-toc";

export const metadata = {
  title: "Products",
  description:
    "The Confidential AI product stack: Confidential Metal, Confidential Kubernetes, Confidential Inference, and Confidential Agents.",
};

export default function ProductsPage() {
  const content = getMarkdownContent("products.md");
  return <MarkdownPageWithToc content={content} />;
}
