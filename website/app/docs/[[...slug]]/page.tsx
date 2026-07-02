import { source } from '@/lib/source';
import {
  DocsBody,
  DocsDescription,
  DocsTitle,
} from 'fumadocs-ui/layouts/docs/page';
import { notFound } from 'next/navigation';
import { getMDXComponents } from '@/components/mdx';
import { createRelativeLink } from 'fumadocs-ui/mdx';
import { TableOfContents, type TocItem } from '@/components/table-of-contents';
import type { Metadata } from 'next';
import type { ReactNode } from 'react';

/** Flatten a heading ReactNode (usually a plain string) to text for the TOC. */
function tocText(n: ReactNode): string {
  if (typeof n === 'string') return n;
  if (typeof n === 'number') return String(n);
  if (Array.isArray(n)) return n.map(tocText).join('');
  if (n && typeof n === 'object' && 'props' in n) {
    return tocText((n as { props?: { children?: ReactNode } }).props?.children);
  }
  return '';
}

export default async function Page(props: {
  params: Promise<{ slug?: string[] }>;
}) {
  const params = await props.params;
  const page = source.getPage(params.slug);
  if (!page) notFound();

  const MDX = page.data.body;

  // The docs use the site's own table-of-contents component (right rail),
  // mapped from Fumadocs' heading data — same look as the marketing pages.
  const toc: TocItem[] = page.data.toc.map((item) => ({
    id: item.url.replace(/^#/, ''),
    text: tocText(item.title),
    level: item.depth,
  }));

  return (
    <>
      {toc.length > 0 && <TableOfContents items={toc} />}
      <DocsTitle>{page.data.title}</DocsTitle>
      <DocsDescription>{page.data.description}</DocsDescription>
      <DocsBody>
        <MDX
          components={getMDXComponents({
            // Allow relative-path links between pages.
            a: createRelativeLink(source, page),
          })}
        />
      </DocsBody>
    </>
  );
}

export async function generateStaticParams() {
  return source.generateParams();
}

export async function generateMetadata(props: {
  params: Promise<{ slug?: string[] }>;
}): Promise<Metadata> {
  const params = await props.params;
  const page = source.getPage(params.slug);
  if (!page) notFound();

  return {
    title: page.data.title,
    description: page.data.description,
  };
}
