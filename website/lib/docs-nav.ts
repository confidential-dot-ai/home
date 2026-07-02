import type { ReactNode } from 'react';
import { source } from '@/lib/source';

/**
 * A serializable slice of the Fumadocs page tree, passed from the server layout
 * to the client Sidebar so the docs navigation can be nested under the "Docs"
 * item using the marketing sidebar's own styling.
 */
export type DocsNavNode =
  | { type: 'page'; title: string; url: string }
  | { type: 'folder'; title: string; url?: string; children: DocsNavNode[] };

/** Flatten a ReactNode (page-tree names are usually plain strings) to text. */
function nodeText(n: ReactNode): string {
  if (typeof n === 'string') return n;
  if (typeof n === 'number') return String(n);
  if (Array.isArray(n)) return n.map(nodeText).join('');
  if (n && typeof n === 'object' && 'props' in n) {
    return nodeText((n as { props?: { children?: ReactNode } }).props?.children);
  }
  return '';
}

// Loose shape of a page-tree node — avoids coupling to Fumadocs internals.
interface TreeNode {
  type?: string;
  name?: ReactNode;
  url?: string;
  index?: { url?: string; name?: ReactNode };
  children?: TreeNode[];
}

function walk(nodes: TreeNode[] | undefined): DocsNavNode[] {
  const out: DocsNavNode[] = [];
  for (const n of nodes ?? []) {
    if (n.type === 'separator') continue;
    if (n.type === 'folder') {
      const children = walk(n.children);
      const idxUrl = n.index?.url;
      // Surface a folder's index page as its first child ("Overview"), and drop
      // any duplicate of it from the children.
      const withIndex: DocsNavNode[] = idxUrl
        ? [
            { type: 'page', title: nodeText(n.index?.name), url: idxUrl },
            ...children.filter((c) => !(c.type === 'page' && c.url === idxUrl)),
          ]
        : children;
      out.push({ type: 'folder', title: nodeText(n.name), url: idxUrl, children: withIndex });
    } else if (n.url) {
      out.push({ type: 'page', title: nodeText(n.name), url: n.url });
    }
  }
  return out;
}

/** The docs navigation tree, minus the /docs hub item (that's the "Docs" link itself). */
export function getDocsNav(): DocsNavNode[] {
  const tree = source.getPageTree() as unknown as { children?: TreeNode[] };
  return walk(tree.children).filter((n) => !(n.type === 'page' && n.url === '/docs'));
}
