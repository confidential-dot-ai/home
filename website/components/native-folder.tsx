'use client';

import { usePathname } from 'next/navigation';
import { ChevronDown } from 'lucide-react';
import type { ReactNode } from 'react';

/**
 * Sidebar folder rendered as a native HTML <details>/<summary>.
 *
 * Why not the default (Radix Collapsible) folder: its expand/collapse is driven
 * by client-side React, so if hydration doesn't run the folder never opens. A
 * native <details> is toggled by the browser itself — zero JavaScript — so the
 * navigation works in every browser regardless of hydration. Clicking the
 * summary toggles the section; it never navigates (only the page links do).
 */

// Loose structural type — matches PageTree.Folder/Item without coupling to internals.
interface TreeNode {
  url?: string;
  name?: ReactNode;
  icon?: ReactNode;
  index?: { url?: string };
  children?: TreeNode[];
}

function containsActive(nodes: TreeNode[] | undefined, pathname: string): boolean {
  return (
    nodes?.some(
      (n) =>
        n.url === pathname ||
        n.index?.url === pathname ||
        containsActive(n.children, pathname),
    ) ?? false
  );
}

export function NativeFolder({
  item,
  children,
}: {
  item: TreeNode;
  children: ReactNode;
}) {
  const pathname = usePathname();
  // Open the section that contains the current page on first render; the browser
  // handles every toggle after that (uncontrolled — no React state involved).
  const open =
    item.index?.url === pathname || containsActive(item.children, pathname);

  return (
    <details className="fd-folder" open={open}>
      <summary className="mt-1 flex flex-row items-center gap-2 rounded-lg p-2 text-start font-medium text-fd-foreground transition-colors hover:bg-fd-accent/50 select-none">
        {item.icon}
        <span className="me-auto">{item.name}</span>
        <ChevronDown
          className="fd-folder-chevron size-4 shrink-0 text-fd-muted-foreground"
          aria-hidden
        />
      </summary>
      {/* Nested pages: indented under a vertical rail so the hierarchy reads at a glance. */}
      <div className="ms-3 mb-1 flex flex-col border-s border-fd-border ps-2">
        {children}
      </div>
    </details>
  );
}
