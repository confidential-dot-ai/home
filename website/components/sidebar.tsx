"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";
import { useMemo, useState } from "react";
import { ThemeToggle } from "./theme-toggle";
import { Logo } from "./logo";
import type { DocsNavNode } from "@/lib/docs-nav";

type Item = { label: string; href: string; external?: boolean };
type Section = { title?: string; items: Item[] };

const SECTIONS: Section[] = [
  {
    items: [
      { label: "Products", href: "/products" },
      { label: "Cloud", href: "/cloud" },
      { label: "Pricing", href: "/pricing" },
      { label: "Docs", href: "/docs" },
    ],
  },
  {
    title: "Company",
    items: [
      { label: "Team", href: "/team" },
      { label: "Careers", href: "/careers" },
      { label: "Blog", href: "/blog" },
    ],
  },
  {
    title: "Demos",
    items: [
      {
        label: "Private Inference",
        href: "https://private-inference-demo.confidential.ai/",
        external: true,
      },
    ],
  },
];

const SOCIALS = [
  {
    label: "LinkedIn",
    href: "https://www.linkedin.com/company/confi-ai",
    path: "M20.447 20.452h-3.554v-5.569c0-1.328-.027-3.037-1.852-3.037-1.853 0-2.136 1.445-2.136 2.939v5.667H9.351V9h3.414v1.561h.046c.477-.9 1.637-1.85 3.37-1.85 3.601 0 4.267 2.37 4.267 5.455v6.286zM5.337 7.433a2.062 2.062 0 01-2.063-2.065 2.064 2.064 0 112.063 2.065zm1.782 13.019H3.555V9h3.564v11.452zM22.225 0H1.771C.792 0 0 .774 0 1.729v20.542C0 23.227.792 24 1.771 24h20.451C23.2 24 24 23.227 24 22.271V1.729C24 .774 23.2 0 22.222 0h.003z",
  },
  {
    label: "GitHub",
    href: "https://github.com/confidential-dot-ai",
    path: "M12 .297c-6.63 0-12 5.373-12 12 0 5.303 3.438 9.8 8.205 11.385.6.113.82-.258.82-.577 0-.285-.01-1.04-.015-2.04-3.338.724-4.042-1.61-4.042-1.61C4.422 18.07 3.633 17.7 3.633 17.7c-1.087-.744.084-.729.084-.729 1.205.084 1.838 1.236 1.838 1.236 1.07 1.835 2.809 1.305 3.495.998.108-.776.417-1.305.76-1.605-2.665-.3-5.466-1.332-5.466-5.93 0-1.31.465-2.38 1.235-3.22-.135-.303-.54-1.523.105-3.176 0 0 1.005-.322 3.3 1.23.96-.267 1.98-.399 3-.405 1.02.006 2.04.138 3 .405 2.28-1.552 3.285-1.23 3.285-1.23.645 1.653.24 2.873.12 3.176.765.84 1.23 1.91 1.23 3.22 0 4.61-2.805 5.625-5.475 5.92.42.36.81 1.096.81 2.22 0 1.606-.015 2.896-.015 3.286 0 .315.21.69.825.57C20.565 22.092 24 17.592 24 12.297c0-6.627-5.373-12-12-12",
  },
  {
    label: "X (Twitter)",
    href: "https://x.com/Confi_AI",
    path: "M18.244 2.25h3.308l-7.227 8.26 8.502 11.24H16.17l-5.214-6.817L4.99 21.75H1.68l7.73-8.835L1.254 2.25H8.08l4.713 6.231zm-1.161 17.52h1.833L7.084 4.126H5.117z",
  },
];

function SidebarFooter() {
  return (
    <div className="flex flex-col gap-3">
      <div className="flex items-center gap-4">
        {SOCIALS.map((s) => (
          <a
            key={s.href}
            href={s.href}
            target="_blank"
            rel="noopener noreferrer"
            aria-label={s.label}
            className="text-muted hover:text-foreground transition-colors"
          >
            <svg width="16" height="16" viewBox="0 0 24 24" fill="currentColor" aria-hidden="true">
              <path d={s.path} />
            </svg>
          </a>
        ))}
      </div>
      <span className="font-mono text-[0.65rem] tracking-wide text-muted">confidential ai</span>
    </div>
  );
}

// ── Nested docs tree (rendered under the "Docs" item on /docs routes) ──────────

function nodeContainsActive(node: DocsNavNode, pathname: string): boolean {
  if (node.type === "page") return node.url === pathname;
  return node.url === pathname || node.children.some((c) => nodeContainsActive(c, pathname));
}

function Chevron({ open }: { open: boolean }) {
  return (
    <svg
      width="10"
      height="10"
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      strokeWidth="2.5"
      aria-hidden="true"
      className={`shrink-0 text-muted transition-transform ${open ? "rotate-90" : ""}`}
    >
      <path d="M9 6l6 6-6 6" />
    </svg>
  );
}

/** Leaf page — muted, no chevron; indented to sit under the section titles. */
function DocsPageLink({
  node,
  pathname,
  onNavigate,
}: {
  node: Extract<DocsNavNode, { type: "page" }>;
  pathname: string;
  onNavigate?: () => void;
}) {
  const active = pathname === node.url;
  return (
    <Link
      href={node.url}
      onClick={onNavigate}
      aria-current={active ? "page" : undefined}
      className={`block py-1 pl-[1.4rem] font-mono text-[0.8rem] no-underline transition-colors hover:text-foreground ${
        active ? "text-accent" : "text-foreground/60"
      }`}
    >
      {node.title}
    </Link>
  );
}

/** Section header — a chevron plus a bolder title. The title links to the
 *  section overview when the folder has an index page, otherwise it toggles.
 *  Children sit inside an indented rail so the hierarchy reads at a glance. */
function DocsFolder({
  node,
  pathname,
  onNavigate,
}: {
  node: Extract<DocsNavNode, { type: "folder" }>;
  pathname: string;
  onNavigate?: () => void;
}) {
  const selfActive = pathname === node.url;
  const active = useMemo(() => nodeContainsActive(node, pathname), [node, pathname]);
  // `null` follows the active state (auto-open the current section); once the
  // user toggles the folder, their choice sticks.
  const [userOpen, setUserOpen] = useState<boolean | null>(null);
  const open = userOpen ?? active;
  const toggle = () => setUserOpen(!open);

  return (
    <div className="flex flex-col">
      <div className="flex items-center gap-1 py-1">
        <button
          type="button"
          onClick={toggle}
          aria-expanded={open}
          aria-label={open ? "Collapse section" : "Expand section"}
          className="flex size-4 items-center justify-center"
        >
          <Chevron open={open} />
        </button>
        {node.url ? (
          <Link
            href={node.url}
            onClick={onNavigate}
            aria-current={selfActive ? "page" : undefined}
            className={`font-mono text-[0.8rem] font-medium no-underline transition-colors hover:text-foreground ${
              selfActive ? "text-accent" : "text-foreground"
            }`}
          >
            {node.title}
          </Link>
        ) : (
          <button
            type="button"
            onClick={toggle}
            className="text-left font-mono text-[0.8rem] font-medium text-foreground transition-colors hover:text-foreground"
          >
            {node.title}
          </button>
        )}
      </div>
      {open && (
        <div className="ml-2 flex flex-col border-l border-border pl-1">
          {node.children.map((c, i) =>
            c.type === "folder" ? (
              <DocsFolder key={i} node={c} pathname={pathname} onNavigate={onNavigate} />
            ) : (
              <DocsPageLink key={c.url} node={c} pathname={pathname} onNavigate={onNavigate} />
            )
          )}
        </div>
      )}
    </div>
  );
}

function DocsTree({
  nodes,
  pathname,
  onNavigate,
}: {
  nodes: DocsNavNode[];
  pathname: string;
  onNavigate?: () => void;
}) {
  return (
    <div className="mt-1 mb-1 ml-1 flex flex-col border-l border-border pl-1">
      {nodes.map((n, i) =>
        n.type === "folder" ? (
          <DocsFolder key={i} node={n} pathname={pathname} onNavigate={onNavigate} />
        ) : (
          <DocsPageLink key={n.url} node={n} pathname={pathname} onNavigate={onNavigate} />
        )
      )}
    </div>
  );
}

function NavContent({
  docsNav,
  onNavigate,
}: {
  docsNav: DocsNavNode[];
  onNavigate?: () => void;
}) {
  const pathname = usePathname();
  const isActive = (href: string) => {
    const base = href.split("#")[0];
    return pathname === base || (base !== "/" && pathname.startsWith(base + "/"));
  };
  const onDocs = isActive("/docs");

  return (
    <nav aria-label="Primary" className="flex flex-col gap-6 text-sm">
      {SECTIONS.map((section, i) => (
        <div key={section.title ?? i} className="flex flex-col gap-1">
          {section.title && (
            <p className="font-mono text-[0.65rem] uppercase tracking-widest text-muted mb-1">
              {section.title}
            </p>
          )}
          {section.items.map((item) =>
            item.external ? (
              <a
                key={item.href}
                href={item.href}
                target="_blank"
                rel="noopener noreferrer"
                onClick={onNavigate}
                className="font-mono text-muted hover:text-foreground transition-colors no-underline py-0.5"
              >
                {item.label} ↗
              </a>
            ) : (
              <div key={item.href} className="flex flex-col">
                <Link
                  href={item.href}
                  onClick={onNavigate}
                  className={`font-mono no-underline py-0.5 transition-colors hover:text-foreground ${
                    isActive(item.href) ? "text-accent" : "text-foreground/85"
                  }`}
                >
                  {item.label}
                </Link>
                {/* Docs navigation nests here when you're in the docs section. */}
                {item.href === "/docs" && onDocs && docsNav.length > 0 && (
                  <DocsTree nodes={docsNav} pathname={pathname} onNavigate={onNavigate} />
                )}
              </div>
            )
          )}
        </div>
      ))}

      <a href="mailto:hello@confidential.ai" onClick={onNavigate} className="cta mt-2 w-fit">
        Contact sales
      </a>
    </nav>
  );
}

export function Sidebar({ docsNav }: { docsNav: DocsNavNode[] }) {
  const [open, setOpen] = useState(false);

  return (
    <>
      {/* Mobile top bar */}
      <header className="md:hidden sticky top-0 z-40 flex items-center justify-between border-b border-border bg-background px-4 h-14">
        <Link href="/" aria-label="Home" className="text-heading">
          <Logo />
        </Link>
        <div className="flex items-center gap-4">
          <ThemeToggle />
          <button
            type="button"
            onClick={() => setOpen(true)}
            aria-label="Open menu"
            className="text-muted hover:text-foreground transition-colors"
          >
            <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" aria-hidden="true">
              <path d="M4 6h16M4 12h16M4 18h16" />
            </svg>
          </button>
        </div>
      </header>

      {/* Desktop fixed sidebar */}
      <aside className="hidden md:flex fixed inset-y-0 left-0 w-64 flex-col border-r border-border bg-background px-6 py-6 overflow-y-auto">
        <Link href="/" aria-label="Home" className="text-heading mb-8 block w-fit">
          <Logo />
        </Link>
        <NavContent docsNav={docsNav} />
        <div className="mt-auto pt-6 flex flex-col gap-4">
          <ThemeToggle />
          <SidebarFooter />
        </div>
      </aside>

      {/* Mobile drawer */}
      {open && (
        <div className="md:hidden fixed inset-0 z-50 flex">
          <button
            type="button"
            aria-label="Close menu"
            className="absolute inset-0 bg-black/50"
            onClick={() => setOpen(false)}
          />
          <div className="relative ml-auto w-72 max-w-[85vw] h-full bg-background border-l border-border px-6 py-6 overflow-y-auto flex flex-col">
            <div className="flex items-center justify-between mb-8">
              <Link href="/" aria-label="Home" className="text-heading" onClick={() => setOpen(false)}>
                <Logo />
              </Link>
              <button
                type="button"
                onClick={() => setOpen(false)}
                aria-label="Close menu"
                className="text-muted hover:text-foreground transition-colors"
              >
                <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" aria-hidden="true">
                  <path d="M6 18L18 6M6 6l12 12" />
                </svg>
              </button>
            </div>
            <NavContent docsNav={docsNav} onNavigate={() => setOpen(false)} />
            <div className="mt-auto pt-6">
              <SidebarFooter />
            </div>
          </div>
        </div>
      )}
    </>
  );
}
