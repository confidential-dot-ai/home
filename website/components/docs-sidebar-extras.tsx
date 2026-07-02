import Link from "next/link";
import { ArrowLeft } from "lucide-react";
import { Logo } from "./logo";
import { ThemeToggle } from "./theme-toggle";

/**
 * Docs sidebar banner: the c8s/docs navigation "overtakes" the marketing
 * sidebar, so this pinned row is the way back to the main site — a back arrow
 * plus the Confidential AI wordmark, linking home.
 */
export function DocsSidebarBanner() {
  return (
    <Link
      href="/"
      aria-label="Back to confidential.ai"
      className="-mx-2 mb-1 flex items-center gap-2 rounded-md px-2 py-1.5 text-fd-muted-foreground transition-colors hover:bg-fd-accent/50 hover:text-fd-foreground"
    >
      <ArrowLeft size={15} className="shrink-0" />
      <Logo height={20} />
    </Link>
  );
}

/** Docs sidebar footer: keep the single theme toggle available inside the docs. */
export function DocsSidebarFooter() {
  return (
    <div className="flex flex-col gap-3 border-t border-fd-border pt-4">
      <ThemeToggle />
      <span className="font-mono text-[0.65rem] tracking-wide text-fd-muted-foreground">
        confidential ai
      </span>
    </div>
  );
}
