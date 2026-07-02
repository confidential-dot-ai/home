import Link from 'next/link';
import { ArrowLeft, ArrowRight } from 'lucide-react';

/**
 * The "path through the docs" journey, mirrored from the homepage cards so the
 * same guided sequence is available on every step page (not just the landing).
 * Drop `<JourneyNav current={N} />` at the bottom of each journey page.
 */
const STEPS = [
  { n: 1, title: 'Understand the runtime', href: '/docs/c8s/runtime/pod-vs-node-cvm' },
  { n: 2, title: 'Provision a confidential cluster', href: '/docs/c8s/install/azure' },
  { n: 3, title: 'Install c8s', href: '/docs/c8s/install/installation' },
  { n: 4, title: 'Bootstrap trust', href: '/docs/c8s/attestation/cds' },
  { n: 5, title: 'Manage the allowlist', href: '/docs/c8s/attestation/allowlist' },
  { n: 6, title: 'Verify confidentiality', href: '/docs/c8s/verification/consumer' },
];

/** URLs of the journey pages — these render the stepper, so the built-in
 *  sidebar-order prev/next footer is suppressed there to avoid double nav. */
export const JOURNEY_URLS = STEPS.map((s) => s.href);

export function JourneyNav({ current }: { current: number }) {
  const prev = STEPS.find((s) => s.n === current - 1);
  const next = STEPS.find((s) => s.n === current + 1);

  return (
    <nav
      aria-label="Getting-started path"
      className="not-prose my-10 rounded-lg border border-fd-border bg-fd-card p-4"
    >
      <div className="mb-3 text-xs uppercase tracking-wide text-fd-muted-foreground">
        Getting started · step {current} of {STEPS.length}
      </div>

      <ol className="mb-1 flex flex-col">
        {STEPS.map((s) => {
          const active = s.n === current;
          return (
            <li key={s.n}>
              <Link
                href={s.href}
                aria-current={active ? 'step' : undefined}
                className={`flex items-center gap-2.5 rounded px-2 py-1.5 text-sm transition-colors ${
                  active
                    ? 'font-medium text-fd-primary'
                    : 'text-fd-muted-foreground hover:text-fd-foreground'
                }`}
              >
                <span
                  className={`grid size-5 shrink-0 place-items-center rounded-full font-mono text-[11px] ${
                    active
                      ? 'bg-fd-primary text-fd-primary-foreground'
                      : 'border border-fd-border'
                  }`}
                >
                  {s.n}
                </span>
                {s.title}
              </Link>
            </li>
          );
        })}
      </ol>

      <div className="mt-3 flex items-center gap-3 border-t border-fd-border pt-3 text-sm">
        {prev && (
          <Link
            href={prev.href}
            className="inline-flex items-center gap-1.5 text-fd-muted-foreground hover:text-fd-foreground"
          >
            <ArrowLeft size={14} /> {prev.title}
          </Link>
        )}
        {next && (
          <Link
            href={next.href}
            className="ms-auto inline-flex items-center gap-1.5 text-fd-primary hover:underline"
          >
            {next.title} <ArrowRight size={14} />
          </Link>
        )}
      </div>
    </nav>
  );
}
