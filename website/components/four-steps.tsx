import Link from 'next/link';
import { ArrowRight } from 'lucide-react';

/**
 * "From zero to verified, in four steps" — the guided getting-started path,
 * carried over from the standalone c8s docs landing page onto the docs hub.
 * Links point into the c8s platform section.
 */
const JOURNEY = [
  {
    n: '01',
    title: 'Provision a confidential cluster',
    body: 'Bring up a Kubernetes cluster on confidential (TEE) hardware — managed in the cloud or your own host.',
    href: '/docs/c8s/install/azure',
  },
  {
    n: '02',
    title: 'Install c8s',
    body: 'One CLI command sets up the attestation root of trust, the encrypted service mesh, and image-policy enforcement.',
    href: '/docs/c8s/install/installation',
  },
  {
    n: '03',
    title: 'Run a workload',
    body: 'Confidential pods boot as attested CVMs and get TEE-bound certs.',
    href: '/docs/c8s/runtime/kata-containers',
  },
  {
    n: '04',
    title: 'Verify confidentiality',
    body: 'Any client — even a browser — cryptographically verifies the enclave.',
    href: '/docs/c8s/verification/consumer',
  },
];

export function FourSteps() {
  return (
    <div className="not-prose my-8">
      <h2 className="text-sm uppercase tracking-[0.15em] text-fd-muted-foreground mb-5">
        From zero to verified, in four steps
      </h2>
      <div className="grid sm:grid-cols-2 lg:grid-cols-4 gap-4">
        {JOURNEY.map((s) => (
          <Link
            key={s.n}
            href={s.href}
            className="group border border-fd-border rounded-lg p-5 hover:border-fd-primary transition-colors bg-fd-card"
          >
            <div className="text-fd-primary font-mono text-sm mb-3">{s.n}</div>
            <div className="text-fd-foreground font-medium mb-2 flex items-center gap-1">
              {s.title}
              <ArrowRight
                size={14}
                className="opacity-0 -translate-x-1 group-hover:opacity-100 group-hover:translate-x-0 transition-all"
              />
            </div>
            <p className="text-sm text-fd-muted-foreground leading-relaxed">{s.body}</p>
          </Link>
        ))}
      </div>
    </div>
  );
}
