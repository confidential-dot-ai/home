import type { BaseLayoutProps } from 'fumadocs-ui/layouts/shared';
import { Logo } from '@/components/logo';

const GITHUB_URL = 'https://github.com/confidential-dot-ai';

/**
 * Shared layout config for the docs. The top nav is intentionally minimal — the
 * left sidebar (with its back-to-site banner) is the primary navigation, mirroring
 * the marketing site's sidebar-first layout.
 */
export function baseOptions(): BaseLayoutProps {
  return {
    nav: {
      url: '/',
      title: (
        <span className="inline-flex items-center gap-2 text-heading">
          <Logo height={20} />
          <span className="font-mono text-[0.65rem] uppercase tracking-widest text-muted">
            docs
          </span>
        </span>
      ),
      transparentMode: 'top',
    },
    githubUrl: GITHUB_URL,
  };
}
