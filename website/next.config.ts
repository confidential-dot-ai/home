import type { NextConfig } from "next";
import { createMDX } from "fumadocs-mdx/next";

const withMDX = createMDX();

const nextConfig: NextConfig = {
  async redirects() {
    return [
      { source: "/components", destination: "/cloud", permanent: true },
      { source: "/enterprise", destination: "/cloud", permanent: true },
      { source: "/agents-api", destination: "/confidential-agents", permanent: true },

      // Docs re-architecture: existing docs URLs moved into themed sections.
      { source: "/docs/intro-to-tees", destination: "/docs/concepts/intro-to-tees", permanent: true },
      {
        source: "/docs/confidential-computing-primer",
        destination: "/docs/concepts/confidential-computing-primer",
        permanent: true,
      },
      {
        source: "/docs/confidential-computing-primer/:path*",
        destination: "/docs/concepts/confidential-computing-primer/:path*",
        permanent: true,
      },
      { source: "/docs/zk", destination: "/docs/concepts/zk", permanent: true },
      { source: "/docs/c8s-whitepaper", destination: "/docs/whitepapers/c8s", permanent: true },
      { source: "/docs/kettle-whitepaper", destination: "/docs/whitepapers/kettle", permanent: true },
      {
        source: "/docs/confidential-agents-api",
        destination: "/docs/api/confidential-agents",
        permanent: true,
      },
    ];
  },
};

export default withMDX(nextConfig);
