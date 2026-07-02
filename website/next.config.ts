import type { NextConfig } from "next";

const nextConfig: NextConfig = {
  async redirects() {
    return [
      { source: "/components", destination: "/cloud", permanent: true },
      { source: "/enterprise", destination: "/cloud", permanent: true },
      { source: "/agents-api", destination: "/confidential-agents", permanent: true },
      { source: "/attestable-builds", destination: "/attested-builds", permanent: true },
      {
        source: "/docs/attestable-builds/what-are-attestable-builds",
        destination: "/docs/attested-builds/what-are-attested-builds",
        permanent: true,
      },
      { source: "/docs/attestable-builds/:path*", destination: "/docs/attested-builds/:path*", permanent: true },
      {
        source: "/attested-builds/v1",
        destination: "https://github.com/confidential-dot-ai/kettle/blob/main/docs/slsa-definitions.md",
        permanent: true,
      },
    ];
  },
};

export default nextConfig;
