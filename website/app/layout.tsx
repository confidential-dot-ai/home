import type { Metadata } from "next";
import Script from "next/script";
import { Source_Serif_4 } from "next/font/google";
import "./globals.css";
import { RootProvider } from "fumadocs-ui/provider/next";
import { Sidebar } from "@/components/sidebar";
import { getDocsNav } from "@/lib/docs-nav";

// Resolve theme before paint: a saved toggle choice wins, otherwise default to light.
// Mirror the choice onto both `data-theme` (home tokens) and the `dark` class
// (Fumadocs' dark tokens + `dark:` utilities key off `.dark`).
const THEME_SCRIPT = `(function(){try{var t=localStorage.getItem('theme');if(t!=='light'&&t!=='dark'){t='light';}var d=document.documentElement;d.dataset.theme=t;d.classList.toggle('dark',t==='dark');}catch(e){document.documentElement.dataset.theme='light';}})();`;

const sourceSerif = Source_Serif_4({
  variable: "--font-source-serif",
  subsets: ["latin"],
});

export const metadata: Metadata = {
  title: {
    default: "Confidential AI",
    template: "Confidential AI ･ %s",
  },
  description: "The confidential computing stack for AI. Run AI inference, agents, & training in hardware-encrypted Trusted Execution Environments (TEEs).",
};

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  // Built server-side and handed to the (client) sidebar so the docs tree can
  // nest under the "Docs" nav item without a separate docs layout.
  const docsNav = getDocsNav();

  return (
    <html lang="en" suppressHydrationWarning>
      <head>
        <script dangerouslySetInnerHTML={{ __html: THEME_SCRIPT }} />
        <Script
          src="https://plausible.io/js/pa-fe_AMrp4xlNmw8myKYHux.js"
          strategy="afterInteractive"
        />
        <Script id="plausible-init" strategy="afterInteractive">
          {`window.plausible=window.plausible||function(){(plausible.q=plausible.q||[]).push(arguments)},plausible.init=plausible.init||function(i){plausible.o=i||{}};plausible.init()`}
        </Script>
      </head>
      <body className={`${sourceSerif.variable} ${sourceSerif.className} antialiased`}>
        {/* next-themes is disabled: the pre-paint script owns `data-theme` and the
            `.dark` class, so nothing mutates <html> on the client. */}
        <RootProvider theme={{ enabled: false }}>
          <Sidebar docsNav={docsNav} />
          <div className="md:pl-64 min-h-screen">{children}</div>
        </RootProvider>
      </body>
    </html>
  );
}
