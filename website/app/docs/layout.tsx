export default function DocsLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  // The navigation lives in the shared sidebar (nested under "Docs"); this is
  // just the content column. Slightly wider than marketing to fit code/tables.
  return (
    <main className="px-5 md:px-10 py-12">
      <div className="max-w-[820px]">{children}</div>
    </main>
  );
}
