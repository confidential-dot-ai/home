export default function MarketingLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  return (
    <main className="px-5 md:px-10 py-12">
      <div className="max-w-[680px]">{children}</div>
    </main>
  );
}
