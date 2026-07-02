import { Sidebar } from "@/components/sidebar";

export default function MarketingLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  return (
    <>
      <Sidebar />
      <div className="md:pl-64 min-h-screen">
        <main className="px-5 md:px-10 py-12">
          <div className="max-w-[680px]">{children}</div>
        </main>
      </div>
    </>
  );
}
