import type { Metadata } from "next";
import Link from "next/link";
import { Wordmark } from "@/components/icons";

// Next marks a not-found response noindex by itself.
export const metadata: Metadata = {
  title: "Page not found",
};

export default function NotFound() {
  return (
    <main className="mx-auto flex min-h-screen max-w-xl flex-col items-center justify-center px-4 text-center">
      <Link href="/" aria-label="RepoCanary home">
        <Wordmark />
      </Link>
      <h1 className="mt-8 text-2xl font-semibold tracking-tight">Nothing lives at this address</h1>
      <p className="mt-3 text-slate-400">
        The page may have moved. To check a repository, paste its link on the home page.
      </p>
      <Link
        href="/"
        className="mt-6 rounded-xl bg-blue-600 px-5 py-2.5 text-sm font-semibold text-slate-950 transition hover:bg-blue-400"
      >
        Check a repository
      </Link>
    </main>
  );
}
