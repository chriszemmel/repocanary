import Link from "next/link";
import LegalLinks from "@/components/LegalLinks";
import { ArrowRight, Wordmark } from "@/components/icons";

/**
 * Frame for the legal notice and the privacy policy: the same brand bar as
 * the coverage page, a readable column, and the shared footer links.
 */
export default function LegalShell({
  title,
  subtitle,
  children,
}: {
  title: string;
  subtitle: string;
  children: React.ReactNode;
}) {
  return (
    <main className="mx-auto max-w-2xl px-4 pt-10 pb-16 sm:pt-14">
      <div className="flex items-center justify-between">
        <Link href="/" className="flex items-center">
          <Wordmark size="sm" />
        </Link>
        <Link
          href="/"
          className="inline-flex items-center gap-1.5 rounded-lg border border-slate-200 px-3 py-1.5 text-sm font-medium text-slate-700 transition hover:bg-slate-50 dark:border-slate-700 dark:text-slate-200 dark:hover:bg-slate-800"
        >
          Scan a repo <ArrowRight className="h-4 w-4" />
        </Link>
      </div>

      <header className="mt-10">
        <h1 className="text-3xl font-semibold tracking-tight sm:text-4xl">{title}</h1>
        <p className="mt-2 text-sm text-slate-500 dark:text-slate-400">{subtitle}</p>
      </header>

      <div className="mt-8 space-y-8 text-sm leading-relaxed text-slate-700 dark:text-slate-300 [&_a]:text-blue-600 [&_a]:underline [&_a]:underline-offset-2 dark:[&_a]:text-blue-400 [&_h2]:text-base [&_h2]:font-semibold [&_h2]:tracking-tight [&_h2]:text-slate-900 dark:[&_h2]:text-slate-100 [&_p]:mt-2 [&_ul]:mt-2 [&_ul]:list-disc [&_ul]:space-y-1 [&_ul]:pl-5">
        {children}
      </div>

      <footer className="mt-12 border-t border-slate-200 pt-6 text-center text-xs leading-relaxed text-slate-500 dark:border-slate-800 dark:text-slate-400">
        <p>Free, no account, no tracking.</p>
        <LegalLinks />
      </footer>
    </main>
  );
}
