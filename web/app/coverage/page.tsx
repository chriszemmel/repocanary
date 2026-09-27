import type { Metadata } from "next";
import Link from "next/link";
import CoverageControls from "@/components/CoverageControls";
import LegalLinks from "@/components/LegalLinks";
import { ArrowRight, Canary, ChevronRight, Wordmark } from "@/components/icons";
import data from "@/lib/coverage-data.json";

export const metadata: Metadata = {
  title: "Threat coverage",
  description:
    "Every fake-interview and supply-chain technique RepoCanary detects, measured by running the real engine over a threat corpus. See the exact rules that fire on each.",
  alternates: { canonical: "/coverage" },
  // A page's openGraph replaces the layout's rather than merging with it, so
  // everything a card needs is restated here, images included.
  openGraph: {
    type: "website",
    url: "/coverage",
    siteName: "RepoCanary",
    title: "RepoCanary threat coverage",
    description:
      "The measured catalog of every technique RepoCanary detects, with the exact rules that fire on each.",
    images: ["/opengraph-image.png"],
  },
  twitter: {
    card: "summary_large_image",
    title: "RepoCanary threat coverage",
    description: "Every technique RepoCanary detects, measured, with the exact rules that fire on each.",
    images: ["/twitter-image.png"],
  },
};

type Rule = { id: string; sev: "high" | "medium" | "low" };
type Row = { name: string; note: string; verdict: "red" | "yellow" | "green"; rules: Rule[] };
type Category = { name: string; rows: Row[] };

/**
 * One line per category, for the index and the section headers. The names
 * and counts come from the generated data; a category the generator adds
 * before this map learns it falls back to its name alone.
 */
const BLURB: Record<string, string> = {
  "Npm install-time": "Scripts that fire the moment npm install finishes, before you have read a line.",
  "Other ecosystems": "The same trick in Python, Rust, Go, Gradle, Maven, PHP, Ruby, and notebooks.",
  "Dependency poisoning":
    "A dependency that is not what the manifest says: git sources, tarballs, lookalike names, poisoned lockfiles.",
  "Obfuscation and loaders": "Payloads hidden as encoded blobs, invisible characters, or two-stage loaders.",
  "Credential theft": "Code that reads browser passwords, wallets, SSH keys, keychains, and environment secrets.",
  "Command and control": "Beacons, dead drops, backdoors, and exfiltration to attacker infrastructure.",
  "Auto-run on open": "Editor, AI-agent, container, make, and CI hooks that run with no install step at all.",
  "Manifest and persistence": "Shadowed commands, shell-startup persistence, and sandbox checks before activating.",
  "Context signals": "Account and README signals that raise suspicion but never convict on their own.",
};

const VERDICT: Record<Row["verdict"], { label: string; chip: string; dot: string; bar: string }> = {
  red: {
    label: "Do not run",
    chip: "bg-red-50 text-red-700 ring-red-200 dark:bg-red-950/50 dark:text-red-300 dark:ring-red-900/70",
    dot: "bg-red-500 dark:bg-red-400",
    bar: "bg-red-500 dark:bg-red-400",
  },
  yellow: {
    label: "Flagged",
    chip: "bg-amber-50 text-amber-700 ring-amber-200 dark:bg-amber-950/50 dark:text-amber-300 dark:ring-amber-900/70",
    dot: "bg-amber-500 dark:bg-amber-400",
    bar: "bg-amber-500 dark:bg-amber-400",
  },
  green: {
    label: "Not caught",
    chip: "bg-slate-100 text-slate-600 ring-slate-200 dark:bg-slate-800 dark:text-slate-300 dark:ring-slate-700",
    dot: "bg-slate-400 dark:bg-slate-500",
    bar: "bg-slate-300 dark:bg-slate-600",
  },
};

const SEV: Record<Rule["sev"], string> = {
  high: "bg-red-50 text-red-700 ring-red-200 dark:bg-red-950/40 dark:text-red-300 dark:ring-red-900/60",
  medium: "bg-amber-50 text-amber-700 ring-amber-200 dark:bg-amber-950/40 dark:text-amber-300 dark:ring-amber-900/60",
  low: "bg-slate-100 text-slate-600 ring-slate-200 dark:bg-slate-800 dark:text-slate-300 dark:ring-slate-700",
};

function slug(name: string) {
  return name.toLowerCase().replace(/[^a-z0-9]+/g, "-").replace(/(^-|-$)/g, "");
}

type Tally = { red: number; yellow: number; green: number; total: number };

function tally(rows: Row[]): Tally {
  const t = { red: 0, yellow: 0, green: 0, total: rows.length };
  for (const r of rows) t[r.verdict] += 1;
  return t;
}

/**
 * The verdict split as a thin stacked bar. Status colours carry the meaning
 * and the labels beside it carry the numbers, so nothing is colour alone.
 */
function VerdictBar({ t, className = "" }: { t: Tally; className?: string }) {
  const segments = (["red", "yellow", "green"] as const).filter((v) => t[v] > 0);
  return (
    <div
      className={`flex h-2 w-full gap-0.5 overflow-hidden rounded-full ${className}`}
      role="img"
      aria-label={`${t.red} do not run, ${t.yellow} flagged, ${t.green} not caught`}
    >
      {segments.map((v) => (
        <div key={v} className={`${VERDICT[v].bar} h-full`} style={{ flexGrow: t[v], flexBasis: 0 }} />
      ))}
    </div>
  );
}

function TallyLabels({ t, showGreen = true }: { t: Tally; showGreen?: boolean }) {
  const items = (["red", "yellow", "green"] as const).filter((v) => v !== "green" || showGreen);
  return (
    <ul className="flex flex-wrap gap-x-4 gap-y-1 text-xs text-slate-500 dark:text-slate-400">
      {items.map((v) => (
        <li key={v} className="inline-flex items-center gap-1.5">
          <span className={`h-2 w-2 rounded-full ${VERDICT[v].dot}`} aria-hidden="true" />
          <span className="font-semibold tabular-nums text-slate-800 dark:text-slate-100">{t[v]}</span>
          <span>{VERDICT[v].label.toLowerCase()}</span>
        </li>
      ))}
    </ul>
  );
}

function VerdictBadge({ verdict }: { verdict: Row["verdict"] }) {
  const v = VERDICT[verdict];
  return (
    <span
      className={`inline-flex shrink-0 items-center gap-1.5 rounded-full px-2.5 py-0.5 text-xs font-medium ring-1 ring-inset ${v.chip}`}
    >
      <span className={`h-1.5 w-1.5 rounded-full ${v.dot}`} aria-hidden="true" />
      {v.label}
    </span>
  );
}

function TechniqueRow({ row }: { row: Row }) {
  return (
    <li className="px-4 py-3.5 sm:px-5">
      <div className="flex items-start justify-between gap-3">
        <p className="text-sm leading-relaxed text-slate-700 dark:text-slate-200">{row.note}</p>
        <VerdictBadge verdict={row.verdict} />
      </div>
      {row.rules.length > 0 ? (
        <div className="mt-2 flex flex-wrap gap-1.5">
          {row.rules.map((r) => (
            <span
              key={r.id}
              title={`${r.id} (${r.sev} severity)`}
              className={`inline-flex items-center rounded-md px-1.5 py-0.5 font-mono text-[11px] ring-1 ring-inset ${SEV[r.sev]}`}
            >
              {r.id}
            </span>
          ))}
        </div>
      ) : (
        <p className="mt-2 text-xs text-slate-400 dark:text-slate-400">
          No rule fires. This is a documented blind spot, kept visible on purpose.
        </p>
      )}
    </li>
  );
}

function Stat({ value, label, sub }: { value: string; label: string; sub?: string }) {
  return (
    <div className="rounded-xl border border-slate-200 bg-white p-4 dark:border-slate-800 dark:bg-slate-900">
      <div className="text-2xl font-semibold tracking-tight tabular-nums text-slate-900 dark:text-slate-50">{value}</div>
      <div className="mt-1 text-xs font-medium text-slate-700 dark:text-slate-200">{label}</div>
      {sub && <div className="mt-0.5 text-xs text-slate-500 dark:text-slate-400">{sub}</div>}
    </div>
  );
}

function CategoryCard({ c }: { c: Category }) {
  const t = tally(c.rows);
  return (
    <a
      href={`#${slug(c.name)}`}
      className="group flex flex-col rounded-xl border border-slate-200 bg-white p-4 transition hover:border-blue-600/60 hover:bg-slate-50 dark:border-slate-800 dark:bg-slate-900 dark:hover:border-blue-500/60 dark:hover:bg-slate-800/60"
    >
      <div className="flex items-baseline justify-between gap-3">
        <h3 className="text-sm font-semibold text-slate-900 dark:text-slate-50">{c.name}</h3>
        <span className="shrink-0 text-xs tabular-nums text-slate-500 dark:text-slate-400">
          {t.total} technique{t.total === 1 ? "" : "s"}
        </span>
      </div>
      <p className="mt-1.5 flex-1 text-xs leading-relaxed text-slate-500 dark:text-slate-400">{BLURB[c.name] ?? ""}</p>
      <VerdictBar t={t} className="mt-3" />
      <div className="mt-2 flex items-center justify-between">
        <TallyLabels t={t} showGreen={t.green > 0} />
        <ChevronRight className="h-4 w-4 text-slate-400 transition group-hover:translate-x-0.5 group-hover:text-blue-600 dark:group-hover:text-blue-400" />
      </div>
    </a>
  );
}

function CategorySection({ c, open = false }: { c: Category; open?: boolean }) {
  const t = tally(c.rows);
  return (
    <details
      id={slug(c.name)}
      data-category
      open={open}
      className="group scroll-mt-6 rounded-2xl border border-slate-200 bg-white open:shadow-sm dark:border-slate-800 dark:bg-slate-900"
    >
      <summary className="flex cursor-pointer list-none items-center gap-3 px-4 py-4 select-none [&::-webkit-details-marker]:hidden sm:px-5">
        <ChevronRight className="h-4 w-4 shrink-0 text-slate-400 transition group-open:rotate-90" />
        <div className="min-w-0 flex-1">
          <div className="flex flex-wrap items-baseline gap-x-3 gap-y-1">
            <h3 className="text-base font-semibold tracking-tight text-slate-900 dark:text-slate-50">{c.name}</h3>
            <span className="text-xs tabular-nums text-slate-500 dark:text-slate-400">
              {t.total} technique{t.total === 1 ? "" : "s"}
            </span>
          </div>
          <p className="mt-0.5 text-xs text-slate-500 dark:text-slate-400">{BLURB[c.name] ?? ""}</p>
        </div>
        <div className="hidden w-40 shrink-0 sm:block">
          <VerdictBar t={t} />
          <div className="mt-1.5">
            <TallyLabels t={t} showGreen={t.green > 0} />
          </div>
        </div>
      </summary>
      <ul className="divide-y divide-slate-100 border-t border-slate-200 dark:divide-slate-800 dark:border-slate-800">
        {c.rows.map((row) => (
          <TechniqueRow key={row.name} row={row} />
        ))}
      </ul>
    </details>
  );
}

export default function CoveragePage() {
  const { stats, categories, evasions, campaigns } = data as {
    stats: {
      techniques: number;
      categories: number;
      rules: number;
      detectionPct: number;
      benignRepos: number;
      evasions: number;
    };
    categories: Category[];
    evasions: Row[];
    campaigns: string[];
  };

  const all = tally(categories.flatMap((c) => c.rows));

  return (
    <main className="mx-auto max-w-4xl px-4 pt-10 pb-16 sm:pt-14">
      {/* Brand bar */}
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

      {/* Hero */}
      <header className="mt-10">
        <h1 className="text-3xl font-semibold tracking-tight sm:text-4xl">What RepoCanary catches</h1>
        <p className="mt-3 max-w-2xl text-base text-slate-600 dark:text-slate-300">
          Measured, not asserted. Every row on this page comes from running the real detection engine
          over a corpus of the techniques these campaigns use and recording which rules fire. Nothing
          is run, cloned, or installed: each sample is scanned as text, the same path a real scan
          uses.
        </p>
        <p className="mt-3 max-w-2xl text-sm text-slate-500 dark:text-slate-400">
          Modelled on the documented playbooks of {campaigns.slice(0, -1).join(", ")}, and{" "}
          {campaigns[campaigns.length - 1]}, plus the wider npm and PyPI supply-chain scene.
        </p>
      </header>

      {/* Scoreboard */}
      <section className="mt-8 rounded-2xl border border-slate-200 bg-white p-5 sm:p-6 dark:border-slate-800 dark:bg-slate-900">
        <div className="flex flex-wrap items-end justify-between gap-x-6 gap-y-3">
          <div>
            <div className="text-4xl font-semibold tracking-tight tabular-nums text-slate-900 sm:text-5xl dark:text-slate-50">
              {all.red + all.yellow}
              <span className="text-slate-400 dark:text-slate-400"> / {all.total}</span>
            </div>
            <div className="mt-1 text-sm font-medium text-slate-700 dark:text-slate-200">
              techniques caught, {stats.detectionPct}% of the corpus
            </div>
          </div>
          <div className="min-w-[14rem] flex-1 sm:max-w-sm">
            <VerdictBar t={all} className="h-2.5" />
            <div className="mt-2">
              <TallyLabels t={all} />
            </div>
          </div>
        </div>
        <div className="mt-5 grid grid-cols-2 gap-3 sm:grid-cols-4">
          <Stat value={String(stats.rules)} label="detection rules" sub="exercised by the corpus" />
          <Stat value={String(stats.categories)} label="categories" sub="one section each, below" />
          <Stat value={`0 / ${stats.benignRepos}`} label="honest repos called red" sub="the standing benign set" />
          <Stat value={String(stats.evasions)} label="known blind spots" sub="listed at the end, not hidden" />
        </div>
      </section>

      {/* Legend */}
      <section className="mt-4 rounded-xl border border-slate-200 bg-slate-50 px-4 py-3 text-xs text-slate-600 dark:border-slate-800 dark:bg-slate-900/50 dark:text-slate-300">
        <ul className="flex flex-wrap gap-x-5 gap-y-1.5">
          <li className="inline-flex items-center gap-2">
            <Canary className="h-4 w-4 shrink-0 text-red-600 dark:text-red-400" />
            <strong className="font-semibold text-slate-800 dark:text-slate-100">Do not run</strong>
            <span className="text-slate-500 dark:text-slate-400">a high-confidence signal fired</span>
          </li>
          <li className="inline-flex items-center gap-2">
            <Canary className="h-4 w-4 shrink-0 text-amber-600 dark:text-amber-400" />
            <strong className="font-semibold text-slate-800 dark:text-slate-100">Flagged</strong>
            <span className="text-slate-500 dark:text-slate-400">raised for human review</span>
          </li>
          <li className="inline-flex items-center gap-2">
            <Canary className="h-4 w-4 shrink-0 text-emerald-600 dark:text-emerald-400" />
            <strong className="font-semibold text-slate-800 dark:text-slate-100">Nothing known matched</strong>
            <span className="text-slate-500 dark:text-slate-400">never proven safe</span>
          </li>
        </ul>
        <p className="mt-2 text-slate-500 dark:text-slate-400">
          Rule chips are coloured by severity: <span className="font-mono text-red-700 dark:text-red-300">high</span>,{" "}
          <span className="font-mono text-amber-700 dark:text-amber-300">medium</span>,{" "}
          <span className="font-mono">low</span>. Any high fires red; mediums and lows accumulate toward a flag.
        </p>
      </section>

      {/* Category index */}
      <section className="mt-10">
        <h2 className="text-xl font-semibold tracking-tight">Nine ways a repository can be a trap</h2>
        <p className="mt-1.5 text-sm text-slate-500 dark:text-slate-400">
          Pick a category to jump to its techniques and the rules that catch each one.
        </p>
        <div className="mt-4 grid gap-3 sm:grid-cols-2 lg:grid-cols-3">
          {categories.map((c) => (
            <CategoryCard key={c.name} c={c} />
          ))}
        </div>
      </section>

      {/* Catalog */}
      <section className="mt-10">
        <div className="flex flex-wrap items-center justify-between gap-3">
          <h2 className="text-xl font-semibold tracking-tight">The full catalog</h2>
          <CoverageControls />
        </div>
        <div className="mt-4 grid gap-3">
          {categories.map((c, i) => (
            <CategorySection key={c.name} c={c} open={i === 0} />
          ))}
        </div>
      </section>

      {/* Evasions */}
      <section id="blind-spots" className="mt-12 scroll-mt-6">
        <div className="flex items-baseline justify-between border-b border-slate-200 pb-2 dark:border-slate-800">
          <h2 className="text-xl font-semibold tracking-tight">Documented blind spots</h2>
          <span className="text-sm text-slate-400 dark:text-slate-400">{evasions.length} kept in the open</span>
        </div>
        <p className="mt-3 max-w-2xl text-sm text-slate-600 dark:text-slate-300">
          A tool that claims to catch everything is lying. These are techniques the static engine
          does not reliably catch, kept in the corpus and measured so the limit stays visible rather
          than quietly forgotten. This is why a green result never means safe.
        </p>
        <ul className="mt-4 divide-y divide-slate-100 rounded-2xl border border-slate-200 bg-white dark:divide-slate-800 dark:border-slate-800 dark:bg-slate-900">
          {evasions.map((row) => (
            <TechniqueRow key={row.name} row={row} />
          ))}
        </ul>
      </section>

      {/* CTA */}
      <section className="mt-12 rounded-2xl border border-slate-200 bg-white p-6 text-center dark:border-slate-800 dark:bg-slate-900">
        <h2 className="text-lg font-semibold tracking-tight">Got a repo someone sent you?</h2>
        <p className="mx-auto mt-2 max-w-md text-sm text-slate-500 dark:text-slate-400">
          Check it against every technique above before you run a single line, or before you open
          it in your editor.
        </p>
        <Link
          href="/"
          className="mt-4 inline-flex items-center gap-1.5 rounded-lg bg-blue-600 px-4 py-2 text-sm font-medium text-slate-950 transition hover:bg-blue-400"
        >
          Scan a repository <ArrowRight className="h-4 w-4" />
        </Link>
      </section>

      {/* Footer */}
      <footer className="mt-12 border-t border-slate-200 pt-6 text-center text-xs leading-relaxed text-slate-500 dark:border-slate-800 dark:text-slate-400">
        <p>
          This catalog is generated by running the engine over the threat corpus, so it cannot drift
          from the code. The full source and reproducible generator live on{" "}
          <a
            href="https://github.com/chriszemmel/repocanary/blob/main/THREAT-COVERAGE.md"
            className="underline"
            target="_blank"
            rel="noopener noreferrer"
          >
            GitHub
          </a>
          . Free, no account, no tracking.{" "}
          <a href="https://nimimo.com/@chris" className="underline" target="_blank" rel="noopener noreferrer">
            Say thanks
          </a>{" "}
          if it helped.
        </p>
        <LegalLinks />
      </footer>
    </main>
  );
}
