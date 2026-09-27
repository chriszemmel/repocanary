import type { Finding, ScanResult, Verdict } from "@/lib/types";
import { Canary, Check } from "@/components/icons";

type VerdictStyle = {
  Icon: (props: React.SVGProps<SVGSVGElement>) => React.ReactElement;
  label: string;
  /** Icon chip. */ chip: string;
  /** Card accent border. */ border: string;
  /** Top edge, which carries the verdict at a glance. */ edge: string;
};

const VERDICT_STYLE: Record<Verdict, VerdictStyle> = {
  red: {
    Icon: Canary,
    label: "Danger",
    chip: "bg-red-50 text-red-600 dark:bg-red-950/50 dark:text-red-400",
    border: "border-red-200 dark:border-red-900/70",
    edge: "border-t-red-600 dark:border-t-red-500",
  },
  yellow: {
    Icon: Canary,
    label: "Caution",
    chip: "bg-amber-50 text-amber-600 dark:bg-amber-950/50 dark:text-amber-400",
    border: "border-amber-200 dark:border-amber-900/70",
    edge: "border-t-amber-500 dark:border-t-amber-500",
  },
  green: {
    Icon: Canary,
    label: "No red flags found",
    chip: "bg-emerald-50 text-emerald-600 dark:bg-emerald-950/50 dark:text-emerald-400",
    border: "border-emerald-200 dark:border-emerald-900/70",
    edge: "border-t-emerald-500 dark:border-t-emerald-500",
  },
};

const SEVERITY_STYLE: Record<Finding["severity"], string> = {
  high: "bg-red-50 text-red-700 dark:bg-red-950/50 dark:text-red-400",
  medium: "bg-amber-50 text-amber-700 dark:bg-amber-950/50 dark:text-amber-400",
  low: "bg-slate-100 text-slate-600 dark:bg-slate-800 dark:text-slate-400",
};

export default function ResultCard({ result }: { result: ScanResult }) {
  const { Icon, label, chip, border, edge } = VERDICT_STYLE[result.verdict];

  return (
    <div
      className={`mt-8 rounded-2xl border border-t-4 ${border} ${edge} bg-white p-6 shadow-sm sm:p-8 dark:bg-slate-900`}
    >
      {/* Verdict header */}
      <div className="flex items-center gap-4">
        <span
          className={`flex h-11 w-11 shrink-0 items-center justify-center rounded-xl ${chip}`}
        >
          <Icon className="h-6 w-6" />
        </span>
        <div className="min-w-0">
          <div className="text-lg font-semibold tracking-tight">{label}</div>
          <div className="truncate text-xs text-slate-500 dark:text-slate-400">
            {result.repo.owner}/{result.repo.repo} · {result.stats.filesScanned}{" "}
            files ·{" "}
            {result.stats.findings === 0
              ? "no findings"
              : `${result.stats.high} high, ${result.stats.medium} medium, ${result.stats.low} low`}{" "}
            {/* Name the model, not just "AI". A second opinion is worth what
                its author is worth, and the reader cannot weigh one they
                cannot see. */}
            ·{" "}
            {result.stats.aiValidated
              ? `static + ${result.stats.aiModel ?? "AI"}`
              : "static analysis"}
          </div>
        </div>
      </div>

      <h2 className="mt-5 text-xl font-semibold tracking-tight sm:text-2xl">
        {result.headline}
      </h2>

      {/* What it does */}
      <Section title="What it does">
        <p className="leading-relaxed text-slate-700 dark:text-slate-300">
          {result.whatItDoes}
        </p>
      </Section>

      {/* Findings, straight from the shared engine */}
      {result.findings.length > 0 && (
        <Section title="What we found">
          <ul className="space-y-3">
            {result.findings.map((f, i) => (
              <li
                key={i}
                className="rounded-xl border border-slate-200 bg-slate-50 p-3.5 text-sm dark:border-slate-800 dark:bg-slate-800/40"
              >
                <div className="flex flex-wrap items-center gap-x-2 gap-y-1">
                  <span
                    className={`rounded-md px-1.5 py-0.5 text-[10px] font-semibold tracking-wider uppercase ${SEVERITY_STYLE[f.severity]}`}
                  >
                    {f.severity}
                  </span>
                  <span className="font-mono text-xs font-medium break-all text-slate-500 dark:text-slate-400">
                    {f.file}
                    {f.line !== null && `:${f.line}`}
                  </span>
                </div>
                {f.snippet && (
                  <pre className="mt-2 overflow-x-auto rounded-lg bg-slate-100 p-2.5 font-mono text-xs whitespace-pre-wrap [overflow-wrap:anywhere] text-slate-700 dark:bg-slate-950 dark:text-slate-300">
                    {f.snippet}
                  </pre>
                )}
                <p className="mt-2 leading-relaxed text-slate-700 dark:text-slate-300">
                  {f.why}
                </p>
                {f.next && (
                  <p className="mt-2 border-t border-slate-200 pt-2 leading-relaxed text-slate-600 dark:border-slate-700 dark:text-slate-400">
                    <span className="font-medium text-slate-500 dark:text-slate-400">
                      What to do:{" "}
                    </span>
                    {linkify(f.next)}
                  </p>
                )}
              </li>
            ))}
          </ul>
        </Section>
      )}

      {/* What to do now */}
      <Section title="What to do now">
        <ul className="space-y-2.5">
          {result.whatToDo.map((step, i) => (
            <li key={i} className="flex gap-2.5 text-sm leading-relaxed">
              <Check className="mt-0.5 h-4 w-4 shrink-0 text-slate-400 dark:text-slate-400" />
              <span className="[overflow-wrap:anywhere] text-slate-700 dark:text-slate-300">
                {linkify(step)}
              </span>
            </li>
          ))}
        </ul>
      </Section>

      {result.notes.length > 0 && (
        <Section title="Notes on this scan">
          <ul className="space-y-2">
            {result.notes.map((note, i) => (
              <li
                key={i}
                className="text-sm leading-relaxed text-slate-600 dark:text-slate-400"
              >
                {note}
              </li>
            ))}
          </ul>
        </Section>
      )}

      <p className="mt-6 border-t border-slate-200 pt-4 text-xs leading-relaxed text-slate-500 dark:border-slate-800 dark:text-slate-400">
        {result.disclaimer}
      </p>
    </div>
  );
}

function Section({
  title,
  children,
}: {
  title: string;
  children: React.ReactNode;
}) {
  return (
    <section className="mt-6">
      <h3 className="text-xs font-semibold tracking-wider text-slate-400 uppercase dark:text-slate-400">
        {title}
      </h3>
      <div className="mt-2.5">{children}</div>
    </section>
  );
}

/**
 * Only the addresses this codebase itself writes into advice become links.
 * Script, dependency and alias names are templated into the same sentences,
 * and a name is any JSON key: one containing a quote and a URL escaped the
 * old "skip quoted spans" rule and put a link of the repository's choosing
 * inside the panel warning the reader about it, the highest-trust place on
 * the page. An allowlist does not depend on how a name is quoted.
 */
const LINKABLE = [
  /^https:\/\/github\.com\/contact\//,
  /^https:\/\/github\.com\/chriszemmel\/repocanary\/blob\/main\/WHAT-TO-DO-NOW\.md$/,
  /^https:\/\/www\.ic3\.gov(\/|$)/,
];

/** Turn the known https:// URLs inside advice text into clickable links. */
function linkify(text: string): React.ReactNode[] {
  return text.split(/(https?:\/\/[^\s"),]*[^\s"),.])/g).map((part, i) =>
    LINKABLE.some((re) => re.test(part)) ? (
      <a
        key={i}
        href={part}
        target="_blank"
        rel="noopener noreferrer"
        className="text-blue-600 underline underline-offset-2 hover:text-blue-500 dark:text-blue-400"
      >
        {part}
      </a>
    ) : (
      <span key={i}>{part}</span>
    ),
  );
}
