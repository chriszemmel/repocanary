/**
 * Report rendering: human text, versioned JSON, and SARIF.
 *
 * Every renderer is deterministic: same scan result in, same bytes out, with
 * no timestamps and no environment-dependent content. Golden tests compare
 * reports byte for byte.
 */

import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import { EXIT_CODES, GREEN_MEANING } from "./verdict.js";
import { redactSnippet, wrapText } from "./textutil.js";

/** The JSON output schema version. Bump only with a documented migration. */
export const JSON_SCHEMA_VERSION = 1;

export function toolVersion() {
  const pkgPath = join(dirname(fileURLToPath(import.meta.url)), "..", "package.json");
  try {
    return JSON.parse(readFileSync(pkgPath, "utf8")).version ?? "0.0.0";
  } catch {
    return "0.0.0";
  }
}

/**
 * The one sentence stating what green means, built around the exact words
 * "nothing known matched". Printed on every report, whatever the verdict,
 * so nobody ever reads green as a guarantee.
 */
export const GREEN_SENTENCE = `A green verdict means ${GREEN_MEANING}: none of RepoCanary's known attack signatures fired. It is not proof the repository is safe.`;

const VERDICT_HEADLINES = {
  red: (repo) => `Danger: ${repo} matches known malware-trap signatures. Do not run it.`,
  yellow: (repo) => `Caution: ${repo} has suspicious signals. Do not run it until they are explained.`,
  green: (repo) => `No known signatures matched in ${repo}.`,
};

/**
 * A green verdict the AI pass lowered from yellow. Saying "no signatures
 * matched" there would be false, so that case gets its own headline and
 * meaning; the footer's GREEN_SENTENCE stays, because it defines the word
 * rather than the run.
 *
 * This is keyed on the caller setting `aiCleared`, never on the report
 * finding a green that still carries findings. Green with one or two low
 * findings is an ordinary static outcome: a verdict turns yellow at three
 * distinct low signals, so the two below it are green with findings printed
 * and no model involved. Inferring a clear from them told everyone scanning
 * an ordinary repository that a model had read the flagged snippets and
 * vouched for them, which is a claim about a review that never happened.
 */
const CLEARED_HEADLINE = (repo) =>
  `Cleared: ${repo} had suspicious signals, and the AI pass judged them benign.`;
const CLEARED_MEANING =
  "Green after an AI clear means signatures did fire, and a model read the flagged snippets and found an innocent explanation for each. This is not the ordinary green, which means nothing known matched; here something did match and a model judged it harmless. Read the findings and the model's reasoning before you trust that; a model can be wrong.";

/**
 * What each verdict means, printed under the headline on every report and
 * returned as `verdictMeaning` in JSON.
 *
 * Red used to end "a pattern that is essentially only ever present in
 * malware. Treat this repository as hostile." That was measured and found
 * false. On 2026-09-09 the 1,170-repository corpus held twenty-seven reds
 * and the tool's own benign set held two, and the reasons are in
 * BENCHMARK.md: thirteen are a project's CI installing things on a build
 * agent, three are software whose advertised purpose is the flagged
 * behaviour (RustDesk is remote-desktop software, pm2 installs a launch
 * agent, Yarn defines yarnPath), and zod moved its dev container to a
 * curl-pipe-bash installer upstream. A sentence a reader can falsify in an
 * hour costs more than the warning it carries.
 *
 * What replaces it says what the tool can defend -- a signature fired, and
 * the shapes it fires on are the shapes of a trap -- and states the limit
 * that produces those twenty-nine: it reads files, so it cannot tell
 * software whose job is the flagged behaviour from malware doing the same
 * thing. The instruction is unchanged, because it is the right instruction
 * either way: do not run it until you can explain what fired.
 */
const VERDICT_MEANINGS = {
  red: "Red means at least one high-severity signature fired: a pattern this tool treats as the shape of a trap. It reads files and nothing else, so it cannot tell software whose advertised job is the flagged behavior (a remote-desktop tool, an installer, a package manager) from malware doing the same thing. Read the finding below before you act on the verdict, and do not run this repository until you can explain what fired.",
  yellow:
    "Yellow means suspicious signals accumulated without a definitive signature. Someone experienced should review the findings below before anyone runs this code.",
  green: GREEN_SENTENCE,
};

const NEXT_STEPS = {
  red: [
    "Do not run npm install, do not build, and do not open the project in an editor that auto-runs tasks.",
    "If you already ran it, follow https://github.com/chriszemmel/repocanary/blob/main/WHAT-TO-DO-NOW.md immediately: disconnect, move funds, revoke tokens, rotate passwords.",
    // Conditional, because a red is a signature match and not a conviction:
    // rustdesk, yarnpkg/berry and pm2 are red for doing their advertised job,
    // and telling every reader to file an abuse report would aim this tool at
    // the projects it misreads. Same conditional the yellow list already has.
    "If the findings describe malice rather than the project's own purpose, report the repository at https://github.com/contact/report-abuse and the sender on the platform they used.",
  ],
  yellow: [
    "Do not run this repository until the findings below are explained by someone you trust.",
    "Ask the sender why a take-home task needs the flagged behavior; a legitimate one rarely does.",
    "If anything about how you got this repo feels off (urgency, unsolicited contact, unverifiable company), treat it as a scam.",
  ],
  green: [
    "Read the code yourself before running anything; a scan is not a review.",
    "Run unfamiliar projects inside a container or virtual machine, never on the machine that holds your passwords and wallets.",
    "Be suspicious of any interview task that requires installing a stranger's dependencies; ask if you can review without running.",
  ],
};

function severityLabel(sev) {
  return sev.toUpperCase().padEnd(6);
}

/** Render the calm, scannable human report. Plain text, 78 columns, no art. */
/**
 * Finding prose on its way to a terminal. Every field can carry repository
 * text, so it is neutralised the same way a snippet is; the generous cap
 * keeps whole sentences while still bounding what one file can print.
 */
const plain = (text) => redactSnippet(String(text ?? ""), 2000);

/** A repository-relative path as an RFC 3986 relative URI reference. */
const sarifUri = (path) => String(path).split("/").map(encodeURIComponent).join("/");

export function renderHuman(result) {
  const { verdict, findings, meta, notes, stats } = result;
  const repoName = `${meta.owner}/${meta.repo}`;
  const out = [];

  // Owner, repository and ref are all attacker-choosable and GitHub allows
  // them long: 39 + 100 characters plus a branch name overruns 78 on its
  // own. Two corpus repositories with long names proved it.
  // The ref is the repository's own default_branch when none was given, and
  // git allows C1 controls and bidi overrides in a branch name: U+009B alone
  // starts a terminal escape that can conceal everything printed after it.
  out.push(wrapText(plain(`RepoCanary scan: ${repoName} (ref: ${meta.ref})`), 78, ""));
  out.push("");
  out.push(`Verdict: ${verdict.toUpperCase()}`);
  out.push("");
  const cleared = verdict === "green" && result.aiCleared === true;
  out.push(wrapText(cleared ? CLEARED_HEADLINE(repoName) : VERDICT_HEADLINES[verdict](repoName), 78, ""));
  out.push("");
  out.push(wrapText(cleared ? CLEARED_MEANING : VERDICT_MEANINGS[verdict], 78, "  "));
  out.push("");

  // From the scan's own tally, not from the findings array, which a report
  // caps. Counting the listed ones would print a total that contradicts it.
  const counts = stats?.severities ?? { high: 0, medium: 0, low: 0 };
  out.push(
    `Scanned ${stats.filesScanned} file${stats.filesScanned === 1 ? "" : "s"} ` +
      `(${Math.round(stats.bytesScanned / 1024)} KB). ` +
      `Findings: ${counts.high} high, ${counts.medium} medium, ${counts.low} low.`,
  );
  out.push("");

  if (findings.length > 0) {
    out.push("Findings");
    out.push("");
    findings.forEach((f, i) => {
      // The path is repository text like every other field here, and it goes
      // through the same boundary. Wrapping alone was not enough: git allows
      // almost any byte in a filename, so a repository could name a file
      // "a[2K[1A  Verdict: GREEN.js" and erase the lines of the
      // red verdict already printed above it. Its length was handled; its
      // bytes were not.
      const location = plain(f.line ? `${f.file}:${f.line}` : f.file);
      out.push(`  ${i + 1}. [${severityLabel(f.severity).trim()}] ${f.id}`);
      out.push(wrapText(location, 78, "     "));
      if (f.snippet) out.push(wrapText(plain(f.snippet), 78, "     > "));
      // Redacted here, not only where they are built. A snippet goes through
      // redactSnippet at every rule that makes one, but `why` and `next`
      // interpolate names and URLs straight out of the file, and an escape
      // sequence in one of those repaints the reader's terminal: a yarnPath
      // of "ESC[2J ESC[32m Verdict: GREEN" printed a green verdict over a
      // red scan. Doing it at the boundary means no rule can forget.
      out.push(wrapText(`Why it matters: ${plain(f.why)}`, 78, "     "));
      out.push(wrapText(`What to do: ${plain(f.next)}`, 78, "     "));
      if (f.scriptBody) {
        out.push(wrapText(`The script it runs (${plain(f.scriptPath)}):`, 78, "     "));
        for (const line of f.scriptBody.split("\n").slice(0, 8)) {
          out.push(`     | ${line.slice(0, 70)}`);
        }
      }
      out.push("");
    });
  }

  // Notes carry repository text too: the paths of files a rule failed on, the
  // programs a manifest named and the listing did not contain, and the AI
  // pass's own sentences, which are a reply to text the repository wrote.
  for (const note of notes) {
    out.push(wrapText(`Note: ${plain(note)}`, 78, ""));
    out.push("");
  }

  out.push("What to do next");
  for (const step of NEXT_STEPS[verdict]) {
    // First line gets the bullet, continuation lines a matching indent.
    out.push(`  - ${wrapText(step, 78, "    ").slice(4)}`);
  }
  out.push("");
  out.push(wrapText(GREEN_SENTENCE, 78, ""));
  out.push(
    wrapText(
      "RepoCanary never downloads, installs, or executes the repository; it only reads files over the GitHub API and matches known patterns.",
      78,
      "",
    ),
  );
  out.push("");
  out.push(`Exit code: ${EXIT_CODES[verdict]} (0 green, 1 yellow, 2 red, 3 scan failed)`);
  out.push("");
  return out.join("\n");
}

/** Versioned, machine-readable JSON. The schema is documented in the README. */
export function renderJson(result) {
  const { verdict, findings, meta, notes, stats } = result;
  const cleared = verdict === "green" && result.aiCleared === true;
  const doc = {
    schemaVersion: JSON_SCHEMA_VERSION,
    tool: { name: "repocanary", version: toolVersion() },
    repository: { owner: meta.owner, repo: meta.repo, ref: meta.ref },
    verdict,
    exitCode: EXIT_CODES[verdict],
    // A green the AI pass lowered from yellow must not carry the sentence
    // saying no signature fired, because the findings listed below are the
    // ones that did. Automation reads this file, so the fact that a model
    // rather than the static rules produced the green is a field of its own
    // and not only a sentence in the notes.
    verdictMeaning: cleared ? CLEARED_MEANING : VERDICT_MEANINGS[verdict],
    ...(cleared ? { aiCleared: true } : {}),
    findings: findings.map((f) => ({
      id: f.id,
      severity: f.severity,
      file: f.file,
      line: f.line ?? null,
      snippet: f.snippet,
      why: f.why,
      next: f.next,
    })),
    notes,
    stats: {
      filesScanned: stats.filesScanned,
      bytesScanned: stats.bytesScanned,
      // Every finding, and the severity split over every finding. A report
      // lists at most MAX_REPORTED_FINDINGS of them, so `listed` says how
      // many are in the array above; a consumer comparing the two can tell
      // whether it has all of them without parsing the notes.
      findings: stats.findings,
      listed: findings.length,
      severities: stats.severities ?? { high: 0, medium: 0, low: 0 },
      treeTruncated: stats.treeTruncated,
    },
  };
  return `${JSON.stringify(doc, null, 2)}\n`;
}

const SARIF_LEVELS = { high: "error", medium: "warning", low: "note" };

/** SARIF 2.1.0, accepted by GitHub code scanning uploads. */
export function renderSarif(result) {
  const { findings, meta } = result;

  const ruleIds = [...new Set(findings.map((f) => f.id))].sort();
  const rules = ruleIds.map((id) => {
    const example = findings.find((f) => f.id === id);
    return {
      id,
      shortDescription: { text: id },
      fullDescription: { text: example.why },
      helpUri: "https://github.com/chriszemmel/repocanary#what-it-checks",
    };
  });
  if (findings.length === 0 && result.verdict !== "green") {
    rules.push({
      id: "repocanary-verdict",
      shortDescription: { text: "repocanary-verdict" },
      fullDescription: {
        text: "The scan reached a verdict that no individual finding carries, so the verdict itself is reported.",
      },
      helpUri: "https://github.com/chriszemmel/repocanary#what-it-checks",
    });
  }

  // A verdict with no findings behind it (the AI pass can raise one) would
  // upload as "no alerts found", which reads as a pass on a repository the
  // tool just called dangerous. The verdict itself becomes the result.
  const verdictResult =
    findings.length === 0 && result.verdict !== "green"
      ? [
          {
            ruleId: "repocanary-verdict",
            level: result.verdict === "red" ? "error" : "warning",
            message: {
              text: `RepoCanary reports this repository as ${result.verdict}. ${result.notes?.join(" ") ?? ""}`.trim(),
            },
            locations: [
              {
                physicalLocation: {
                  artifactLocation: { uri: "README.md" },
                  region: { startLine: 1 },
                },
              },
            ],
          },
        ]
      : [];

  const results = findings.map((f) => ({
    ruleId: f.id,
    level: SARIF_LEVELS[f.severity],
    message: { text: `${f.why} What to do: ${f.next}` },
    locations: [
      {
        physicalLocation: {
          // A URI, not a path: a file named "a b/#x?.js" otherwise sends a
          // SARIF consumer to a different file than the one that fired.
          artifactLocation: { uri: sarifUri(f.file === "(repository)" ? "README.md" : f.file) },
          region: { startLine: f.line ?? 1 },
        },
      },
    ],
  }));

  const doc = {
    $schema: "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
    version: "2.1.0",
    runs: [
      {
        tool: {
          driver: {
            name: "RepoCanary",
            informationUri: "https://github.com/chriszemmel/repocanary",
            version: toolVersion(),
            rules,
          },
        },
        properties: {
          verdict: result.verdict,
          repository: `${meta.owner}/${meta.repo}`,
          ref: meta.ref,
        },
        invocations: [
          {
            executionSuccessful: true,
            toolExecutionNotifications: (result.notes ?? []).map((text) => ({
              level: "note",
              message: { text },
            })),
          },
        ],
        results: [...verdictResult, ...results],
      },
    ],
  };
  return `${JSON.stringify(doc, null, 2)}\n`;
}

/**
 * The machine-readable report of a scan that did not complete. A consumer
 * that parses stdout must get a document saying so, not zero bytes: empty
 * output made JSON.parse throw and made jq print nothing and exit 0, which
 * a careless pipeline reads as a pass.
 */
export function renderJsonError({ owner, repo, ref = null }, kind, message) {
  const doc = {
    schemaVersion: JSON_SCHEMA_VERSION,
    tool: { name: "repocanary", version: toolVersion() },
    repository: { owner, repo, ref },
    verdict: "error",
    exitCode: EXIT_CODES.error,
    error: { kind, message },
  };
  return `${JSON.stringify(doc, null, 2)}\n`;
}

/** The same for SARIF: a run whose invocation says it did not succeed. */
export function renderSarifError({ owner, repo, ref = null }, kind, message) {
  const doc = {
    $schema: "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
    version: "2.1.0",
    runs: [
      {
        tool: {
          driver: {
            name: "RepoCanary",
            informationUri: "https://github.com/chriszemmel/repocanary",
            version: toolVersion(),
            rules: [],
          },
        },
        properties: { verdict: "error", repository: `${owner}/${repo}`, ref, errorKind: kind },
        invocations: [
          {
            executionSuccessful: false,
            toolExecutionNotifications: [{ level: "error", message: { text: message } }],
          },
        ],
        results: [],
      },
    ],
  };
  return `${JSON.stringify(doc, null, 2)}\n`;
}
