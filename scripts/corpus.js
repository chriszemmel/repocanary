#!/usr/bin/env node
/**
 * Scan the regression corpus: every real repository this project has been
 * measured against, cloned fresh and run through the real engine.
 *
 * The corpus is tuned on. Rules were fixed for what these repositories got
 * wrong, so a clean run proves no regression and measures nothing. The honest
 * number comes from repositories the rules have never seen; BENCHMARK.md says
 * which those were and what they showed.
 *
 * What this does prove is that a rule change did not quietly convict a
 * thousand honest projects, which is the failure that ends a scanner's
 * usefulness. Every red must be named in corpus/expected-red.txt with the
 * reason it earns one, so --check fails on anything new.
 *
 *   node scripts/corpus.js              scan, print a summary
 *   node scripts/corpus.js --check      exit 1 on an unexpected red
 *   node scripts/corpus.js --limit 100  scan the first 100, for a quick pass
 *   node scripts/corpus.js --resume     keep results from a previous run
 *   node scripts/corpus.js --shard 2/4  scan one quarter, for a CI matrix
 *   node scripts/corpus.js --list f.txt scan the names in f.txt instead,
 *                                        e.g. a fresh wave the rules have
 *                                        never seen
 *
 * Clones are shallow, scanned, and deleted one at a time, so the disk holds
 * at most --concurrency repositories at once. Nothing is executed: the clone
 * only provides the bytes the GitHub client would otherwise fetch.
 */

import { execFile } from "node:child_process";
import {
  appendFileSync,
  existsSync,
  lstatSync,
  mkdtempSync,
  readFileSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve, sep } from "node:path";
import { fileURLToPath } from "node:url";
import { promisify } from "node:util";
import { scanRepo } from "../src/scan.js";
import { renderHuman } from "../src/report.js";
import { neutralMeta } from "./grade.js";

// Asynchronous on purpose. With execFileSync every clone blocked the event
// loop, so --concurrency 10 ran one clone at a time and a full run took
// hours longer than it had to; only the scans interleaved.
const run = promisify(execFile);

const HERE = dirname(fileURLToPath(import.meta.url));
const CORPUS = join(HERE, "corpus", "regression.txt");
const EXPECTED = join(HERE, "corpus", "expected-red.txt");
const RESULTS = join(HERE, "corpus", "last-run.tsv");
const LOCK = join(HERE, "corpus", ".running");

function parseArgs(argv) {
  const opts = {
    concurrency: 4,
    check: false,
    limit: 0,
    resume: false,
    shard: 0,
    shards: 1,
    list: null,
  };
  for (let i = 0; i < argv.length; i++) {
    if (argv[i] === "--concurrency") opts.concurrency = Number(argv[++i]) || 4;
    else if (argv[i] === "--limit") opts.limit = Number(argv[++i]) || 0;
    else if (argv[i] === "--check") opts.check = true;
    else if (argv[i] === "--resume") opts.resume = true;
    else if (argv[i] === "--list") opts.list = resolve(String(argv[++i] ?? ""));
    else if (argv[i] === "--shard") {
      const [n, of] = String(argv[++i] ?? "").split("/");
      opts.shard = Number(n) || 0;
      opts.shards = Number(of) || 1;
    }
  }
  return opts;
}

const lines = (file) =>
  readFileSync(file, "utf8")
    .split("\n")
    .map((l) => l.trim())
    .filter((l) => l && !l.startsWith("#"));

/**
 * A repository GitHub says is gone is a fact about the corpus; a clone that
 * timed out or ran the disk dry is a fact about this machine, and the two must
 * never share a row. Coverage silently shrinking while --check still passes is
 * how a regression run comes back green having proved nothing.
 */
const GONE =
  /repository not found|not found|does not exist|access rights|could not read Username|remote branch/i;

/**
 * A first attempt long enough for anything that will finish, and a retry only
 * for failures that are not timeouts. Retrying a timeout with a bigger budget
 * multiplies the worst case for a repository that is simply enormous, and a
 * handful of those in one CI shard is the difference between a run and a
 * timed-out job. They get their own outcome instead.
 */
const CLONE_TIMEOUT_MS = 300_000;
const RETRY_TIMEOUT_MS = 600_000;

async function clone(repo, dir, timeout) {
  try {
    await run(
      "git",
      [
        "clone",
        "--depth",
        "1",
        "--single-branch",
        "--quiet",
        // -- so a corpus entry beginning with a dash is a URL to git, not
        // an option. execFile already rules out shell injection; these
        // lists take contributions.
        "--",
        `https://github.com/${repo}`,
        dir,
      ],
      { timeout, maxBuffer: 16 * 1024 * 1024 },
    );
    return null;
  } catch (err) {
    const stderr =
      String(err?.stderr ?? "")
        .trim()
        .split("\n")
        .filter(Boolean)
        .pop() ?? "";
    const timedOut = err?.killed === true || err?.signal === "SIGTERM" || err?.code === "ETIMEDOUT";
    const detail = (stderr || String(err?.message ?? "")).slice(0, 160);
    if (timedOut)
      return {
        kind: "oversized",
        detail: `clone did not finish within ${Math.round(timeout / 1000)}s`,
      };
    return { kind: GONE.test(stderr) ? "gone" : "error", detail };
  }
}

/** Shallow-clone a repository and serve its files the way the API client would. */
async function cloneClient(repo) {
  const dir = mkdtempSync(join(tmpdir(), "repocanary-corpus-"));
  // One retry, and only for a failure that was not a timeout: those are the
  // ones a second attempt can resolve. A repository GitHub has deleted fails
  // the same way twice, and one too large to clone here fails the same way
  // slower, which is the expensive kind of certainty.
  let failure = await clone(repo, dir, CLONE_TIMEOUT_MS);
  if (failure?.kind === "error") {
    rmSync(dir, { recursive: true, force: true });
    failure = await clone(repo, dir, RETRY_TIMEOUT_MS);
  }
  if (failure) {
    rmSync(dir, { recursive: true, force: true });
    const err = new Error(failure.detail);
    err.verdict = failure.kind;
    throw err;
  }
  const { stdout } = await run("git", ["ls-files"], {
    cwd: dir,
    encoding: "utf8",
    maxBuffer: 64 * 1024 * 1024,
  });
  const listed = stdout
    .trim()
    .split("\n")
    .filter(Boolean);
  const tree = [];
  let symlinks = 0;
  for (const p of listed) {
    try {
      // lstat, not stat: a symlink's content is a path rather than code, and
      // the API client skips mode 120000 for exactly that reason. Following
      // one here would scan a file the real scan never sees.
      const st = lstatSync(join(dir, p));
      if (st.isSymbolicLink()) symlinks += 1;
      else if (st.isFile()) tree.push({ path: p, type: "blob", size: st.size });
    } catch {
      // A submodule or a broken link in the index, which the API client skips too.
    }
  }
  const [owner, name] = repo.split("/");
  return {
    client: {
      fetchRepo: async () => ({
        meta: neutralMeta(owner, name),
        tree,
        treeTruncated: false,
        submodules: 0,
        symlinks,
      }),
      fetchFile: async (o, r, ref, p) => {
        // This is the one component that reads from a disk, so it checks that
        // the path it was handed stays inside the clone. git's index cannot
        // hold a ".." segment, so this should never fire; a scanner reading
        // attacker-supplied paths should not rely on "should".
        const full = resolve(dir, p);
        if (full !== dir && !full.startsWith(dir + sep)) return null;
        try {
          const text = readFileSync(full, "utf8");
          return text.includes("\0") ? null : text;
        } catch {
          return null;
        }
      },
    },
    cleanup: () => rmSync(dir, { recursive: true, force: true }),
  };
}

/**
 * Render the report and check what only real repositories can check.
 *
 * Until 2026-09-06 nothing here rendered anything: this runner reads verdicts
 * and the benchmark reads verdicts, so the only reports ever produced in
 * anger came from fixtures written beside the rules. Two faults lived in that
 * gap, and both were found by one scan of an ordinary repository. Rendering
 * is pure string work, so a thousand repositories' worth costs nothing and
 * buys the rendering path the same weekly re-check the rules get.
 *
 * Returns a description of the fault, or "" when the report is well formed.
 */
function reportFault(scan) {
  let human;
  try {
    human = renderHuman(scan);
  } catch (err) {
    return `render threw: ${String(err?.message ?? err)}`;
  }
  const faults = [];
  // The report announces 78 columns, and everything beyond its own prose
  // comes from the scanned repository.
  const over = human.split("\n").filter((l) => l.length > 78);
  if (over.length > 0) faults.push(`${over.length} line(s) over 78 columns: ${JSON.stringify(over[0].slice(0, 60))}`);
  // Nothing may claim a model reviewed the findings; no AI pass runs here.
  if (human.includes("Cleared:") || human.includes("AI pass judged")) faults.push("claims an AI clear with no AI pass");
  // The two renderings must not disagree about what the verdict was.
  if (!human.includes(`Verdict: ${scan.verdict.toUpperCase()}`)) faults.push("headline disagrees with the verdict");
  // The printed tally is the true one, not the count of what was listed.
  const s = scan.stats.severities;
  const m = human.match(/Findings: (\d+) high, (\d+) medium, (\d+) low/);
  if (!m) faults.push("no findings tally");
  else if (Number(m[1]) !== s.high || Number(m[2]) !== s.medium || Number(m[3]) !== s.low) {
    faults.push(`tally ${m.slice(1, 4).join("/")} disagrees with ${s.high}/${s.medium}/${s.low}`);
  }
  return faults.join("; ");
}

async function scanOne(repo) {
  let handle;
  try {
    handle = await cloneClient(repo);
    const [owner, name] = repo.split("/");
    const scan = await scanRepo({ owner, repo: name, client: handle.client });
    const highs = scan.findings
      .filter((f) => f.severity === "high")
      .map((f) => `${f.id}@${f.file}:${f.line ?? "?"}`)
      .join(" | ");
    // The medium findings too: --check reads only the reds, and a rule that
    // turns every stock Laravel manifest yellow passed it unseen until a
    // fresh wave found five such rules on 2026-09-16.
    const mediums = scan.findings
      .filter((f) => f.severity === "medium")
      .map((f) => `${f.id}@${f.file}:${f.line ?? "?"}`)
      .join(" | ");
    return { repo, verdict: scan.verdict, highs, mediums, report: reportFault(scan) };
  } catch (err) {
    const known = err?.verdict === "gone" || err?.verdict === "oversized";
    const verdict = known ? err.verdict : "error";
    return {
      repo,
      verdict,
      highs: String(err?.message ?? "")
        .split("\n")[0]
        .slice(0, 160),
    };
  } finally {
    handle?.cleanup();
  }
}

const opts = parseArgs(process.argv.slice(2));
const all = lines(opts.list ?? CORPUS);
const limited = opts.limit > 0 ? all.slice(0, opts.limit) : all;
// Strided rather than sliced, so each shard draws from the whole corpus.
// The list is grouped by the wave a repository came from, and contiguous
// slices would hand one shard every heavy infrastructure repository and
// another every tutorial.
const repos =
  opts.shards > 1
    ? limited.filter(
        (_, i) =>
          i % opts.shards === (opts.shard - 1 + opts.shards) % opts.shards,
      )
    : limited;
const expected = new Set(lines(EXPECTED).map((l) => l.split(/\s+/)[0]));

// A run writes to one fixed path, so a second one started while the first is
// still going truncates its results. That happened, and the fix belongs here
// rather than in a habit: the results of an hour-long run should not depend
// on nobody typing the command twice.
let holdsLock = false;
try {
  writeFileSync(LOCK, String(process.pid), { flag: "wx" });
  holdsLock = true;
} catch {
  const owner = Number(readFileSync(LOCK, "utf8").trim());
  let alive = false;
  try {
    process.kill(owner, 0);
    alive = true;
  } catch {
    // ESRCH: the process is gone, so the lock is stale and this run takes it.
  }
  if (alive) {
    console.error(
      `Another corpus run (pid ${owner}) is using ${RESULTS}. Wait for it, or stop it first.`,
    );
    process.exit(2);
  }
  writeFileSync(LOCK, String(process.pid));
  holdsLock = true;
}
const releaseLock = () => {
  if (holdsLock) rmSync(LOCK, { force: true });
  holdsLock = false;
};
process.on("exit", releaseLock);
for (const sig of ["SIGINT", "SIGTERM"])
  process.on(sig, () => process.exit(130));

const done = new Map();
if (opts.resume && existsSync(RESULTS)) {
  for (const line of readFileSync(RESULTS, "utf8")
    .split("\n")
    .filter(Boolean)) {
    const [repo, verdict, highs, mediums = "", report = ""] = line.split("\t");
    // An error row is the absence of a result, so --resume retries it. Rows
    // that say the repository is gone or too large are results, and stay.
    // The report fault comes back too: without it a resumed run passed
    // --check on a malformed report the interrupted run had already found.
    if (verdict !== "error" && verdict !== "unreachable")
      done.set(repo, { repo, verdict, highs, mediums, report });
  }
} else {
  writeFileSync(RESULTS, "");
}

const todo = repos.filter((r) => !done.has(r));
const shardLabel =
  opts.shards > 1 ? ` (shard ${opts.shard} of ${opts.shards})` : "";
console.log(
  `Corpus${shardLabel}: ${repos.length} repositories, ${done.size} already done, ${todo.length} to scan.`,
);
// The pid, because a run this long gets watched from another shell, and the
// lock file is the only place that reliably says which process is the run.
console.log(
  `Process ${process.pid}; the same number is in corpus/.running while this runs.`,
);
console.log(
  "Each clone is deleted as soon as it is scanned. Nothing is executed.\n",
);

const results = [...done.values()];
const row = (r) => `${r.repo}\t${r.verdict}\t${r.highs}\t${r.mediums ?? ""}\t${r.report ?? ""}\n`;
let finished = 0;
let next = 0;
await Promise.all(
  Array.from({ length: Math.min(opts.concurrency, todo.length) }, async () => {
    while (next < todo.length) {
      const repo = todo[next++];
      const result = await scanOne(repo);
      results.push(result);
      appendFileSync(RESULTS, row(result));
      if (result.verdict === "red" && !expected.has(result.repo)) {
        console.log(
          `UNEXPECTED RED  ${result.repo}\n                ${result.highs}`,
        );
      }
      if (++finished % 50 === 0) console.log(`... ${finished}/${todo.length}`);
    }
  }),
);

// Rows are appended as scans finish, so --resume survives an interrupted
// run. Once every worker is done they are put back in corpus order, so two
// runs over the same repositories write the same file and print the same
// lists, whichever clone happened to be slow.
const position = new Map(repos.map((r, i) => [r, i]));
results.sort((a, b) => (position.get(a.repo) ?? Infinity) - (position.get(b.repo) ?? Infinity));
writeFileSync(RESULTS, results.map(row).join(""));

const counts = { green: 0, yellow: 0, red: 0, gone: 0, oversized: 0, error: 0 };
for (const r of results) counts[r.verdict] = (counts[r.verdict] ?? 0) + 1;
const scanned = counts.green + counts.yellow + counts.red;
const unexpected = results.filter(
  (r) => r.verdict === "red" && !expected.has(r.repo),
);
const errored = results.filter((r) => r.verdict === "error");
const missing = [...expected].filter((e) =>
  results.some((r) => r.repo === e && r.verdict !== "red"),
);

console.log("\n====================================================");
console.log(`  scanned      ${scanned}`);
console.log(
  `  green        ${counts.green}   ${scanned ? Math.round((counts.green / scanned) * 100) : 0}%`,
);
console.log(`  yellow       ${counts.yellow}`);
// --check fails on an unexpected red and on nothing else, so a yellow on
// every stock Laravel manifest passes it. The gate stays what it is, since a
// yellow baseline would need a thousand reasons written down; the breakdown
// is printed so a new rule's noise is at least visible in the run that
// introduced it.
const yellowByRule = new Map();
for (const r of results) {
  if (r.verdict !== "yellow") continue;
  const ids = new Set(String(r.mediums ?? "").split(" | ").map((h) => h.split("@")[0]).filter(Boolean));
  for (const id of ids) yellowByRule.set(id, (yellowByRule.get(id) ?? 0) + 1);
}
if (yellowByRule.size > 0) {
  console.log("  yellow, by the medium finding that raised it:");
  for (const [id, n] of [...yellowByRule.entries()].sort((a, b) => b[1] - a[1]).slice(0, 15)) {
    console.log(`    ${String(n).padStart(5)}  ${id}`);
  }
}
console.log(`  red          ${counts.red}`);
console.log(
  `  gone         ${counts.gone}   (deleted, renamed, or private since)`,
);
console.log(
  `  oversized    ${counts.oversized}   (too large to clone here; a limit of this machine, not of the rules)`,
);
console.log(
  `  error        ${counts.error}   <- not scanned for no known reason`,
);
console.log(
  `  unexpected   ${unexpected.length}   <- each one is a regression`,
);
const malformed = results.filter((r) => r.report);
console.log(
  `  malformed    ${malformed.length}   <- the report the user would read is wrong`,
);
if (missing.length > 0) {
  console.log(
    `\n  Listed as expected-red but no longer red: ${missing.join(", ")}`,
  );
  console.log(
    "  That is usually good news. Remove the line, or say why it changed.",
  );
}
const oversized = results.filter((r) => r.verdict === "oversized");
if (oversized.length > 0) {
  console.log("\n  Too large to clone here, so not scanned:");
  for (const r of oversized.slice(0, 20)) console.log(`    ${r.repo}`);
  if (oversized.length > 20)
    console.log(`    ... and ${oversized.length - 20} more`);
  console.log(
    "  This is a property of the machine, so --check does not fail on it.",
  );
  console.log(
    "  It is still coverage this run did not have. Scan them somewhere roomier.",
  );
}
if (errored.length > 0) {
  console.log("\n  Could not be scanned:");
  for (const r of errored.slice(0, 20))
    console.log(`    ${r.repo}  ${r.highs}`);
  if (errored.length > 20)
    console.log(`    ... and ${errored.length - 20} more`);
  console.log("  Rerun with --resume; only these are retried.");
}
if (malformed.length > 0) {
  console.log("\n  Reports that did not come out well formed:");
  for (const r of malformed.slice(0, 20)) console.log(`    ${r.repo}  ${r.report}`);
  if (malformed.length > 20) console.log(`    ... and ${malformed.length - 20} more`);
  console.log("  A verdict nobody can read is a verdict nobody acts on.");
}
if (opts.check && malformed.length > 0) {
  console.error(
    `\n${malformed.length} repositories produced a malformed report.`,
  );
  process.exit(1);
}
if (opts.check && unexpected.length > 0) {
  console.error(
    "\nA repository turned red that is not in corpus/expected-red.txt.",
  );
  process.exit(1);
}
// A run that could not read part of the corpus has not checked it, and
// passing on the remainder would report a coverage failure as a clean bill of
// health. "Too large to clone on this machine" is the one exception: it is
// reproducible, it is named above, and it says nothing about the rules, so
// failing on it would only teach whoever reads the run to ignore red.
if (opts.check && errored.length > 0) {
  console.error(
    `\n${errored.length} repositories could not be scanned for no known reason.`,
  );
  process.exit(1);
}
