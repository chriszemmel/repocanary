#!/usr/bin/env node
/**
 * Benchmark the detector against real and synthetic repositories.
 *
 * It measures four things a self-authored fixture corpus cannot, because
 * those fixtures were written alongside the rules:
 *
 *   false positives   benign repositories flagged red (each one a bug) or
 *                     yellow (noise to keep low). Measured on real code
 *                     cloned from GitHub.
 *   true positives    malicious repositories caught (red).
 *   false negatives   malicious repositories missed (green or yellow). The
 *                     dangerous kind of miss. Measured on synthetic samples
 *                     that are NOT held out: CONTRIBUTING.md requires a
 *                     sample for every new rule, so each was written beside
 *                     the rule that catches it. This measures that the
 *                     catalogue is self-consistent, not that the tool
 *                     catches malware it has never seen.
 *   documented misses THREAT-MODEL's stated limits, asserted to still hold,
 *                     so the tool's honesty about what it cannot catch is
 *                     measured rather than claimed.
 *
 * Benign repositories are cloned (public git read works where the scoped API
 * does not). Synthetic samples run in memory. Both drive the real engine.
 *
 *   node scripts/benchmark.js            clone benign repos, run everything
 *   node scripts/benchmark.js --quick    skip cloning, synthetic samples only
 *   node scripts/benchmark.js --concurrency 4
 */

import { execFileSync } from "node:child_process";
import { mkdtempSync, readFileSync, rmSync, statSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { scanRepo } from "../src/scan.js";
import { MALICIOUS, EVASIONS, BENIGN } from "./benchmark-samples.js";
import { byCategory, detection, meetsExpectation, neutralMeta, scanSample as scanInMemory } from "./grade.js";

const SECURITY_TOOLING = [{ repo: "chriszemmel/repocanary", note: "contains its own signatures" }];

function parseArgs(argv) {
  const opts = { concurrency: 4, quick: false };
  for (let i = 0; i < argv.length; i++) {
    if (argv[i] === "--concurrency") opts.concurrency = Number(argv[++i]) || 4;
    else if (argv[i] === "--quick") opts.quick = true;
  }
  return opts;
}

/** Shallow-clone a repository and build a client backed by the checkout. */
function cloneClient(repo) {
  const dir = mkdtempSync(join(tmpdir(), "repocanary-bench-"));
  execFileSync("git", ["clone", "--depth", "1", "--single-branch", "--quiet", "--", `https://github.com/${repo}`, dir], {
    timeout: 240_000,
    stdio: "ignore",
  });
  const listed = execFileSync("git", ["ls-files"], { cwd: dir, encoding: "utf8", maxBuffer: 64 * 1024 * 1024 })
    .trim()
    .split("\n")
    .filter(Boolean);
  const tree = [];
  for (const p of listed) {
    try {
      const st = statSync(join(dir, p));
      if (st.isFile()) tree.push({ path: p, type: "blob", size: st.size });
    } catch {
      // Submodule or broken link in the index; skip, as the API client does.
    }
  }
  const [owner, name] = repo.split("/");
  const client = {
    fetchRepo: async () => ({ meta: neutralMeta(owner, name), tree, treeTruncated: false, submodules: 0 }),
    fetchFile: async (o, r, ref, p) => {
      try {
        const text = readFileSync(join(dir, p), "utf8");
        return text.includes("\0") ? null : text;
      } catch {
        return null;
      }
    },
  };
  return { client, cleanup: () => rmSync(dir, { recursive: true, force: true }) };
}

async function scanClonedRepo(repo) {
  const started = Date.now();
  let handle;
  try {
    handle = cloneClient(repo);
    const [owner, name] = repo.split("/");
    const scan = await scanRepo({ owner, repo: name, client: handle.client });
    return { repo, ok: true, ms: Date.now() - started, ...pack(scan) };
  } catch (err) {
    return { repo, ok: false, ms: Date.now() - started, error: (err?.message ?? "clone failed").split("\n")[0] };
  } finally {
    handle?.cleanup();
  }
}

async function scanSample(sample) {
  const scan = await scanInMemory(sample);
  return {
    repo: sample.name,
    ok: true,
    ms: 0,
    note: sample.note,
    category: sample.category,
    expect: sample.expect,
    ...pack(scan),
  };
}

function pack(scan) {
  const counts = { high: 0, medium: 0, low: 0 };
  for (const f of scan.findings) counts[f.severity]++;
  return { verdict: scan.verdict, counts, findings: scan.findings };
}

/** Bounded-concurrency map preserving order. */
async function pool(items, limit, worker) {
  const out = new Array(items.length);
  let next = 0;
  await Promise.all(
    Array.from({ length: Math.min(limit, items.length) }, async () => {
      while (next < items.length) {
        const i = next++;
        out[i] = await worker(items[i]);
      }
    }),
  );
  return out;
}

const pad = (s, n) => String(s).padEnd(n);
const rate = (n, d) => (d === 0 ? "n/a" : `${((n / d) * 100).toFixed(0)}%`);

function printTable(title, rows) {
  console.log(`\n${title}`);
  console.log(`${pad("REPOSITORY", 30)} ${pad("VERDICT", 8)} H/M/L`);
  console.log("-".repeat(52));
  for (const r of rows) {
    const counts = r.counts ? `${r.counts.high}/${r.counts.medium}/${r.counts.low}` : "-";
    console.log(`${pad(r.repo, 30)} ${pad((r.verdict ?? "ERROR").toUpperCase(), 8)} ${counts}`);
  }
}

async function run() {
  const opts = parseArgs(process.argv.slice(2));

  const malicious = await pool(MALICIOUS, opts.concurrency, scanSample);
  const evasions = await pool(EVASIONS, opts.concurrency, scanSample);

  let benign = [];
  let tooling = [];
  if (!opts.quick) {
    console.log(`Cloning and scanning ${BENIGN.length} benign repositories (concurrency ${opts.concurrency})...`);
    benign = await pool(BENIGN, opts.concurrency, (e) => scanClonedRepo(e.repo));
    tooling = await pool(SECURITY_TOOLING, 1, (e) => scanClonedRepo(e.repo));
  }

  // ----- Malicious: true positives and false negatives -----
  // A "red" sample must come back red; a "flag" sample must come back at
  // least yellow. A green on either is a false negative.
  const missed = malicious.filter((r) => !meetsExpectation(r.expect, r.verdict));

  // Group the table by category so coverage reads as a catalog.
  console.log(`\nTHREAT CATALOG (${malicious.length} techniques across the campaigns)`);
  console.log(`${pad("TECHNIQUE", 34)} ${pad("EXPECT", 7)} ${pad("VERDICT", 8)} OK`);
  console.log("-".repeat(60));
  for (const [category, rows] of byCategory(malicious)) {
    console.log(`\n  ${category}`);
    for (const r of rows) {
      const ok = meetsExpectation(r.expect, r.verdict);
      console.log(
        `  ${pad(r.repo, 34)} ${pad(r.expect, 7)} ${pad((r.verdict ?? "ERR").toUpperCase(), 8)} ${ok ? "ok" : "MISS"}`,
      );
    }
  }

  const caughtCount = detection(malicious).caught;
  console.log(
    `\n  caught: ${caughtCount} of ${malicious.length}   detection ${rate(caughtCount, malicious.length)}   (red as red, flag as at least yellow)`,
  );
  console.log(`  FALSE NEGATIVES: ${missed.length}`);
  for (const m of missed) console.log(`    ${m.repo} expected ${m.expect}, got ${m.verdict}  (${m.note})`);

  // ----- Evasions: documented misses must still miss -----
  printTable("DOCUMENTED EVASIONS (expected to pass, per THREAT-MODEL)", evasions);
  const unexpectedlyCaught = evasions.filter((r) => !meetsExpectation(r.expect, r.verdict));
  console.log(`\n  passed as documented:  ${evasions.length - unexpectedlyCaught.length} of ${evasions.length}`);
  if (unexpectedlyCaught.length > 0) {
    console.log("  Now flagged red (a guess, not a real signal, investigate):");
    for (const e of unexpectedlyCaught) console.log(`    ${e.repo}: ${e.note}`);
  }

  // ----- Benign: false positives and noise -----
  let benignReds = 0;
  if (!opts.quick) {
    const scanned = benign.filter((r) => r.ok);
    printTable("BENIGN REPOSITORIES (expected not red)", benign);
    const reds = scanned.filter((r) => r.verdict === "red");
    const yellows = scanned.filter((r) => r.verdict === "yellow");
    const greens = scanned.filter((r) => r.verdict === "green");
    benignReds = reds.length;
    console.log(`\n  scanned:    ${scanned.length} of ${BENIGN.length}`);
    console.log(`  green:      ${greens.length}   ${rate(greens.length, scanned.length)}`);
    console.log(`  yellow:     ${yellows.length}   (noise: flagged for review)`);
    console.log(`  RED:        ${reds.length}   <- false positives, each one a bug`);

    if (reds.length > 0) {
      console.log("\n  FALSE POSITIVES:");
      for (const r of reds) {
        console.log(`    ${r.repo}`);
        for (const f of r.findings.filter((x) => x.severity === "high")) {
          console.log(`      [high] ${f.id}  ${f.file}${f.line ? ":" + f.line : ""}`);
        }
      }
    }

    // Which medium rules fire most on benign code. High on this list is a
    // candidate to tighten or drop to low.
    const medTally = new Map();
    for (const r of scanned) {
      for (const f of r.findings.filter((x) => x.severity === "medium")) {
        if (!medTally.has(f.id)) medTally.set(f.id, new Set());
        medTally.get(f.id).add(r.repo);
      }
    }
    if (medTally.size > 0) {
      console.log("\n  MEDIUM findings on benign repositories, by rule (candidates to tighten):");
      for (const [id, repos] of [...medTally.entries()].sort((a, b) => b[1].size - a[1].size)) {
        console.log(`    ${pad(id, 26)} ${repos.size} repos: ${[...repos].slice(0, 6).join(", ")}`);
      }
    }

    const failures = benign.filter((r) => !r.ok);
    if (failures.length > 0) {
      console.log("\n  Could not scan:");
      for (const f of failures) console.log(`    ${f.repo}: ${f.error}`);
    }

    printTable("SECURITY TOOLING (expected red, by design)", tooling);
  }

  // ----- Summary -----
  console.log("\n" + "=".repeat(52));
  console.log("SUMMARY");
  console.log(`  detection rate (malicious caught):  ${rate(caughtCount, malicious.length)}`);
  console.log(`  false negatives:                    ${missed.length}`);
  if (!opts.quick) {
    const scanned = benign.filter((r) => r.ok);
    const greens = scanned.filter((r) => r.verdict === "green").length;
    console.log(`  false positives (benign red):       ${benignReds}`);
    console.log(`  benign green rate:                   ${rate(greens, scanned.length)}`);
  }
  console.log(`  documented evasions still missed:   ${evasions.length - unexpectedlyCaught.length} of ${evasions.length}`);

  process.exitCode = missed.length + benignReds + unexpectedlyCaught.length > 0 ? 1 : 0;
}

run();
