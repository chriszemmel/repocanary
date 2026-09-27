#!/usr/bin/env node
/**
 * The gate a loosening change has to pass.
 *
 * Most fixes to this scanner narrow a rule: a false positive is found on a
 * real repository and the rule learns to let that shape through. Every one of
 * those can only cost detection, never add noise, so the question a corpus
 * run answers ("did this convict a thousand honest projects?") is the wrong
 * one. The question is whether anything that used to be caught still is.
 *
 * Three things must hold, and all three are cheap:
 *
 *   - every synthetic malicious sample still reaches its expected verdict
 *   - every documented evasion still passes, so the stated limits stay real
 *   - every repository in expected-red.txt is still red
 *
 * That last one is the whole risk of a downgrade in one list: those are the
 * reds a human has already read and confirmed. Losing one silently is how a
 * scanner stops working while its tests stay green.
 *
 *   node scripts/guard.js              everything
 *   node scripts/guard.js --offline    skip the clones, samples only
 */

import { execFileSync } from "node:child_process";
import { mkdtempSync, readFileSync, readdirSync, rmSync, lstatSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve, sep } from "node:path";
import { fileURLToPath } from "node:url";
import { scanRepo } from "../src/scan.js";
import { MALICIOUS, EVASIONS } from "./benchmark-samples.js";
import { meetsExpectation, neutralMeta, scanSample } from "./grade.js";

const HERE = dirname(fileURLToPath(import.meta.url));
const EXPECTED = join(HERE, "corpus", "expected-red.txt");
const offline = process.argv.includes("--offline");
const concurrency = 5;

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

function cloneClient(repo) {
  const dir = mkdtempSync(join(tmpdir(), "repocanary-guard-"));
  execFileSync("git", ["clone", "--depth", "1", "--single-branch", "--quiet", "--", `https://github.com/${repo}`, dir], {
    timeout: 240_000,
    stdio: ["ignore", "ignore", "pipe"],
  });
  const listed = execFileSync("git", ["ls-files"], { cwd: dir, encoding: "utf8", maxBuffer: 64 * 1024 * 1024 })
    .trim()
    .split("\n")
    .filter(Boolean);
  const tree = [];
  let symlinks = 0;
  for (const p of listed) {
    try {
      const st = lstatSync(join(dir, p));
      if (st.isSymbolicLink()) symlinks += 1;
      else if (st.isFile()) tree.push({ path: p, type: "blob", size: st.size });
    } catch {
      // A submodule or a broken link, which the API client skips too.
    }
  }
  const [owner, name] = repo.split("/");
  return {
    client: {
      fetchRepo: async () => ({ meta: neutralMeta(owner, name), tree, treeTruncated: false, submodules: 0, symlinks }),
      fetchFile: async (o, r, ref, p) => {
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

const failures = [];

// 1. Detection on the synthetic set.
const caught = await pool(MALICIOUS, concurrency, async (s) => {
  const scan = await scanSample(s);
  return { name: s.name, ok: meetsExpectation(s.expect, scan.verdict), verdict: scan.verdict, expect: s.expect };
});
const missed = caught.filter((r) => !r.ok);
console.log(`malicious samples   ${caught.length - missed.length}/${caught.length} caught`);
for (const m of missed) failures.push(`no longer caught: ${m.name} (expected ${m.expect}, got ${m.verdict})`);

// 2. The documented limits stay limits: an evasion that starts being caught
// is good news, but the threat model claims it is not, so it has to be read
// and the claim rewritten rather than quietly drifting.
const evaded = await pool(EVASIONS, concurrency, async (s) => {
  const scan = await scanSample(s);
  return { name: s.name, ok: meetsExpectation(s.expect, scan.verdict), verdict: scan.verdict, expect: s.expect };
});
const drifted = evaded.filter((r) => !r.ok);
console.log(`documented evasions ${evaded.length - drifted.length}/${evaded.length} still as documented`);
for (const d of drifted) failures.push(`evasion changed: ${d.name} (documented ${d.expect}, got ${d.verdict}). Update THREAT-MODEL`);

// 3. The reds a human has already confirmed.
if (offline) {
  console.log("expected reds       skipped (--offline)");
} else {
  const repos = readFileSync(EXPECTED, "utf8")
    .split("\n")
    .map((l) => l.trim())
    .filter((l) => l && !l.startsWith("#"))
    .map((l) => l.split(/\s+/)[0]);
  const reds = await pool(repos, concurrency, async (repo) => {
    let handle;
    try {
      handle = cloneClient(repo);
      const [owner, name] = repo.split("/");
      const scan = await scanRepo({ owner, repo: name, client: handle.client });
      return { repo, verdict: scan.verdict };
    } catch (err) {
      return { repo, verdict: "unreadable", detail: String(err?.message ?? "").split("\n")[0].slice(0, 120) };
    } finally {
      handle?.cleanup();
    }
  });
  const lost = reds.filter((r) => r.verdict !== "red");
  console.log(`expected reds       ${reds.length - lost.length}/${reds.length} still red`);
  for (const l of lost) {
    // A repository that could not be read has not been checked, and reporting
    // that as a pass is the failure this whole file exists to prevent.
    failures.push(`no longer red: ${l.repo} (now ${l.verdict}${l.detail ? `: ${l.detail}` : ""})`);
  }
}

console.log("");
if (failures.length === 0) {
  console.log("Nothing that was caught before is missed now.");
  process.exit(0);
}
console.error(`${failures.length} loss${failures.length === 1 ? "" : "es"} of detection:`);
for (const f of failures) console.error(`  ${f}`);
console.error("\nA narrowing fix cost detection. Either it was too broad, or the entry it lost needs its reason rewritten.");
process.exit(1);
