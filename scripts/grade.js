/**
 * The grading rules shared by scripts/benchmark.js and scripts/coverage.js,
 * kept apart from both so the rules that judge the engine can themselves be
 * judged by test/grading.test.js. A bug here would report success that is
 * not there, so nothing in this file touches the network or the filesystem.
 */

import { scanRepo } from "../src/scan.js";

/**
 * Metadata of a long-established account, so context rules stay quiet and
 * the measurement is of the file rules. Real benign repositories have
 * exactly this, and a synthetic sample is judged on its code unless it
 * overrides a field on purpose.
 */
export function neutralMeta(owner, name) {
  return {
    owner,
    repo: name,
    defaultBranch: "main",
    ref: "main",
    description: null,
    topics: [],
    stars: 1000,
    isFork: false,
    ownerType: "User",
    ownerCreatedAt: "2012-01-01T00:00:00Z",
    ownerPublicRepos: 50,
    orgPublicMembers: null,
    commitAuthorNames: [owner],
    commitDates: [],
  };
}

/** An injected client over an in-memory { path: content } map. */
export function memoryClient(owner, name, files, meta = {}) {
  const tree = Object.entries(files).map(([path, content]) => ({ path, type: "blob", size: content.length }));
  return {
    fetchRepo: async () => ({ meta: { ...neutralMeta(owner, name), ...meta }, tree, treeTruncated: false, submodules: 0 }),
    fetchFile: async (o, r, ref, p) => (p in files ? files[p] : null),
  };
}

/** Scan one synthetic sample through the real engine, in memory. */
export async function scanSample(sample, now = Date.now()) {
  const owner = "candidate";
  const client = memoryClient(owner, sample.name, sample.files, sample.meta);
  return scanRepo({ owner, repo: sample.name, client, now });
}

/**
 * Whether a verdict satisfies what a sample expects. "red" must come back
 * red; "flag" must come back at least yellow; "miss" is a documented limit
 * that must not come back red, since a red there would be a guess.
 */
export function meetsExpectation(expect, verdict) {
  if (expect === "red") return verdict === "red";
  if (expect === "flag") return verdict === "yellow" || verdict === "red";
  if (expect === "miss") return verdict === "green" || verdict === "yellow";
  throw new Error(`Unknown expectation: ${expect}`);
}

/** The distinct rules a scan fired, each with the highest severity it reached. */
export function firedRules(findings) {
  const rank = { high: 2, medium: 1, low: 0 };
  const seen = new Map();
  for (const f of findings) {
    const current = seen.get(f.id);
    if (current === undefined || rank[f.severity] > rank[current]) seen.set(f.id, f.severity);
  }
  return [...seen.entries()].map(([id, sev]) => ({ id, sev })).sort((a, b) => a.id.localeCompare(b.id));
}

/** Detection rate as a whole percentage, with the count behind it. */
export function detection(rows) {
  const caught = rows.filter((r) => meetsExpectation(r.expect, r.verdict)).length;
  return { caught, total: rows.length, pct: rows.length === 0 ? 0 : Math.round((caught / rows.length) * 100) };
}

/** Group rows by category, preserving first-seen order. */
export function byCategory(rows) {
  const categories = new Map();
  for (const r of rows) {
    if (!categories.has(r.category)) categories.set(r.category, []);
    categories.get(r.category).push(r);
  }
  return categories;
}
