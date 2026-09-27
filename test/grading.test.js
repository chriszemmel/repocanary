/**
 * The scripts that grade the engine are graded here. scripts/coverage.js
 * writes THREAT-COVERAGE.md and scripts/benchmark.js prints the detection
 * rate; a bug in either reports a success that is not there, so their rules
 * are pinned, the synthetic half of the benchmark runs as part of the suite,
 * and every rule the engine can emit has to be exercised somewhere.
 */

import "./helpers.js";
import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync, readdirSync } from "node:fs";
import { join } from "node:path";
import { listFixtures, loadFixture, scanFixture, TEST_DIR } from "./helpers.js";
import { byCategory, detection, firedRules, meetsExpectation, scanSample } from "../scripts/grade.js";
import { renderCoverage } from "../scripts/coverage.js";
import { MALICIOUS, EVASIONS } from "../scripts/benchmark-samples.js";

const ROOT = join(TEST_DIR, "..");

test("meetsExpectation: red needs red, flag needs at least yellow, miss must not be red", () => {
  assert.equal(meetsExpectation("red", "red"), true);
  assert.equal(meetsExpectation("red", "yellow"), false);
  assert.equal(meetsExpectation("red", "green"), false);
  assert.equal(meetsExpectation("flag", "red"), true);
  assert.equal(meetsExpectation("flag", "yellow"), true);
  assert.equal(meetsExpectation("flag", "green"), false);
  assert.equal(meetsExpectation("miss", "green"), true);
  assert.equal(meetsExpectation("miss", "yellow"), true);
  assert.equal(meetsExpectation("miss", "red"), false);
  assert.throws(() => meetsExpectation("maybe", "red"), /Unknown expectation/);
});

test("detection counts and rounds honestly, and an empty corpus is 0%, not 100%", () => {
  assert.deepEqual(detection([]), { caught: 0, total: 0, pct: 0 });
  const rows = [
    { expect: "red", verdict: "red" },
    { expect: "red", verdict: "yellow" },
    { expect: "flag", verdict: "yellow" },
  ];
  assert.deepEqual(detection(rows), { caught: 2, total: 3, pct: 67 });
});

test("firedRules lists each rule once at its highest severity, sorted", () => {
  const rules = firedRules([
    { id: "b", severity: "low" },
    { id: "a", severity: "medium" },
    { id: "b", severity: "high" },
    { id: "a", severity: "low" },
  ]);
  assert.deepEqual(rules, [
    { id: "a", sev: "medium" },
    { id: "b", sev: "high" },
  ]);
});

test("byCategory keeps first-seen order", () => {
  const grouped = byCategory([{ category: "z" }, { category: "a" }, { category: "z" }]);
  assert.deepEqual([...grouped.keys()], ["z", "a"]);
  assert.equal(grouped.get("z").length, 2);
});

test("every sample declares a known expectation, a category, files, and a unique name", () => {
  const names = new Set();
  for (const s of [...MALICIOUS, ...EVASIONS]) {
    assert.ok(["red", "flag", "miss"].includes(s.expect), `${s.name}: expect ${s.expect}`);
    assert.ok(typeof s.category === "string" && s.category.length > 0, `${s.name}: category`);
    assert.ok(Object.keys(s.files).length > 0, `${s.name}: files`);
    assert.ok(!names.has(s.name), `${s.name} is listed twice`);
    names.add(s.name);
  }
  assert.ok(MALICIOUS.every((s) => s.expect !== "miss"), "a documented miss belongs in EVASIONS");
  assert.ok(EVASIONS.every((s) => s.expect === "miss"), "an evasion sample is one the engine misses");
});

test("no sample carries a live host or a routable address", () => {
  // The threat corpus is authored, not copied: every host is reserved and
  // every IP sits in a documentation range, so the samples are inert. The
  // only real domains allowed are the ones a rule matches by name (a webhook
  // or tunnel service, a registry, a source host), never a payload server.
  const reserved = /(^|\.)(invalid|example|test|localhost)$|^(example\.com|localhost)$/;
  // A host a rule names literally, escaped or plain, in any source file.
  // Optional groups in a pattern (discord(app)?\.com) are dropped so the
  // plain host is searchable.
  const sources = readdirSync(join(ROOT, "src"))
    .map((f) => readFileSync(join(ROOT, "src", f), "utf8"))
    .join("\n")
    .replace(/\([^()]*\)\?/g, "");
  const namedInARule = (host) => {
    const labels = host.split(".");
    for (let i = 0; i <= labels.length - 2; i++) {
      const suffix = labels.slice(i).join(".");
      if (sources.includes(suffix) || sources.includes(suffix.replace(/\./g, "\\."))) return true;
    }
    return false;
  };
  // A bare address; digits that are only the first labels of a reserved
  // hostname (45.61.129.255.example.invalid) are inert and pass.
  const routable = /\b(?!(?:192\.0\.2|198\.51\.100|203\.0\.113|127\.0\.0|0\.0\.0|10\.0\.0)\.)(?:\d{1,3}\.){3}\d{1,3}(?![.\w])/;
  for (const s of [...MALICIOUS, ...EVASIONS]) {
    for (const [path, content] of Object.entries(s.files)) {
      for (const url of content.match(/https?:\/\/[^\s"'`)]+/g) ?? []) {
        const host = new URL(url).hostname;
        if (/^\d+\.\d+\.\d+\.\d+$/.test(host)) continue;
        assert.ok(reserved.test(host) || namedInARule(host), `${s.name} ${path}: ${host} is neither reserved nor named by a rule`);
      }
      assert.ok(!routable.test(content), `${s.name} ${path}: routable IP address`);
    }
  }
});

test("the synthetic benchmark holds: every malicious sample is caught and every evasion still passes", async () => {
  const misses = [];
  for (const s of MALICIOUS) {
    const { verdict } = await scanSample(s);
    if (!meetsExpectation(s.expect, verdict)) misses.push(`${s.name} expected ${s.expect}, got ${verdict}`);
  }
  assert.deepEqual(misses, []);
  const guesses = [];
  for (const s of EVASIONS) {
    const { verdict } = await scanSample(s);
    if (!meetsExpectation(s.expect, verdict)) guesses.push(`${s.name} is documented as a miss but came back ${verdict}`);
  }
  assert.deepEqual(guesses, []);
});

test("THREAT-COVERAGE.md and the site's coverage data match what the engine does now", async () => {
  const { body, json } = await renderCoverage();
  assert.equal(readFileSync(join(ROOT, "THREAT-COVERAGE.md"), "utf8"), body, "run: node scripts/coverage.js");
  assert.equal(readFileSync(join(ROOT, "web/lib/coverage-data.json"), "utf8"), json, "run: node scripts/coverage.js");
});

test("the coverage catalog is deterministic", async () => {
  const a = await renderCoverage();
  const b = await renderCoverage();
  assert.equal(a.body, b.body);
  assert.equal(a.json, b.json);
});

/** Every rule id the engine can emit, read from the source. */
function ruleIdsInSource() {
  const ids = new Set();
  for (const entry of readdirSync(join(ROOT, "src"))) {
    // report.js names the SARIF rule, not a detection rule.
    if (entry === "report.js") continue;
    const source = readFileSync(join(ROOT, "src", entry), "utf8");
    for (const m of source.matchAll(/\bid:\s*"([a-z0-9-]*-[a-z0-9-]*)"/g)) ids.add(m[1]);
    for (const m of source.matchAll(/finding\(\s*\n?\s*"([a-z0-9-]+)"/g)) ids.add(m[1]);
  }
  return ids;
}

test("every rule the engine can emit fires on at least one fixture or benchmark sample", async () => {
  const exercised = new Set();
  for (const name of listFixtures()) {
    const { result } = await scanFixture(name);
    for (const f of result.findings) exercised.add(f.id);
  }
  for (const s of [...MALICIOUS, ...EVASIONS]) {
    const result = await scanSample(s);
    for (const f of result.findings) exercised.add(f.id);
  }
  const unexercised = [...ruleIdsInSource()].filter((id) => !exercised.has(id)).sort();
  assert.deepEqual(unexercised, [], "a rule nothing exercises is a rule nobody has seen fire");
});

test("every fixture pins at least one rule by name, so a verdict cannot pass by accident", () => {
  for (const name of listFixtures()) {
    const { expected } = loadFixture(name);
    const pinned = [...(expected.mustFire ?? []), ...(expected.mustNotFire ?? [])];
    assert.ok(pinned.length > 0, `${name} pins no rule`);
  }
});
