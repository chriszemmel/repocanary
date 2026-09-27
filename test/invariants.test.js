/**
 * Tests for the project invariants. Each one exists so that a change
 * breaking a load-bearing promise fails loudly instead of shipping.
 */

import "./helpers.js";
import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync, readdirSync, statSync } from "node:fs";
import { join } from "node:path";
import { TEST_DIR } from "./helpers.js";
import { MAX_FILES_FETCHED, MAX_FILE_BYTES, MAX_TOTAL_BYTES } from "../src/github.js";
import { GREEN_SENTENCE } from "../src/report.js";
import { GREEN_MEANING } from "../src/verdict.js";

const ROOT = join(TEST_DIR, "..");

test("INVARIANT: zero runtime dependencies", () => {
  const pkg = JSON.parse(readFileSync(join(ROOT, "package.json"), "utf8"));
  assert.equal(pkg.dependencies, undefined, "repocanary must have no runtime dependencies");
  assert.equal(pkg.devDependencies, undefined, "repocanary must have no dev dependencies either");
  assert.ok(pkg.engines.node.includes("20"), "Node 20+ support is part of the contract");
  assert.equal(pkg.license, "MIT");
});

test("INVARIANT: the hard fetch caps exist and are sane", () => {
  assert.ok(Number.isInteger(MAX_FILES_FETCHED) && MAX_FILES_FETCHED > 0 && MAX_FILES_FETCHED <= 300);
  assert.ok(MAX_FILE_BYTES <= 2_000_000);
  assert.ok(MAX_TOTAL_BYTES <= 10_000_000);
});

test("INVARIANT: green is worded as 'nothing known matched', never as safe", () => {
  assert.ok(GREEN_SENTENCE.includes(GREEN_MEANING));
  assert.ok(GREEN_SENTENCE.toLowerCase().includes("not proof"));
});

function sourceFiles(dir, out = []) {
  for (const entry of readdirSync(dir)) {
    if (["node_modules", ".git", ".next", "out", "fixtures", "golden"].includes(entry)) continue;
    const full = join(dir, entry);
    if (statSync(full).isDirectory()) sourceFiles(full, out);
    else if (/\.(js|ts|tsx|md|json|yml|yaml)$/.test(entry)) out.push(full);
  }
  return out;
}

test("INVARIANT: the scanner never imports child_process or executes anything", () => {
  // The tool must never run what it scans. Nothing in src/ or cli.js may
  // spawn processes, eval strings, or dynamically import fetched content.
  const files = sourceFiles(join(ROOT, "src")).concat([join(ROOT, "cli.js")]);
  for (const file of files) {
    const content = readFileSync(file, "utf8");
    assert.ok(!/require\s*\(\s*["']child_process/.test(content), `${file} must not use child_process`);
    assert.ok(!/from\s+["']node:child_process/.test(content), `${file} must not use child_process`);
    assert.ok(!/\beval\s*\(\s*[^)]/.test(content), `${file} must not eval`);
    assert.ok(!/new\s+Function\s*\(/.test(content), `${file} must not build code from strings`);
  }
});

test("INVARIANT: the only outbound hosts in src/ are api.github.com and the opt-in AI endpoint", () => {
  const files = sourceFiles(join(ROOT, "src"));
  // The only hosts RepoCanary ever fetches from: GitHub for reading the
  // repo, and the AI providers when the user opts in with --ai.
  const allowed = new Set([
    "api.github.com",
    "generativelanguage.googleapis.com",
    "api.groq.com",
    "api.openai.com",
    "api.anthropic.com",
  ]);
  for (const file of files) {
    const content = readFileSync(file, "utf8");
    for (const m of content.matchAll(/https:\/\/([a-z0-9.-]+)/g)) {
      // Hosts inside rule patterns and messages are matched text, not
      // endpoints RepoCanary contacts; only fetch targets matter. This
      // check keeps anyone from quietly adding a telemetry endpoint next
      // to a fetch call.
      if (content.slice(Math.max(0, m.index - 80), m.index).includes("fetch")) {
        assert.ok(allowed.has(m[1]), `${file} fetches from unexpected host ${m[1]}`);
      }
    }
  }
});
