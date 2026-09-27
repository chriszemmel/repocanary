#!/usr/bin/env node
/**
 * Zero-dependency lint. Enforces the project's own rules:
 *   - every .js file passes node --check
 *   - no em dashes in any source or documentation file, written either as
 *     the character or as a JavaScript escape that renders as one
 *   - no runtime dependencies in package.json
 *   - no invisible characters outside test/
 */

import { readFileSync, readdirSync, statSync } from "node:fs";
import { join, relative, sep } from "node:path";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import { dirname } from "node:path";

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..");
const SKIP = new Set(["node_modules", ".git", ".next", "out", "fixtures", "golden"]);

function walk(dir, out = []) {
  for (const entry of readdirSync(dir)) {
    if (SKIP.has(entry)) continue;
    const full = join(dir, entry);
    if (statSync(full).isDirectory()) walk(full, out);
    else out.push(full);
  }
  return out;
}

// Both needles are built rather than written out, so this file does not
// contain the thing it forbids and can check itself along with the rest.
const EM_DASH = String.fromCharCode(0x2014);
const ESCAPED_EM_DASH = `${"\\"}u2014`;

const failures = [];
const files = walk(ROOT);

for (const file of files) {
  const rel = relative(ROOT, file).split(sep).join("/");
  // mjs and cjs are source like any other. They were absent, so the site's
  // build configuration sat outside both this check and the type checker at
  // the same time, which is the one file where nobody would notice.
  if (!/\.(js|mjs|cjs|ts|tsx|json|md|yml|yaml|txt)$/.test(file)) continue;
  const content = readFileSync(file, "utf8");

  if (content.includes(EM_DASH)) failures.push(`${rel}: contains an em dash`);
  if (content.includes(ESCAPED_EM_DASH)) failures.push(`${rel}: contains an escaped em dash`);
  if (/[\u200B\u200C\u200D\u2060]/.test(content) && !rel.startsWith("test/")) {
    failures.push(`${rel}: contains invisible characters`);
  }

  if (/\.(js|mjs|cjs)$/.test(file)) {
    const res = spawnSync(process.execPath, ["--check", file], { encoding: "utf8" });
    if (res.status !== 0) failures.push(`${rel}: syntax error\n${res.stderr}`);
  }
}

const pkg = JSON.parse(readFileSync(join(ROOT, "package.json"), "utf8"));
if (pkg.dependencies && Object.keys(pkg.dependencies).length > 0) {
  failures.push("package.json: runtime dependencies are forbidden");
}

if (failures.length > 0) {
  console.error(`lint: ${failures.length} problem(s)`);
  for (const f of failures) console.error(`  ${f}`);
  process.exit(1);
}
console.log(`lint: ${files.length} files clean`);
