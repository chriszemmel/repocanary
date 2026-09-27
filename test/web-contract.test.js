/**
 * web/types/engine.d.ts is hand written. TypeScript believes it without
 * checking it against the engine, so a rename or a new error kind would keep
 * compiling and break the site at run time. These assertions are that check.
 */

import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

import * as github from "../src/github.js";
import * as scan from "../src/scan.js";
import * as ai from "../src/ai.js";
import * as verdict from "../src/verdict.js";

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..");
const DTS = readFileSync(join(ROOT, "web/types/engine.d.ts"), "utf8");

const MODULES = {
  "@engine/github.js": github,
  "@engine/scan.js": scan,
  "@engine/ai.js": ai,
  "@engine/verdict.js": verdict,
};

/** The body of one `declare module "..." { ... }` block. */
function moduleBlock(specifier) {
  const start = DTS.indexOf(`declare module "${specifier}"`);
  assert.notEqual(start, -1, `engine.d.ts declares no module ${specifier}`);
  const open = DTS.indexOf("{", start);
  let depth = 0;
  for (let i = open; i < DTS.length; i++) {
    if (DTS[i] === "{") depth += 1;
    if (DTS[i] === "}") {
      depth -= 1;
      if (depth === 0) return DTS.slice(open + 1, i);
    }
  }
  throw new Error(`unterminated module block for ${specifier}`);
}

for (const [specifier, mod] of Object.entries(MODULES)) {
  test(`engine.d.ts declares only functions ${specifier} exports`, () => {
    const declared = [...moduleBlock(specifier).matchAll(/export function (\w+)/g)].map((m) => m[1]);
    for (const name of declared) {
      assert.equal(typeof mod[name], "function", `${specifier} has no exported function ${name}`);
    }
  });
}

test("engine.d.ts GitHubErrorKind matches every kind the engine constructs", () => {
  const source = readFileSync(join(ROOT, "src/github.js"), "utf8");
  const constructed = new Set(
    [...source.matchAll(/new GitHubError\([\s\S]*?,\s*"([a-z-]+)"/g)].map((m) => m[1]),
  );
  const union = moduleBlock("@engine/github.js").match(/export type GitHubErrorKind\s*=([\s\S]*?);/);
  assert.ok(union, "engine.d.ts declares no GitHubErrorKind");
  const declared = new Set([...union[1].matchAll(/"([a-z-]+)"/g)].map((m) => m[1]));

  assert.deepEqual(
    [...constructed].sort(),
    [...declared].sort(),
    "the declared error kinds and the ones src/github.js throws have drifted apart",
  );
});

test("engine.d.ts Verdict matches the engine's verdicts", () => {
  const declared = [...moduleBlock("@engine/verdict.js").matchAll(/"(green|yellow|red)"/g)].map(
    (m) => m[1],
  );
  assert.deepEqual([...new Set(declared)].sort(), ["green", "red", "yellow"]);
  assert.equal(verdict.decideVerdict([]), "green");
});

test("engine.d.ts Finding fields match a finding the engine produces", () => {
  const declared = [...moduleBlock("@engine/scan.js").matchAll(/^\s{4}(\w+)[?]?:/gm)].map((m) => m[1]);
  const finding = { id: "", severity: "high", file: "", line: null, snippet: "", why: "", next: "" };
  for (const key of Object.keys(finding)) {
    assert.ok(declared.includes(key), `engine.d.ts does not declare Finding.${key}`);
  }
});

test("the site's build configuration loads without a TypeScript compiler", async () => {
  // next.config.ts cannot be read without TypeScript: Next resolves the
  // `typescript` package from the app directory and calls into it before it
  // looks at a single setting. On a builder whose restored node_modules gave
  // back a typescript without a Node-side `sys`, that died with
  //   TypeError: Cannot read properties of undefined (reading 'fileExists')
  // and the deploy failed having never reached the config. Plain ESM has no
  // such step, so this asserts the file is what it needs to be and that
  // importing it takes nothing but Node.
  const { existsSync } = await import("node:fs");
  assert.ok(existsSync(join(ROOT, "web/next.config.mjs")), "the config must be plain ESM");
  assert.ok(
    !existsSync(join(ROOT, "web/next.config.ts")),
    "a .ts config brings back a compiler resolution the deploy does not need",
  );

  const config = (await import(join(ROOT, "web/next.config.mjs"))).default;
  // And it is still the configuration it claims to be: the headers the site's
  // one security control depends on come from this file.
  const rules = await config.headers();
  const keys = rules[0].headers.map((h) => h.key);
  for (const required of ["Content-Security-Policy", "X-Frame-Options", "Strict-Transport-Security"]) {
    assert.ok(keys.includes(required), `${required} must survive in the config`);
  }
  assert.equal(config.poweredByHeader, false);
});
