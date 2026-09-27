/**
 * A scanner an attacker can stall is a scanner an attacker can switch off.
 *
 * Every rule in this project is a regular expression run over a file someone
 * else wrote, up to a megabyte of it, fifty files per scan, inside a web
 * request with a sixty second ceiling. A pattern that backtracks
 * catastrophically therefore is not a performance nit: it is a denial of
 * service, and worse, it is one a malicious repository can aim at its own
 * scan so no verdict is ever reached.
 *
 * These are the shapes that cause it. `(^|\n)\s*x` and `^\s*x` under /m are
 * the common one, because `\s` matches a newline, so a run of blank lines can
 * be re-divided at every position. `token[^\n]*needle` is the other: on a
 * long line every occurrence of the token rescans the rest of it. Both were
 * present here, and the worst took seventeen seconds on a single file of a
 * hundred thousand newlines.
 */

import "./helpers.js";
import test from "node:test";
import assert from "node:assert/strict";
import { checkFile } from "../src/heuristics.js";
import { MAX_REPORTED_FINDINGS, scanRepo } from "../src/scan.js";
import { MAX_FILE_BYTES, MAX_TOTAL_BYTES, FOLLOW_UP_RESERVE_BYTES } from "../src/github.js";
import { makeClient } from "./helpers.js";

/** One name per rule family, so no group of rules escapes this. */
const NAMES = [
  "package.json",
  "package-lock.json",
  "yarn.lock",
  "pnpm-lock.yaml",
  "setup.py",
  "Cargo.toml",
  "build.rs",
  "Makefile",
  "Dockerfile",
  "install.sh",
  "index.js",
  ".npmrc",
  ".yarnrc.yml",
  ".vscode/tasks.json",
  ".mcp.json",
  ".claude/settings.json",
  ".dir-locals.el",
  ".nvim.lua",
  "CLAUDE.md",
  "pom.xml",
  "build.gradle",
  "extconf.rb",
  "composer.json",
  ".github/workflows/ci.yml",
  "bin/lint",
  "README.md",
];

/**
 * Inputs chosen to be worst cases rather than realistic ones: long runs of a
 * single character, and long runs of the tokens the rules look for, so a
 * pattern that rescans from every occurrence has the most to rescan.
 */
function hostileContents(scale) {
  return {
    newlines: "\n".repeat(scale * 5),
    blankIndent: "  \n".repeat(scale * 2),
    curl: "curl ".repeat(scale),
    eval: "exec require import fetch eval ".repeat(Math.round(scale / 4)),
    add: "ADD ".repeat(scale),
    registry: "registry".repeat(scale),
    slashes: "/".repeat(scale * 5),
    quotes: '"'.repeat(scale * 3),
    dollar: "$(".repeat(scale * 2),
    comment: "// x\n".repeat(scale),
    secrets: "curl ${{ secrets.A }} ".repeat(Math.round(scale / 2)),
    bangs: "!\n".repeat(scale * 2),
    url: `https://${"a.".repeat(scale)}com/x`,
    // An import declaration that never completes: `import` and then a run
    // of spaces and a stray character took seconds at two kilobytes, because
    // the declaration pattern re-divided the spaces at every position.
    importSpaces: `import${" ".repeat(scale)}!\nfrom a import ${" ".repeat(scale)}!\n`,
    // Quote-backslash pairs: every quote opened a string literal that
    // consumed the rest of the line through the escape branch and failed.
    escapedQuotes: '"\\'.repeat(scale),
    // Four shapes an audit found after this file was first written, each one
    // a run with no ceiling sitting in front of a literal, and each one
    // quadratic. They are here rather than only in the pinned cases below
    // because every rule family above has to survive them too.
    opens: "open(".repeat(scale),
    posts: "requests.post(".repeat(Math.round(scale / 3)),
    compiles: "exec(compile(".repeat(Math.round(scale / 3)),
    fetches: "fetch(".repeat(Math.round(scale / 2)),
    // One unbroken run with no whitespace in it, which is what makes two
    // unbounded runs either side of a character re-divide the same text.
    urlRun: "http://a?".repeat(Math.round(scale / 2)),
    links: "[x](http://a?".repeat(Math.round(scale / 3)),
    // A download per line, each naming a file: the shape that made the rule
    // rebuild the rest of the file once per line.
    downloads: Array.from({ length: Math.round(scale / 8) }, (_, i) => `curl -o a${i}.sh http://e.example/a${i}.sh`).join("\n"),
    // A lone carriage return is a line break to `^` under /m, and `[^\S\n]`
    // matched it too, so indentation patterns re-divided a run of them at
    // every position. Behind a pull_request_target checkout, where two such
    // runs sit side by side, four thousand of them took twenty seconds.
    carriageReturns: "\r".repeat(scale * 5),
    prtCarriageReturns: `on: pull_request_target\n    ref: \${{ github.event.pull_request.head.sha }}\n${"\r".repeat(Math.round(scale / 5))}`,
    // One escape anywhere switches the YAML decoder on; then every quote in
    // a line of quote-backslash pairs opened a scalar that ran to the end.
    yamlEscapes: `# \\u0041\n${'"\\'.repeat(scale)}`,
    zeroWidth: "\u200b".repeat(scale * 5),
    rawUrls: "raw.githubusercontent.com/".repeat(Math.round(scale / 4)),
  };
}

/**
 * Generous on purpose. The point is to catch a pattern that has gone
 * quadratic, which costs seconds to minutes, not to police tens of
 * milliseconds on a shared CI runner.
 */
const BUDGET_MS = 5_000;

test("no rule stalls on a hostile file", () => {
  const contents = hostileContents(20_000);
  for (const path of NAMES) {
    for (const [label, content] of Object.entries(contents)) {
      const file = {
        path,
        content,
        bytes: content.length,
        lines: content.split("\n").length,
        executable: false,
      };
      const started = performance.now();
      let findings;
      assert.doesNotThrow(() => {
        findings = checkFile(file, { owner: "o", repo: "r" });
      }, `${path} / ${label} threw`);
      const ms = performance.now() - started;
      assert.ok(Array.isArray(findings), `${path} / ${label} returned no findings array`);
      assert.ok(ms < BUDGET_MS, `${path} / ${label} took ${ms.toFixed(0)}ms, over the ${BUDGET_MS}ms budget`);
    }
  }
});

test("INVARIANT: scan cost grows with the file, not with its square", () => {
  // Quadratic means four times the work for twice the input, and linear means
  // two, so the threshold has to sit between them: at eight, which is what it
  // was, nothing quadratic could ever fail it, and four rules that were
  // quadratic at every step did not. Three fails on quadratic while leaving
  // half again over linear for a warm-up effect and a noisy runner.
  //
  // Per shape, never summed. This test used to add up every path and every
  // shape and compare the totals, which is the one arrangement that cannot
  // see what it is looking for: one quadratic shape among a dozen linear ones
  // moves a total by a few percent. Four quadratic rules sat under a passing
  // version of this assertion for exactly that reason.
  const small = hostileContents(10_000);
  const large = hostileContents(20_000);
  const measure = (content) => {
    let total = 0;
    for (const path of NAMES) {
      const file = {
        path,
        content,
        bytes: content.length,
        lines: content.split("\n").length,
        executable: false,
      };
      const started = performance.now();
      checkFile(file, { owner: "o", repo: "r" });
      total += performance.now() - started;
    }
    return total;
  };
  // The smallest of several paired ratios, not the ratio of the smallest
  // readings: taking a minimum in the denominator inflates the result, which
  // is the wrong direction for a threshold you are trying not to trip by
  // accident. Each trial times both sizes and divides them, and the lowest
  // trial wins. Noise on a shared runner adds time to whichever size it lands
  // on, so it can only push a trial away from the truth; a rule that is
  // genuinely quadratic measures near four in every trial and has no low one
  // to hide behind.
  const ratioFor = (shape, samples) => {
    let half = 0;
    let ratio = Infinity;
    for (let i = 0; i < samples; i++) {
      const h = measure(small[shape]);
      const f = measure(large[shape]);
      if (i === 0) half = h;
      ratio = Math.min(ratio, f / Math.max(h, 1));
    }
    return { half, ratio };
  };

  for (const shape of Object.keys(small)) {
    measure(small[shape]); // warm the JIT and the regex caches, so the ratio is not measuring compilation
    let { half, ratio } = ratioFor(shape, 1);
    // A shape the rules dispose of in a millisecond cannot be measured this
    // way: scheduler jitter alone moves it by a factor of four. Those are
    // covered by the whole-repository budget below, at the size that matters.
    if (half < 20) continue;
    // One reading over the line is re-taken before it is believed. The window
    // this has to resolve is narrow (linear is 2, quadratic is 4), so a single
    // sample straddles it under load often enough to matter: a genuinely
    // linear shape came back at 3.1 on CI and failed a passing tree. Paying
    // for the extra samples only when a shape looks bad keeps the common case
    // one measurement.
    if (ratio >= 3) ({ ratio } = ratioFor(shape, 5));
    assert.ok(ratio < 3, `doubling "${shape}" multiplied the work by ${ratio.toFixed(1)}, which is not linear`);
  }
});

/**
 * The per-file assertions above bound one rule on one file. This bounds a
 * whole scan, which is the number that actually has to fit inside a web
 * request, and it is the assertion that would have caught the original bug
 * at the size it really mattered: the byte budget, not the sample size a
 * probe happens to use.
 */
test("INVARIANT: a repository built to be slow still scans inside the request budget", async () => {
  // What the caps allow a single scan to read: the selection's budget plus
  // the separate allowance for files an install script or an editor hook
  // names.
  //
  // Every hostile shape, one per megabyte-sized file, rather than one shape
  // repeated. A single shape is a guess about which pattern is worst, and the
  // previous guess ("curl ") happened to be one of the linear ones, so this
  // assertion passed while a megabyte of "open(" took 251 seconds. A scanned
  // repository picks the shape, so the test has to try all of them, and it
  // has to do it at MAX_FILE_BYTES: quadratic is invisible at a tenth of that
  // and fatal at the size the engine actually reads.
  const megabytes = Math.ceil((MAX_TOTAL_BYTES + FOLLOW_UP_RESERVE_BYTES) / MAX_FILE_BYTES);
  const shapes = Object.values(hostileContents(MAX_FILE_BYTES / 5));
  const files = {};
  // Spread across the file kinds that carry the most rules, so no shape is
  // only ever judged by the workflow rules.
  const carriers = [".github/workflows/build", "src/index", "Makefile", "CLAUDE.md", "install", "setup", "bin/tool"];
  for (let i = 0; i < megabytes; i++) {
    const carrier = carriers[i % carriers.length];
    const name = carrier.includes(".") ? `${i}-${carrier}` : `${carrier}-${i}.js`;
    files[name] = shapes[i % shapes.length];
  }
  // And every shape at the per-file cap, on the path family it is aimed at,
  // even when there are more shapes than the budget has megabytes for.
  for (let i = megabytes; i < shapes.length; i++) files[`extra-${i}.js`] = shapes[i];
  const client = makeClient(files);

  const started = performance.now();
  const result = await scanRepo({ owner: "o", repo: "r", client });
  const ms = performance.now() - started;

  assert.ok(result.verdict, "a hostile repository must still produce a verdict");
  // Vercel's ceiling for this route is 60 seconds. Half of it leaves room for
  // a slower runner and for the fetches, while still failing long before a
  // request could time out. Measured worst case at the time of writing: 7.5s.
  assert.ok(ms < 30_000, `a hostile repository took ${(ms / 1000).toFixed(1)}s to scan, which risks the request budget`);
});

/**
 * The tests above check shapes I thought of. This one checks the ones I did
 * not: random files built from the tokens the rules react to, which is where
 * a pattern with two variable-length runs next to each other shows itself.
 *
 * It is not a real fuzzer, because a test that finds a different bug on every
 * run is a test nobody can act on. The seeds are fixed, so a failure here is
 * reproducible from the seed printed beside it, and new seeds get added when
 * a sweep with fresh ones turns something up. That is how the `\S+` in
 * DANGEROUS_SCRIPT was found: seed 103442 built a 30 KB `.nvim.lua` that took
 * four seconds.
 */

/** xorshift32: same sequence everywhere, so a failing case is reproducible. */
function seeded(seed) {
  let x = seed >>> 0 || 1;
  return () => {
    x ^= x << 13;
    x >>>= 0;
    x ^= x >> 17;
    x ^= x << 5;
    x >>>= 0;
    return x / 4294967296;
  };
}

const INVISIBLE = ["\u200b", "\u200d", "\ufeff", "\u202e", "\u{e0041}", "\u{1f3f4}"];
const TOKENS = [
  ...'{}[]()<>"\'`\\/|;&$#!=:,.-_ \n\t\r*?+^',
  "curl ",
  "wget ",
  "eval(",
  "https://",
  "npm ",
  "${{",
  "}}",
  "secrets.",
  "ADD ",
  "registry=",
  "postinstall",
  "require(",
  "base64",
  "node -e",
  "sh -c",
  "//",
  "-o ",
  "| sh",
  // The escape forms the JSON and YAML decoders resolve, so the fuzzer
  // exercises that path rather than leaving it to the shapes I thought of.
  "\\u0063",
  "\\x63",
  '"runOn"',
  '"hooks"',
  ...INVISIBLE,
];

/** The file a given seed builds, so a failure can be reproduced from the seed. */
function generated(seed) {
  const random = seeded(seed);
  const length = 1 + Math.floor(random() * 900);
  let content = "";
  for (let j = 0; j < length; j++) content += TOKENS[Math.floor(random() * TOKENS.length)];
  // Repeating a fragment hard is what makes a pattern re-divide it.
  if (random() < 0.4) content = content.slice(0, 40).repeat(1 + Math.floor(random() * 900));
  return { content, path: NAMES[Math.floor(random() * NAMES.length)], executable: random() < 0.2 };
}

const timed = (path, content, executable = false) => {
  const file = { path, content, bytes: content.length, lines: content.split("\n").length, executable };
  const started = performance.now();
  let findings;
  assert.doesNotThrow(() => {
    findings = checkFile(file, { owner: "o", repo: "r" });
  }, `${path} threw`);
  assert.ok(Array.isArray(findings));
  return performance.now() - started;
};

/**
 * The exact file that took 3,972ms, written out rather than regenerated.
 *
 * The sweep found it under seed 103442, and it is spelled out here because
 * deriving it from the generator does not survive the generator changing.
 * A first version of this test did derive it, and guarded that with the
 * content's length; adding four tokens to the alphabet then changed every
 * character while leaving the length alone, because the length comes from the
 * random sequence and not from the alphabet. The case silently stopped being
 * the case, and nothing failed. Literal bytes cannot drift.
 */
const FOUR_SECOND_UNIT = "\u{200d}postinstall/\u{200d}#^<https://secrets.;$\u{1f3f4}'-o";
const FOUR_SECOND_FILE = FOUR_SECOND_UNIT.repeat(743);

test("the 30 KB file that took four seconds is fast now", () => {
  assert.equal(FOUR_SECOND_FILE.length, 29_720);
  const ms = timed(".nvim.lua", FOUR_SECOND_FILE);
  assert.ok(ms < 1_000, `the pinned case took ${ms.toFixed(0)}ms; it took 3,972ms before the fix`);
});

test("no random file of rule tokens throws or stalls", () => {
  for (const seed of [12345, 777, 4242, 99991, 31337, 103442]) {
    for (let i = 0; i < 400; i++) {
      const at = seed + i;
      const { content, path, executable } = generated(at);
      const ms = timed(path, content, executable);
      assert.ok(ms < 1_000, `seed ${at} on ${path} (${content.length} bytes) took ${ms.toFixed(0)}ms`);
    }
  }
});

test("a thousand findings become a readable report without changing the verdict", async () => {
  // A lockfile can legitimately declare hundreds of install scripts, and an
  // adversarial one can declare thousands. The report has to stay readable
  // and the response has to stay a response, but nothing may be hidden from
  // the judgement itself.
  const packages = {};
  for (let i = 0; i < 1_200; i++) {
    packages[`node_modules/p${i}`] = {
      version: "1.0.0",
      resolved: `https://registry.npmjs.org/p${i}/-/p${i}-1.0.0.tgz`,
      hasInstallScript: true,
    };
  }
  const client = makeClient({
    "package-lock.json": JSON.stringify({ lockfileVersion: 3, packages }),
    "package.json": JSON.stringify({ name: "x", version: "1.0.0" }),
  });
  const result = await scanRepo({ owner: "o", repo: "r", client });

  assert.ok(result.findings.length <= MAX_REPORTED_FINDINGS, "the listed findings are capped");
  assert.ok(result.stats.findings > MAX_REPORTED_FINDINGS, "the true count is still reported");
  // The severity tally must count every finding, not the listed ones, or the
  // report prints a total that contradicts the breakdown beside it.
  const tallied = result.stats.severities.high + result.stats.severities.medium + result.stats.severities.low;
  assert.equal(tallied, result.stats.findings, "the severity tally covers every finding");
  assert.ok(
    result.notes.some((n) => n.includes("not listed") && n.includes(String(result.stats.findings))),
    "a note has to say how many were left out and that the verdict used all of them",
  );
  // What survives the cut is the most severe, never an arbitrary slice.
  const rank = { high: 0, medium: 1, low: 2 };
  for (let i = 1; i < result.findings.length; i++) {
    assert.ok(
      rank[result.findings[i - 1].severity] <= rank[result.findings[i].severity],
      "the listed findings stay in severity order",
    );
  }
});
