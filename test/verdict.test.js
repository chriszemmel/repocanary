import "./helpers.js";
import test from "node:test";
import assert from "node:assert/strict";
import { applyAiVerdict, decideVerdict, EXIT_CODES, GREEN_MEANING, sortFindings } from "../src/verdict.js";

const f = (severity, extra = {}) => ({ id: "x", severity, file: "a.js", line: 1, snippet: "", why: "", next: "", ...extra });

test("three low findings of one rule stay green; three different low rules make yellow", () => {
  assert.equal(decideVerdict([f("low"), f("low"), f("low")]), "green");
  assert.equal(decideVerdict([f("low", { id: "a" }), f("low", { id: "b" }), f("low", { id: "c" })]), "yellow");
});

test("a plain lifecycle script and a declared dependency's install script are one weak signal", () => {
  // MikroTik3/enkod_api: "postinstall": "prisma generate", the Prisma
  // engines' install script in the lockfile, and a generated WebAssembly
  // blob under prisma/generated/ made three lows, and an ordinary NestJS
  // application was yellow for being one.
  const lifecycle = f("low", { id: "lifecycle-script" });
  const transitive = f("low", { id: "transitive-install-script" });
  const vendored = f("low", { id: "base64-blob", vendored: true });
  assert.equal(decideVerdict([lifecycle, transitive, vendored]), "green");
  // With a third observation that is not about install scripts, three
  // different weak signals still corroborate each other.
  assert.equal(decideVerdict([lifecycle, transitive, vendored, f("low", { id: "typosquat-dependency" })]), "yellow");
  // A Composer hook is the same observation in another ecosystem.
  const composer = f("low", { id: "composer-install-script" });
  assert.equal(decideVerdict([lifecycle, composer, vendored]), "green");
  // And lifecycle-script still corroborates everything else on its own.
  assert.equal(decideVerdict([lifecycle, f("low", { id: "a" }), f("low", { id: "b" })]), "yellow");
});

test("no findings is green", () => {
  assert.equal(decideVerdict([]), "green");
});

test("one high finding is red", () => {
  assert.equal(decideVerdict([f("high")]), "red");
});

test("one medium finding is yellow", () => {
  assert.equal(decideVerdict([f("medium")]), "yellow");
});

test("two lows stay green, three different lows turn yellow", () => {
  assert.equal(decideVerdict([f("low", { id: "a" }), f("low", { id: "b" })]), "green");
  assert.equal(decideVerdict([f("low", { id: "a" }), f("low", { id: "b" }), f("low", { id: "c" })]), "yellow");
});

test("INVARIANT: the AI pass can never lower a red", () => {
  assert.equal(applyAiVerdict("red", "green"), "red");
  assert.equal(applyAiVerdict("red", "yellow"), "red");
  assert.equal(applyAiVerdict("red", "red"), "red");
});

test("the AI pass may clear a yellow and raise a green to yellow", () => {
  assert.equal(applyAiVerdict("yellow", "green"), "green");
  assert.equal(applyAiVerdict("green", "yellow"), "yellow");
  assert.equal(applyAiVerdict("yellow", "yellow"), "yellow");
});

test("INVARIANT: the AI pass can never produce a red; red means a signature fired", () => {
  assert.equal(applyAiVerdict("yellow", "red"), "yellow");
  assert.equal(applyAiVerdict("green", "red"), "yellow");
});

test("garbage AI verdicts leave the static verdict untouched", () => {
  assert.equal(applyAiVerdict("yellow", "safe"), "yellow");
  assert.equal(applyAiVerdict("green", undefined), "green");
  assert.equal(applyAiVerdict("green", "__proto__"), "green");
});

test("INVARIANT: exit codes are 0 green, 1 yellow, 2 red, 3 error", () => {
  assert.deepEqual(EXIT_CODES, { green: 0, yellow: 1, red: 2, error: 3 });
});

test("INVARIANT: green is defined as exactly 'nothing known matched'", () => {
  assert.equal(GREEN_MEANING, "nothing known matched");
});

test("sortFindings is deterministic and severity-first", () => {
  const input = [
    f("low", { id: "b", file: "z.js" }),
    f("high", { id: "a", file: "m.js", line: 9 }),
    f("medium", { id: "c", file: "a.js" }),
    f("high", { id: "a", file: "m.js", line: 2 }),
  ];
  const sorted = sortFindings(input);
  assert.deepEqual(
    sorted.map((x) => [x.severity, x.file, x.line]),
    [
      ["high", "m.js", 2],
      ["high", "m.js", 9],
      ["medium", "a.js", 1],
      ["low", "z.js", 1],
    ],
  );
  // Sorting again changes nothing and the input is not mutated.
  assert.deepEqual(sortFindings(sorted), sorted);
  assert.equal(input[0].id, "b");
});

test("three low findings in a test path are one observation, not three", () => {
  // The test-path downgrade already says a finding there "cannot be the sole
  // evidence of danger". Three of them are one observation about the test
  // suite: babel-generator's minified printer fixture trips the entropy rule
  // and the download rule in the same file, and ripgrep's test helpers name a
  // homoglyph and a sandbox check in two more.
  const low = (id, file) => ({ id, severity: "low", file, line: 1 });
  const inTests = [
    { ...low("high-entropy-literal", "test/fixtures/big/input.js"), testPath: true },
    { ...low("download-and-execute", "test/fixtures/big/input.js"), testPath: true },
    { ...low("homoglyph-identifier", "tests/regression.rs"), testPath: true },
  ];
  assert.equal(decideVerdict(inTests), "green");

  // The same three in the source tree still corroborate. Only the tag moves
  // the verdict, so this is the collapse doing the work and not the low rule
  // quietly going soft. (Two tagged plus one untagged is two observations and
  // green by the same arithmetic, which is the point of the tag.)
  const inSrc = [
    low("high-entropy-literal", "src/big.js"),
    low("download-and-execute", "src/update.js"),
    low("homoglyph-identifier", "src/parse.rs"),
  ];
  assert.equal(decideVerdict(inSrc), "yellow");

  // A file an install script or an editor hook names is not tagged, because
  // the downgrade that sets the tag is guarded on !executable, so a payload
  // moved into examples/ and wired to a postinstall collapses nothing.
  assert.equal(decideVerdict(inTests.map((f) => ({ ...f, testPath: undefined }))), "yellow");
});

test("maintainer scripts nothing runs are one observation, however many there are", () => {
  const tool = (id, file) => ({ id, severity: "low", file, manualTool: true });
  const findings = [
    tool("download-and-execute", "scripts/release.js"),
    tool("startup-persistence", "deploy/install.sh"),
    tool("base64-blob", "tools/pack.py"),
  ];
  assert.equal(decideVerdict(findings), "green");
  assert.equal(decideVerdict([...findings, { id: "exfil-sink", severity: "low", file: "src/a.js" }, { id: "odd-dependency-mix", severity: "low", file: "package.json" }]), "yellow");
});
