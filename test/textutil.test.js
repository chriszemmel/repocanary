import "./helpers.js";
import test from "node:test";
import assert from "node:assert/strict";
import { lineOfIndex, matchLocation, redactSnippet, safeJsonParse, wrapText } from "../src/textutil.js";

test("redactSnippet shortens long base64 runs so payloads never round-trip", () => {
  const blob = "A".repeat(400);
  const out = redactSnippet(`prefix ${blob} suffix`);
  assert.ok(out.includes("[400 chars redacted]"));
  assert.ok(!out.includes("A".repeat(100)));
});

test("redactSnippet collapses whitespace and strips control characters", () => {
  assert.equal(redactSnippet("a\x07b\n\n   c\t\td"), "a b c d");
});

test("redactSnippet caps length", () => {
  assert.ok(redactSnippet("word ".repeat(200)).length <= 200);
});

test("safeJsonParse never throws", () => {
  assert.deepEqual(safeJsonParse('{"a":1}'), { ok: true, value: { a: 1 } });
  assert.equal(safeJsonParse("not json {").ok, false);
  assert.equal(safeJsonParse("").ok, false);
});

test("lineOfIndex is 1-based", () => {
  const s = "one\ntwo\nthree";
  assert.equal(lineOfIndex(s, 0), 1);
  assert.equal(lineOfIndex(s, 4), 2);
  assert.equal(lineOfIndex(s, s.indexOf("three")), 3);
});

test("wrapText respects width and indent", () => {
  const wrapped = wrapText("aaa bbb ccc ddd eee", 11, "  ");
  for (const line of wrapped.split("\n")) {
    assert.ok(line.length <= 11);
    assert.ok(line.startsWith("  "));
  }
});

test("REGRESSION: a word longer than the width is broken, not overhung", () => {
  // Prose has no unbreakable words, but a snippet is a line lifted out of the
  // scanned repository, and a URL or a run of minified code carries no space
  // to break at. Found on real repositories: gohugoio/hugo printed a 90-column
  // line from a dart-sass release URL under a report announcing 78.
  const url = "https://github.com/sass/dart-sass/releases/download/${DART_SASS_VERSION}/dart-sass-x-linux.tar.gz";
  const wrapped = wrapText(`fetches ${url} during the build`, 78, "     > ");
  for (const line of wrapped.split("\n")) {
    assert.ok(line.length <= 78, `line over 78 columns: ${JSON.stringify(line)}`);
    assert.ok(line.startsWith("     > "));
  }
  // Broken, not dropped: every character of the long token still appears.
  assert.equal(wrapped.split("\n").map((l) => l.slice(7)).join("").replace(/ /g, ""), `fetches${url}duringthebuild`);

  // A degenerate width must terminate rather than loop.
  assert.ok(wrapText("xxxxxxxx", 3, "      ").split("\n").every((l) => l.length <= 7));
});

test("a snippet reveals a deceptive character instead of performing it", () => {
  // The rules that find these exist because the characters change what the
  // reader sees. Quoting one back into a terminal reproduces the deception
  // inside the warning about it, so the report writes the code point out.
  const rtl = String.fromCharCode(0x202e);
  const zwsp = String.fromCharCode(0x200b);
  const tag = String.fromCodePoint(0xe0041);

  const bidi = redactSnippet(`open("safe${rtl}gnp.txt.exe")`);
  assert.ok(!bidi.includes(rtl), "no bidi override may survive into a snippet");
  assert.ok(bidi.includes("<U+202E>"), "the override is named where it stood");

  const invisible = redactSnippet(`isAdmin${zwsp} = true`);
  assert.ok(!invisible.includes(zwsp));
  assert.ok(invisible.includes("<U+200B>"));

  const smuggled = redactSnippet(`x${tag}y`);
  assert.ok(!smuggled.includes(tag), "tag characters are the whole smuggling channel");
  assert.ok(smuggled.includes("<U+E0041>"));

  // Ordinary text is untouched, including non-ASCII that means what it says.
  assert.equal(redactSnippet("const grüße = 'héllo'; // 日本語"), "const grüße = 'héllo'; // 日本語");
});

test("an excerpt starts at its line or a word, never mid-token", () => {
  const tasks = '{\n  "tasks": [{ "command": "node x.js", "runOptions": {\n        "runOn": "folderOpen" } }]\n}';
  assert.equal(matchLocation(tasks, /"runOn":\s*"folderOpen"/).snippet, '"runOn": "folderOpen" } }] }');
  const long = `${"word ".repeat(30)}eval(payload) and then some more words after it`;
  const { snippet } = matchLocation(long, /eval\(/);
  assert.match(snippet, /^word /);
  assert.ok(snippet.includes("eval(payload)"));
});
