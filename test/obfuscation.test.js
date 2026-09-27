import "./helpers.js";
import test from "node:test";
import assert from "node:assert/strict";
import { checkObfuscation, findInvisibleCharacter, shannonEntropy } from "../src/obfuscation.js";

function run(content, path = "src/app.js") {
  return checkObfuscation(path, content, { bytes: content.length, lines: content.split("\n").length });
}

test("REGRESSION: a soft hyphen after a letter is hyphenation, not hiding", () => {
  // linebender/parley wrote "not in\u00ADteresting" across a line wrap and
  // turned red. A soft hyphen follows a letter and stays invisible until a
  // line breaks there; no language accepts it in an identifier, so in code it
  // lives only in comments and strings, where it is typography.
  const at = (c) => checkObfuscation("f.rs", c, { bytes: c.length, lines: c.split("\n").length }).filter((f) => f.id === "invisible-characters");
  // Mid-word, and the real parley shape with the soft hyphen before a newline.
  assert.equal(at("// weight aliases are not in\u00ADteresting here").length, 0);
  assert.equal(at("// are not in\u00AD\nteresting for other cases").length, 0);

  // The zero-width space in the same spot is the real carrier and still fires.
  assert.equal(at("const ad\u200Bmin = 1;")[0]?.severity, "high");
  // A soft hyphen that does not follow a letter is not hyphenation; kept.
  assert.equal(at("x = \u00AD1")[0]?.severity, "high");
});

test("REGRESSION: a table of the characters is not an attack with them", () => {
  // Cranot/roam-code strips dangerous Unicode for a living and lists all nine
  // controls, one per line with a comment naming each. The existing window
  // test could not see it: a comment on every entry pushes the next control
  // character well past the twelve columns it looks at. A control character
  // alone inside its own quotes reorders nothing, which is what an entry in a
  // table looks like and what an attack never does.
  const C = (h) => String.fromCharCode(parseInt(h, 16));
  const table = [
    ["202a", "LTR embedding"], ["202b", "RTL embedding"], ["202c", "pop directional"],
    ["202d", "LTR override"], ["202e", "RTL override"],
  ]
    .map(([h, name]) => `        "${C(h)}",  # ${name}`)
    .join("\n");
  const at = (out) => out.filter((f) => f.id === "bidi-override");
  assert.equal(at(checkObfuscation("src/strip.py", table, { bytes: table.length, lines: 5 })).length, 0);

  // The same character doing its job inside real text still convicts.
  const attack = `const isAdmin = false; // ${C("202e")} }${C("202c")} if (isAdmin) { grant();`;
  assert.equal(at(checkObfuscation("src/auth.js", attack, { bytes: attack.length, lines: 1 }))[0]?.severity, "high");

  // And a lone override in prose, not quoted, is still the trojan shape.
  const bare = `rename the file to safe${C("202e")}gnp.txt.exe before shipping`;
  assert.equal(at(checkObfuscation("src/x.js", bare, { bytes: bare.length, lines: 1 })).length, 1);
});

test("shannonEntropy behaves at the extremes", () => {
  assert.equal(shannonEntropy(""), 0);
  assert.equal(shannonEntropy("aaaa"), 0);
  assert.ok(shannonEntropy("abcdefgh") > 2.9);
});

test("a zero-width character in code fires high", () => {
  const findings = run('const admin​ = false;\nconst admin = true;\n');
  assert.equal(findings[0].id, "invisible-characters");
  assert.equal(findings[0].severity, "high");
  assert.equal(findings[0].line, 1);
});

test("INVARIANT: a file at the per-file cap scans in reasonable time", async () => {
  // A single 1 MB line is what a minified or obfuscated payload looks like,
  // and the selector fetches those on purpose.
  const { checkFile } = await import("../src/heuristics.js");
  const content = "a".repeat(1_000_000);
  const started = Date.now();
  checkFile({ path: "src/bundle.js", content, bytes: content.length, lines: 1 });
  assert.ok(Date.now() - started < 5_000, "no rule may scale worse than linearly with file size");
});

/** Hosts whose rules use a subdomain wildcard, which must still match. */
const WILDCARD_HOSTS = [
  { name: "trycloudflare", content: 'fetch("https://abc-def.trycloudflare.com/x")', id: "tunneling-infra" },
  { name: "serveo", content: 'fetch("http://tun.serveo.net/p")', id: "tunneling-infra" },
  { name: "pipedream", content: 'fetch("https://eo123.pipedream.net/hook")', id: "exfil-sink" },
  { name: "vercel c2 path", content: 'fetch("https://drop-xyz.vercel.app/api/ipcheck")', id: "throwaway-host-c2" },
];

for (const { name, content, id } of WILDCARD_HOSTS) {
  test(`wildcard host rules still fire: ${name}`, async () => {
    const { checkFile } = await import("../src/heuristics.js");
    const findings = checkFile({ path: "src/a.js", content, bytes: content.length, lines: 1 });
    assert.ok(findings.some((f) => f.id === id), findings.map((f) => f.id).join(","));
  });
}

/** Code points that are ordinary typography, not concealment. */
const LEGITIMATE_INVISIBLES = [
  { name: "an emoji ZWJ sequence", content: 'const flag = "\u{1F468}\u200D\u{1F4BB}";\n' },
  { name: "Arabic text using ZWNJ", content: 'const label = "\u0645\u06CC\u200C\u062E\u0648\u0627\u0647\u0645";\n' },
  { name: "Persian text using ZWNJ", content: 'const t = { greeting: "\u062F\u0648\u0633\u062A\u200C\u062F\u0627\u0631\u0645" };\n' },
  { name: "a Devanagari string using ZWNJ", content: 'const s = "\u0915\u094D\u200C\u0937";\n' },
];

for (const { name, content } of LEGITIMATE_INVISIBLES) {
  test(`invisible characters: ${name} does not fire`, () => {
    assert.equal(findInvisibleCharacter(content), -1);
    assert.deepEqual(run(content), []);
  });
}

test("invisible characters: a zero-width space inside an ASCII identifier fires", () => {
  assert.ok(findInvisibleCharacter('const isAdmin\u200B = false;\n') > 0);
});

test("a leading BOM alone does not fire", () => {
  assert.equal(findInvisibleCharacter('﻿const x = 1;\n'), -1);
  assert.deepEqual(run('﻿const x = 1;\n'), []);
});

test("a BOM in the middle of the file fires", () => {
  assert.ok(findInvisibleCharacter('const x = 1;﻿const y = 2;') > 0);
});

test("a homoglyph URL fires high", () => {
  // Cyrillic small a (U+0430) inside a Latin hostname.
  const findings = run('fetch("https://pаypal.com/login");\n');
  assert.equal(findings[0].id, "homoglyph-url");
  assert.equal(findings[0].severity, "high");
});

test("a mixed-script identifier fires low", () => {
  const findings = run('const pаssword = getSecret();\n');
  assert.equal(findings[0].id, "homoglyph-identifier");
  assert.equal(findings[0].severity, "low");
});

test("a fully non-Latin comment does not fire", () => {
  assert.deepEqual(run('// проверка кода\nconst x = 1;\n'), []);
});

test("a high-entropy literal fires low; plain prose does not", () => {
  // Base64 of varied bytes, with punctuation mixed in so the more specific
  // pure-base64 rule does not claim it first.
  const bytes = Buffer.from(Array.from({ length: 240 }, (_, i) => (i * 97 + 13) % 256));
  const noisy = bytes.toString("base64").match(/.{1,10}/g).join("!*");
  const findings = run(`const key = "${noisy}";\n`);
  assert.equal(findings[0].id, "high-entropy-literal");
  assert.equal(findings[0].severity, "low");

  const prose = `const msg = "${"this is a perfectly ordinary sentence about widgets ".repeat(4)}";\n`;
  assert.deepEqual(run(prose), []);
});

test("a file that is mostly encoded blobs fires medium", () => {
  const blob = Buffer.from("payload".repeat(400)).toString("base64");
  const content = `const data = "${blob}";\nconst more = "${blob}";\n`;
  const findings = run(content);
  assert.ok(findings.some((f) => f.id === "encoded-blob-density"));
});

test("a giant single-line file is noted, not cautioned (the decode and eval rules judge what it does)", () => {
  const content = `var x=1;${"f();".repeat(3000)}`;
  const findings = run(content);
  assert.ok(findings.some((f) => f.id === "single-line-blob" && f.severity === "low"));
});

test("ordinary multi-line source fires nothing", () => {
  const content = Array.from({ length: 200 }, (_, i) => `function fn${i}() { return ${i}; }`).join("\n");
  assert.deepEqual(run(content), []);
});

test("bidirectional override characters fire high (Trojan Source)", () => {
  const findings = run('const x = "user‮/* ‭admin */";\n');
  assert.ok(findings.some((f) => f.id === "bidi-override" && f.severity === "high"));
});

test("a run of Private Use Area characters fires high (steganography)", () => {
  const findings = run('const m = "";\n');
  assert.ok(findings.some((f) => f.id === "private-use-steganography" && f.severity === "high"));
});

test("a single stray private-use character does not fire", () => {
  assert.deepEqual(run('const icon = "";\n'), []);
});

test("a line of markup is not a packed payload", () => {
  // The 4-bits-per-character figure for English holds for lowercase letters
  // and spaces. Text with mixed case, digits, punctuation and markup in it
  // spreads over seventy-odd distinct characters and measures 5.0 to 5.1,
  // which is over the line. This exact line is from borg's paperkey page,
  // where it says where the QR code goes; prisma's roadmap page and a Prisma
  // error message built from a template literal earned the finding the same
  // way.
  const markup =
    '<text style="font-size:10px;fill:#ddd;stroke:none;stroke-width:1px;" x="47.321415" y="99.851288">QR Code goes here</text>';
  assert.ok(markup.length > 120, "the line has to be long enough to reach the rule");
  assert.deepEqual(run(`const svg = \`${markup}\`;\n`), []);

  // Padding a payload with whitespace buys nothing, because the rule reads
  // the longest unbroken run and not the literal around it: a real packed
  // blob is still a run of 120 characters however much text sits beside it.
  const bytes = Buffer.from(Array.from({ length: 240 }, (_, i) => (i * 97 + 13) % 256));
  const noisy = bytes.toString("base64").match(/.{1,10}/g).join("!*");
  const padded = run(`const key = "the QR code goes here ${noisy} and here it ends";\n`);
  assert.equal(padded.some((f) => f.id === "high-entropy-literal"), true);
});

test("encoded data that says what it is does not count toward blob density", () => {
  const density = (path, c) => run(c, path).find((f) => f.id === "encoded-blob-density");
  const b64 = (bytes) => Buffer.from(bytes).toString("base64");
  const noise = (n, seed) => Array.from({ length: n }, (_, i) => (i * 131 + seed * 197 + ((i * seed) % 7) * 53) % 256);
  // A TrueType font exported as a module, a WebP split across concatenated
  // literals, a JSON test fixture, a PEM certificate and a zero-filled map.
  const font = `export default Buffer.from('${b64([0, 1, 0, 0, ...noise(6000, 1)])}', 'base64');\n`;
  assert.equal(density("lib/fonts/inter.ts", font), undefined);
  const webp = b64([0x52, 0x49, 0x46, 0x46, ...noise(6000, 2)]);
  const split = `export const BG = 'data:image/webp;base64,' +\n  '${webp.slice(0, 4000)}' +\n  '${webp.slice(4000)}';\n`;
  assert.equal(density("src/bg.js", split), undefined);
  const json = `const body = "${b64(JSON.stringify({ spec: noise(3000, 3) }))}";\n`;
  assert.equal(density("server_test.go", json), undefined);
  const zeros = `const grid = [\n${Array.from({ length: 40 }, () => `  '${"0".repeat(200)}',`).join("\n")}\n];\n`;
  assert.equal(density("src/data/map.js", zeros), undefined);
  // The same bytes with no header saying what they are keep their caution.
  const bare = `module.exports = '${b64(noise(6000, 4))}';\n`;
  assert.equal(density("src/sprites.js", bare)?.severity, "medium");
});

test("a joined file's byte-order mark and a zero-width space ending a sentence hide nothing", () => {
  assert.equal(findInvisibleCharacter("  return x;\n}\n﻿function build(multi) {\n"), -1);
  assert.equal(findInvisibleCharacter("<p>the bank's digital-first strategy​. </p>\n"), -1);
  // The identifier split still fires, at a word's end or inside it.
  assert.ok(findInvisibleCharacter("const isAdmin​ = true;\n") > 0);
  assert.ok(findInvisibleCharacter('if (role === "adm​in") grant();\n') > 0);
});
