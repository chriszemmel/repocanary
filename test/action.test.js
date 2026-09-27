/**
 * The composite step in action.yml, run against a stand-in CLI.
 *
 * The step's shell is extracted from the YAML and executed directly, so these
 * assertions cover the real script rather than a copy of it.
 */

import test from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { existsSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..");
const HAS_BASH = spawnSync("bash", ["-c", "exit 0"]).status === 0;

/** The `run:` script of the composite step, dedented out of action.yml. */
function stepScript() {
  const lines = readFileSync(join(ROOT, "action.yml"), "utf8").split("\n");
  const start = lines.findIndex((l) => /^\s+run: \|/.test(l));
  assert.notEqual(start, -1, "action.yml has no run block");
  const indent = lines[start].match(/^\s*/)[0].length + 2;
  const body = [];
  for (const line of lines.slice(start + 1)) {
    if (line.trim() !== "" && line.match(/^\s*/)[0].length < indent) break;
    body.push(line.slice(indent));
  }
  return body.join("\n");
}

/**
 * Run the step with a CLI that reports `verdict` and exits with `code`.
 * Returns the step's exit status and the value it wrote to GITHUB_OUTPUT.
 */
function runStep({
  verdict,
  code,
  failOn = "red",
  sarif = "",
  repository = "owner/repo",
  ref = "main",
  sarifMode = "ok",
  missingCli = false,
}) {
  const dir = mkdtempSync(join(tmpdir(), "repocanary-action-"));
  try {
    if (!missingCli) {
      writeFileSync(
        join(dir, "cli.js"),
        [
          "const sarifRun = process.argv.includes('--sarif');",
          "if (sarifRun) {",
          "  const mode = process.env.FAKE_SARIF_MODE;",
          "  if (mode === 'fail') process.exit(3);",
          "  if (mode !== 'empty') process.stdout.write('{\\'runs\\':[]}');",
          "  process.exit(0);",
          "}",
          "const code = Number(process.env.FAKE_CODE);",
          "if (process.env.FAKE_VERDICT) process.stdout.write(JSON.stringify({",
          "  verdict: process.env.FAKE_VERDICT, argv: process.argv.slice(2) }));",
          "process.exit(code);",
        ].join("\n"),
      );
    }
    const outFile = join(dir, "github_output");
    writeFileSync(outFile, "");
    const res = spawnSync("bash", ["-c", stepScript()], {
      encoding: "utf8",
      env: {
        ...process.env,
        GITHUB_OUTPUT: outFile,
        RC_ACTION_PATH: dir,
        RC_REPOSITORY: repository,
        RC_REF: ref,
        RC_CURRENT_REPOSITORY: "owner/repo",
        RC_CURRENT_SHA: "0123abc",
        RC_FAIL_ON: failOn,
        RC_SARIF_FILE: sarif ? join(dir, sarif) : "",
        FAKE_VERDICT: verdict,
        FAKE_CODE: String(code),
        FAKE_SARIF_MODE: sarifMode,
      },
    });
    const output = readFileSync(outFile, "utf8").trim();
    const sarifPath = sarif ? join(dir, sarif) : "";
    return {
      status: res.status,
      stdout: res.stdout ?? "",
      verdict: output.startsWith("verdict=") ? output.slice("verdict=".length) : "",
      sarifWritten: sarifPath ? existsSync(sarifPath) : false,
      sarifBytes: sarifPath && existsSync(sarifPath) ? readFileSync(sarifPath, "utf8").length : 0,
    };
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
}

/** Every fail-on setting against every verdict. SARIF must not change the exit status. */
const MATRIX = [
  { failOn: "red", verdict: "green", code: 0, expect: 0 },
  { failOn: "red", verdict: "yellow", code: 1, expect: 0 },
  { failOn: "red", verdict: "red", code: 2, expect: 2 },
  { failOn: "red", verdict: "error", code: 3, expect: 3 },
  { failOn: "yellow", verdict: "green", code: 0, expect: 0 },
  { failOn: "yellow", verdict: "yellow", code: 1, expect: 1 },
  { failOn: "yellow", verdict: "red", code: 2, expect: 2 },
  { failOn: "yellow", verdict: "error", code: 3, expect: 3 },
  { failOn: "never", verdict: "green", code: 0, expect: 0 },
  { failOn: "never", verdict: "yellow", code: 1, expect: 0 },
  { failOn: "never", verdict: "red", code: 2, expect: 0 },
  { failOn: "never", verdict: "error", code: 3, expect: 3 },
];

for (const row of MATRIX) {
  for (const sarif of ["", "report.sarif"]) {
    const label = sarif ? "with SARIF" : "without SARIF";
    test(`action: fail-on ${row.failOn} on ${row.verdict} exits ${row.expect} ${label}`, { skip: !HAS_BASH }, () => {
      const res = runStep({ ...row, sarif });
      assert.equal(res.status, row.expect);
    });
  }
}

test("action: the verdict output carries the scan result", { skip: !HAS_BASH }, () => {
  assert.equal(runStep({ verdict: "yellow", code: 1, failOn: "never" }).verdict, "yellow");
  assert.equal(runStep({ verdict: "green", code: 0 }).verdict, "green");
});

/** Ways a scan can fail to produce a verdict. None may pass the step. */
const FAILED_SCANS = [
  { name: "the documented could-not-check exit", code: 3, verdict: "" },
  { name: "a crash that exits like a yellow", code: 1, verdict: "" },
  { name: "a crash that exits like a red", code: 2, verdict: "" },
  { name: "a runner that cannot start node", code: 127, verdict: "" },
];

for (const scan of FAILED_SCANS) {
  for (const failOn of ["red", "yellow", "never"]) {
    test(`action: ${scan.name} fails the step under fail-on ${failOn}`, { skip: !HAS_BASH }, () => {
      const res = runStep({ ...scan, failOn });
      assert.equal(res.status, 3);
      assert.equal(res.verdict, "error");
    });
  }
}

test("action: a missing CLI fails the step rather than passing it", { skip: !HAS_BASH }, () => {
  const res = runStep({ verdict: "green", code: 0, failOn: "never", missingCli: true });
  assert.equal(res.status, 3);
});

test("action: an unrecognised fail-on value is rejected", { skip: !HAS_BASH }, () => {
  assert.equal(runStep({ verdict: "green", code: 0, failOn: "high" }).status, 1);
  assert.equal(runStep({ verdict: "green", code: 0, failOn: "Red" }).status, 1);
});

test("action: a repository value cannot break out of the shell script", { skip: !HAS_BASH }, () => {
  const marker = join(tmpdir(), `repocanary-injection-${process.pid}`);
  rmSync(marker, { force: true });
  const res = runStep({
    verdict: "green",
    code: 0,
    repository: `owner/repo"; touch ${marker}; echo "`,
  });
  assert.equal(res.status, 0);
  assert.equal(existsSync(marker), false, "the value was executed instead of passed as an argument");
  assert.match(res.stdout, /owner\/repo/);
});

/** The argv the stand-in CLI was given, from the JSON it printed. */
const argvOf = (res) => JSON.parse(res.stdout.trim().split("\n")[0]).argv;

test("action: an explicit ref is passed through", { skip: !HAS_BASH }, () => {
  const res = runStep({ verdict: "green", code: 0, repository: "other/repo", ref: "dev" });
  assert.deepEqual(argvOf(res).slice(0, 3), ["other/repo", "--ref", "dev"]);
});

test("action: without a ref, the running repository is scanned at the triggering commit", { skip: !HAS_BASH }, () => {
  const res = runStep({ verdict: "green", code: 0, repository: "owner/repo", ref: "" });
  assert.deepEqual(argvOf(res).slice(0, 3), ["owner/repo", "--ref", "0123abc"]);
});

test("action: without a ref, another repository is scanned at its default branch", { skip: !HAS_BASH }, () => {
  const res = runStep({ verdict: "green", code: 0, repository: "some-recruiter/take-home-task", ref: "" });
  assert.deepEqual(argvOf(res), ["some-recruiter/take-home-task", "--json"]);
});

test("action: a SARIF report is written when one is asked for", { skip: !HAS_BASH }, () => {
  const res = runStep({ verdict: "red", code: 2, failOn: "never", sarif: "report.sarif" });
  assert.equal(res.status, 0);
  assert.equal(res.sarifWritten, true);
  assert.ok(res.sarifBytes > 0);
});

test("action: a SARIF report that cannot be produced fails the step", { skip: !HAS_BASH }, () => {
  for (const sarifMode of ["fail", "empty"]) {
    const res = runStep({ verdict: "green", code: 0, failOn: "never", sarif: "report.sarif", sarifMode });
    assert.equal(res.status, 3, sarifMode);
    assert.equal(res.sarifBytes, 0, sarifMode);
  }
});

test("INVARIANT: action.yml passes inputs by environment, never by interpolation", { skip: !HAS_BASH }, () => {
  assert.doesNotMatch(stepScript(), /\$\{\{/);
});
