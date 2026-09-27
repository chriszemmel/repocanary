#!/usr/bin/env node
/**
 * RepoCanary CLI.
 *
 * Usage: repocanary <owner/repo | github url> [options]
 *
 * Exit codes are the contract: 0 green, 1 yellow, 2 red, 3 the scan could
 * not complete. A failed scan never exits 0.
 */

import { realpathSync } from "node:fs";
import { createInterface } from "node:readline";
import { fileURLToPath } from "node:url";
import { createGitHubClient, GitHubError, parseGitHubUrl } from "./src/github.js";
import { scanRepo } from "./src/scan.js";
import { renderHuman, renderJson, renderJsonError, renderSarif, renderSarifError, toolVersion } from "./src/report.js";
import { PROVIDERS, configuredProviders, providerFromKey, runAiPass } from "./src/ai.js";
import { EXIT_CODES } from "./src/verdict.js";
import { wrapText } from "./src/textutil.js";

const HELP = `repocanary: check a GitHub repo for known malware-trap signatures
without downloading or running any of its code.

Usage:
  repocanary <owner/repo | github.com URL> [options]

Options:
  --json         print a versioned JSON report instead of text
  --sarif        print a SARIF 2.1.0 report (for GitHub code scanning)
  --ref <name>   scan a branch, tag, or commit (default: the default branch)
  --ai           opt in to an AI second-opinion pass; it can raise a green to
                 yellow or clear a yellow, never lower or produce a red. With
                 no provider key set, it offers to take one you paste (input
                 stays hidden)
  --ai-provider <name>
                 force one provider: gemini, groq, openai, or anthropic
  -h, --help     show this help
  -v, --version  show the version

Environment:
  GITHUB_TOKEN       a scan makes up to 175 API requests and GitHub allows
                     60 an hour without a token, so set one: any token
                     with public repository read access. It also allows
                     scanning private repos the token can read

  An --ai pass uses your own key from whichever of these is set. Gemini is
  tried first, then Groq, then OpenAI, then Anthropic. Each provider takes
  an optional model override in the second variable.
    GEMINI_API_KEY      GEMINI_MODEL      (default gemini-3.5-flash-lite)
    GROQ_API_KEY        GROQ_MODEL        (default openai/gpt-oss-120b)
    OPENAI_API_KEY      OPENAI_MODEL      (default gpt-5.4-mini)
    ANTHROPIC_API_KEY   ANTHROPIC_MODEL   (default claude-opus-5)

Exit codes:
  0  green   nothing known matched (this is not proof of safety)
  1  yellow  suspicious signals; have someone review before running
  2  red     known malware signatures matched; do not run the repository
  3  error   the scan could not complete
`;

export function parseArgs(argv) {
  const opts = {
    target: null,
    json: false,
    sarif: false,
    ai: false,
    aiProvider: null,
    ref: null,
    help: false,
    version: false,
  };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === "--json") opts.json = true;
    else if (a === "--sarif") opts.sarif = true;
    else if (a === "--ai") opts.ai = true;
    else if (a === "--ai-provider") {
      const name = argv[++i] ?? "";
      if (!Object.prototype.hasOwnProperty.call(PROVIDERS, name)) {
        throw new Error(
          `Unknown AI provider: ${name || "(missing)"}. Choose one of: ${Object.keys(PROVIDERS).join(", ")}.`,
        );
      }
      opts.aiProvider = name;
      opts.ai = true;
    } else if (a === "--ref") {
      const ref = argv[++i];
      if (ref === undefined || ref.startsWith("-")) {
        throw new Error(`--ref needs a branch, tag, or commit${ref ? `, got: ${ref}` : ""}.`);
      }
      opts.ref = ref;
    } else if (a === "-h" || a === "--help") opts.help = true;
    else if (a === "-v" || a === "--version") opts.version = true;
    else if (a.startsWith("-")) throw new Error(`Unknown option: ${a}. Run repocanary --help for usage.`);
    else if (opts.target === null) opts.target = a;
    else throw new Error(`Unexpected extra argument: ${a}. Run repocanary --help for usage.`);
  }
  return opts;
}

/**
 * Read an API key typed or pasted at the terminal without echoing it, so the
 * key never appears on screen or in the terminal scrollback. Resolves null
 * when stdin is not a terminal (a pipe, CI) or the user submits nothing.
 *
 * A key is deliberately never accepted as a command-line flag: arguments are
 * saved in shell history and are visible to every other process on the
 * machine through the process list.
 */
export function promptForApiKey({
  stdin = process.stdin,
  stdout = process.stdout,
  stderr = process.stderr,
} = {}) {
  // The prompt goes to stderr, so --json and --sarif stay machine readable
  // even when the user is at a terminal. Both streams must be a terminal, or
  // the prompt would be drawn where nobody is reading it.
  if (!stdin.isTTY || !stderr.isTTY) return Promise.resolve(null);
  return new Promise((resolve) => {
    const rl = createInterface({ input: stdin, output: stderr, terminal: true });
    let settled = false;
    const done = (value) => {
      if (settled) return;
      settled = true;
      rl.close();
      stderr.write("\n");
      resolve(value);
    };
    // Ctrl-D closes the stream without an answer; without this the promise
    // never settles and the CLI hangs after the scan has already finished.
    rl.on("close", () => done(null));
    // readline echoes each keystroke through _writeToOutput. Let the prompt
    // itself through, then swallow everything after it so the key stays
    // hidden while it is being typed or pasted.
    let promptWritten = false;
    rl._writeToOutput = (chunk) => {
      if (!promptWritten) {
        stderr.write(chunk);
        promptWritten = true;
      }
    };
    rl.question("Paste an AI provider API key (hidden, Enter to skip): ", (answer) => {
      // A multi-line paste would otherwise be silently truncated to its first
      // line, and the user would be told the key shape is unrecognised.
      done(String(answer).replace(/\s+/g, "") || null);
    });
  });
}

/**
 * Resolve which provider and key the AI pass should use. Returns an env-like
 * object plus a note explaining anything the user needs to know. The pasted
 * key is held in memory for this run only: writing it to disk would turn a
 * tool people run once into a place secrets accumulate.
 */
async function resolveAiKey(env, forcedProvider, { stdin, stdout, stderr }) {
  if (configuredProviders(env, forcedProvider).length > 0) return { env, note: null };

  const pasted = await promptForApiKey({ stdin, stdout, stderr });
  if (!pasted) {
    const names = Object.values(PROVIDERS)
      .map((p) => p.envKey)
      .join(", ");
    return {
      env,
      note: `AI pass skipped: no provider key. Set one of ${names}, or run --ai again and paste a key. The static verdict stands.`,
    };
  }

  const detected = forcedProvider ?? providerFromKey(pasted);
  if (!detected) {
    return {
      env,
      note: "AI pass skipped: could not tell which provider that key belongs to. Re-run with --ai-provider to say which one. The static verdict stands.",
    };
  }

  const spec = PROVIDERS[detected];
  return {
    env: { ...env, [spec.envKey]: pasted },
    note: `Using the pasted ${spec.label} key for this run only. Set ${spec.envKey} in your environment to skip this prompt next time.`,
  };
}

/**
 * Run the CLI. Dependencies are injectable so tests can drive the whole
 * program with a fixture client and captured output, offline.
 */
export async function main(
  argv,
  // aiFetch is injectable for the same reason client is: without it the
  // branch that swaps the verdict after an AI pass could not be tested at
  // all, and that is the highest-consequence branch in this file.
  {
    client,
    stdin = process.stdin,
    stdout = process.stdout,
    stderr = process.stderr,
    env = process.env,
    aiFetch = fetch,
  } = {},
) {
  let opts;
  try {
    opts = parseArgs(argv);
  } catch (err) {
    stderr.write(`${err.message}\n`);
    return EXIT_CODES.error;
  }

  if (opts.help) {
    stdout.write(HELP);
    return 0;
  }
  // No target is a usage error: a line on stderr, not the whole help on
  // stdout, where a --json consumer would try to parse it.
  if (!opts.target && !opts.version) {
    stderr.write("Usage: repocanary <owner/repo | github.com URL> [options]. Run repocanary --help for more.\n");
    return EXIT_CODES.error;
  }
  if (opts.version) {
    stdout.write(`repocanary ${toolVersion()}\n`);
    return 0;
  }
  if (opts.json && opts.sarif) {
    stderr.write("Choose either --json or --sarif, not both.\n");
    return EXIT_CODES.error;
  }

  const parsed = parseGitHubUrl(opts.target);
  if (!parsed) {
    stderr.write(
      `${wrapText(`"${opts.target}" does not look like a GitHub repository. Expected owner/repo or https://github.com/owner/repo. Run repocanary --help for usage.`, 78)}\n`,
    );
    return EXIT_CODES.error;
  }

  // A link copied from a branch page names the branch, and scanning the
  // default branch instead without a word would answer a different question.
  const branchInUrl = !opts.ref && /github\.com\/[^/]+\/[^/]+\/(tree|blob|commit)\//i.test(opts.target);
  if (branchInUrl) {
    stderr.write(
      `${wrapText("Note: the branch or commit in that link is not used. Scanning the default branch; pass --ref <name> to scan another.", 78)}\n`,
    );
  }

  // allowPrivate: on the command line the token and the person holding it
  // are the same, so a private repository they can read is theirs to scan.
  const ghClient = client ?? createGitHubClient({ token: env.GITHUB_TOKEN, allowPrivate: true });

  let result;
  try {
    result = await scanRepo({ owner: parsed.owner, repo: parsed.repo, ref: opts.ref, client: ghClient });
  } catch (err) {
    const message = err instanceof GitHubError ? err.message : `The scan failed unexpectedly: ${err.message}`;
    const where = { owner: parsed.owner, repo: parsed.repo, ref: opts.ref };
    const kind = err instanceof GitHubError ? err.kind : "internal";
    if (opts.json) stdout.write(renderJsonError(where, kind, message));
    else if (opts.sarif) stdout.write(renderSarifError(where, kind, message));
    stderr.write(`${wrapText(`Could not check ${parsed.owner}/${parsed.repo}. ${message}`, 78)}\n`);
    stderr.write("Exit code 3: the scan did not complete, so no verdict was reached.\n");
    return EXIT_CODES.error;
  }

  // Optional AI second opinion. It can raise a green to yellow or clear a yellow;
  // the red floor is enforced inside runAiPass via applyAiVerdict.
  const notes = [];
  if (opts.ai) {
    const resolved = await resolveAiKey(env, opts.aiProvider, { stdin, stdout, stderr });
    if (resolved.note) notes.push(resolved.note);

    if (configuredProviders(resolved.env, opts.aiProvider).length > 0) {
      const issues = [];
      const ai = await runAiPass(result, { env: resolved.env, provider: opts.aiProvider, issues, fetchImpl: aiFetch });

      // A safety classifier declining is worth saying out loud: analyzing
      // malware signatures is exactly the kind of request one may decline,
      // and silence would read as agreement.
      for (const issue of issues.filter((i) => i.kind === "refusal")) {
        notes.push(
          `${PROVIDERS[issue.provider].label} (${issue.model}) declined to judge these findings on safety grounds (${issue.detail}). That is a provider policy decision, not a verdict. The static rules are unaffected.`,
        );
      }

      if (ai) {
        // Name the model, not just the vendor. A second opinion is worth
        // what its author is worth, the model is configurable, and the
        // defaults move between releases, so the report has to say which
        // one actually answered.
        const label = `${PROVIDERS[ai.provider].label}, ${ai.model}`;
        if (ai.verdict !== result.verdict) {
          notes.push(
            `AI pass (${label}) ${ai.verdict === "green" ? "cleared" : "raised"} the static ${result.verdict} verdict to ${ai.verdict}. ${ai.assessment} This is one model's reading of the flagged files and can differ between runs.`,
          );
          // The report words a green that carries findings as an AI clear
          // only when one actually happened, so it is recorded here rather
          // than guessed from the shape of the result.
          result = { ...result, verdict: ai.verdict, aiCleared: ai.verdict === "green" };
        } else {
          notes.push(`AI pass (${label}) agreed with the static verdict. ${ai.assessment}`);
        }
      } else {
        notes.push("AI pass failed on every configured provider; the static verdict stands.");
      }
    }
    result = { ...result, notes: [...result.notes, ...notes] };
  }

  if (opts.json) stdout.write(renderJson(result));
  else if (opts.sarif) stdout.write(renderSarif(result));
  else stdout.write(renderHuman(result));

  return EXIT_CODES[result.verdict];
}

/**
 * True when this file is the program node was asked to run, not a module a
 * test imported. Compared as resolved paths: the npm bin shim is a symlink
 * (or a .cmd on Windows), and a URL built by hand from argv[1] never matched
 * a path with a space or a backslash in it, so the CLI exited 0 unscanned.
 */
function invokedAsProgram() {
  if (!process.argv[1]) return false;
  try {
    return realpathSync(process.argv[1]) === realpathSync(fileURLToPath(import.meta.url));
  } catch {
    return false;
  }
}

if (invokedAsProgram()) {
  // A reader that closes the pipe early (`| head`) is not a failure of the
  // scan, and crashing on it replaced the verdict's exit code with 1, which
  // reads as yellow.
  process.stdout.on("error", (err) => {
    if (err.code !== "EPIPE") throw err;
  });
  main(process.argv.slice(2)).then(
    (code) => {
      process.exitCode = code;
    },
    (err) => {
      process.stderr.write(`Unexpected failure: ${err?.stack ?? err}\n`);
      process.exitCode = EXIT_CODES.error;
    },
  );
}
