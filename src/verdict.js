/**
 * Verdict scoring. Static rules decide the verdict; nothing else does.
 *
 * The rules are deliberately simple enough to state in one sentence each:
 *   - any high-severity finding makes the verdict red
 *   - any medium finding, or three or more low findings, makes it yellow
 *   - otherwise green, which means "nothing known matched" and nothing more
 *
 * The optional AI pass (src/ai.js) may raise a verdict or clear a yellow to
 * green after reading the evidence. It may never lower a red. That floor is
 * enforced here, in applyAiVerdict, and is not configurable.
 */

const VERDICT_RANK = { green: 0, yellow: 1, red: 2 };

export const EXIT_CODES = {
  green: 0,
  yellow: 1,
  red: 2,
  error: 3,
};

/** The exact meaning of a green verdict, used verbatim everywhere it appears. */
export const GREEN_MEANING = "nothing known matched";

/**
 * Four rules that all report the same observation: this file carries encoded
 * content. A minified bundle trips most of them at once, so counting them
 * separately turns one thing noticed into the three that raise a caution.
 * They are collapsed into a single signal for that reason.
 */
export const ENCODED_CONTENT_SIGNALS = new Set([
  "base64-blob",
  "single-line-blob",
  "encoded-blob-density",
  "high-entropy-literal",
]);

/**
 * Findings that are reported but never move a verdict on their own. An
 * instruction file executes nothing: saying a repository ships one is advice
 * to the reader, not evidence about the repository, and shipping one is
 * ordinary. The agent-hook and MCP rules are not here, because those describe
 * something that runs. The same rule at high severity still convicts, since
 * that fires on what the file says rather than on its existence.
 */
const ADVISORY_SIGNALS = new Set([
  "agent-instruction-file",
  // One more that describes ordinary structure rather than behaviour, and
  // whose behaviour has its own louder rule. Bare eval and new Function run
  // through every bundler, parser and template engine, which this rule's own
  // comment says when it sets itself to low; running DECODED or FETCHED text
  // is eval-decoded-blob and remote-code-execution, both high, and neither
  // depends on this one.
  //
  // Counted, it was a third of the reason vue, eslint, prettier, discord.js
  // and helix were yellow on nothing but the profile of a JavaScript
  // toolchain: has a postinstall, uses eval, somewhere fetches and spawns.
  // Signals that all say "this is a build tool" corroborate nothing.
  //
  // lifecycle-script is deliberately NOT here. Two tests in
  // false-positives.test.js use it as one of three signals that should
  // corroborate, and a postinstall beside an encoded blob and a lookalike
  // identifier is a different thing from a postinstall beside eval.
  "dynamic-code-execution",
]);

/**
 * Two rules that report the same observation at low severity: this project
 * runs install scripts that look ordinary. A benign postinstall in the
 * manifest ("prisma generate") and a declared native dependency that
 * declares one (esbuild, sharp, the Prisma engines) are one fact about a
 * Node project, not two, and with any third weak signal, such as a vendored
 * bundle, they made an ordinary NestJS-and-Prisma application yellow.
 * lifecycle-script still corroborates anything else: the collapse is only
 * with its lockfile twin.
 */
const INSTALL_SCRIPT_SIGNALS = new Set(["lifecycle-script", "transitive-install-script", "composer-install-script"]);

export function decideVerdict(findings) {
  let highs = 0;
  let meds = 0;
  const lowIds = new Set();
  for (const f of findings) {
    if (f.severity === "high") highs++;
    else if (f.severity === "medium") meds++;
    else if (!ADVISORY_SIGNALS.has(f.id)) {
      // A vendored bundle trips several weak rules at once because it is a
      // megabyte of minified library code, not because the project did
      // several odd things. All of them together are one signal, the same
      // treatment the four encoded-content rules already get.
      // Findings in a test path collapse for the same reason vendored ones
      // do, and it is the reason the downgrade there already states: a
      // finding in a test path "cannot be the sole evidence of danger". Three
      // of them are one observation -- this project has a test suite that
      // exercises the shapes this tool looks for -- not three about the
      // project. babel-generator keeps one minified fixture that trips both
      // the entropy rule and the download rule, and ripgrep's test helpers
      // name a homoglyph and a sandbox check in two files.
      //
      // A separate key from vendored: a bundled library and a test fixture
      // are different observations, and merging them would count two things
      // as one. The !executable guard where the tag is set still holds, so a
      // file an install script names collapses nothing.
      // Maintainer scripts nothing runs are a third such observation: this
      // project keeps release and CI tooling, which downloads and shells
      // out, and that is one fact however many scripts show it.
      lowIds.add(
        f.vendored
          ? "vendored-artifact"
          : f.manualTool
            ? "maintainer-tool"
            : f.testPath
              ? "test-path"
              : ENCODED_CONTENT_SIGNALS.has(f.id)
                ? "encoded-content"
                : INSTALL_SCRIPT_SIGNALS.has(f.id)
                  ? "install-scripts"
                  : f.id,
      );
    }
  }
  // Three different weak signals corroborate each other; the same weak
  // signal in three files (a hash-like literal in three test fixtures) is
  // one signal, not three, and neither are four names for one observation.
  const lows = lowIds.size;
  if (highs >= 1) return "red";
  if (meds >= 1 || lows >= 3) return "yellow";
  return "green";
}

/**
 * Combine the static verdict with the AI pass verdict.
 *
 * A red static verdict is a hard floor the AI can never lower. Red is also a
 * ceiling the AI can never reach on its own: red means a high-severity
 * signature fired, and a model's opinion is not a signature. The benchmark
 * showed a model raising a well-known benign repository to red on one run
 * and clearing it on the next, so an AI "red" over a non-red scan lands as
 * yellow: the caution is kept, the model's reasoning is printed, and the
 * word red keeps its meaning.
 */
export function applyAiVerdict(staticVerdict, aiVerdict) {
  if (staticVerdict === "red") return "red";
  if (!Object.prototype.hasOwnProperty.call(VERDICT_RANK, aiVerdict)) return staticVerdict;
  if (aiVerdict === "red") return "yellow";
  return aiVerdict;
}

const SEVERITY_RANK = { high: 2, medium: 1, low: 0 };

/**
 * Deterministic finding order: severity first, then file, line, rule id.
 * Same input, same bytes out, so golden tests can compare reports exactly.
 */
export function sortFindings(findings) {
  return [...findings].sort((a, b) => {
    const sev = SEVERITY_RANK[b.severity] - SEVERITY_RANK[a.severity];
    if (sev !== 0) return sev;
    if (a.file !== b.file) return a.file < b.file ? -1 : 1;
    const la = a.line ?? 0;
    const lb = b.line ?? 0;
    if (la !== lb) return la - lb;
    if (a.id !== b.id) return a.id < b.id ? -1 : 1;
    return 0;
  });
}
