/**
 * Which files a scan reads, decided from the tree alone, and which further
 * files the fetched ones say will run.
 *
 * Selection is where a scanner is evaded cheaply: a file never fetched is a
 * file no rule sees. So the order is by where a trap has to live to fire
 * before anyone reads it, each kind of file has a quota, and nothing a
 * category matched may leave the selection silently.
 */

import { TEST_PATH, TEST_PATH_CAMEL } from "./vendored.js";
import { autorunProgramPaths, mcpServers } from "./ecosystems.js";

// .mts and .cts are ordinary Node module files that tsx, ts-node and Node's
// own type stripping run directly; they were missed because `\.` sat straight
// in front of `ts`, so a rename was enough to skip a file entirely. Single
// file components and HTML carry a real <script> block, which makes them
// source rather than markup, and a front-end take-home keeps its application
// code in them. The rest are interpreters this engine already names in
// INTERPRETER and runsFile: it would convict a script for invoking one and
// then never read the file it invoked.
export const CODE_EXT =
  /\.(js|cjs|mjs|ts|mts|cts|jsx|tsx|vue|svelte|astro|html?|py|go|rs|sh|bash|zsh|ps1|psm1|bat|cmd|rb|php|lua|pl|java|kt|swift|cs)$/i;
export const CONFIG_FILE =
  /(^|\/)(postcss|vite|next|webpack|babel|tailwind|rollup|nuxt|svelte|metro|jest)\.config\.(js|cjs|mjs|ts)$/i;

const LOCKFILE_NAMES = ["package-lock.json", "npm-shrinkwrap.json", "yarn.lock", "pnpm-lock.yaml"];
const ECOSYSTEM_FILES =
  /(^|\/)(setup\.py|pyproject\.toml|requirements[\w.-]*\.txt|build\.rs|build\.gradle(\.kts)?|settings\.gradle(\.kts)?|pom\.xml|composer\.json|extconf\.rb|Rakefile|rakefile)$|\.gemspec$/;
/**
 * Files a coding agent reads as instructions, with close to the authority of
 * its own system prompt. Nothing in them executes by itself, which is why
 * they are judged separately from the configuration that does: the risk is
 * that the agent working in the folder obeys them.
 */
export const AGENT_INSTRUCTION_FILES =
  /(^|\/)(CLAUDE|AGENTS?|GEMINI|CONVENTIONS)\.md$|(^|\/)\.(cursorrules|clinerules|windsurfrules|aiderrules)$|(^|\/)\.(cursor|clinerules|windsurf)\/rules\/[\w.-]+$|(^|\/)\.github\/copilot-instructions\.md$/i;

const AUTORUN_FILES =
  /(^|\/)(\.vscode\/tasks\.json|\.vscode\/settings\.json|\.vscode\/mcp\.json|\.cursor\/mcp\.json|\.cursor\/hooks\.json|\.claude\/settings(\.local)?\.json|\.mcp\.json|\.zed\/settings\.json|\.gemini\/settings\.json|\.roo\/mcp\.json|\.dir-locals(-2)?\.el|\.nvim\.lua|\.nvimrc|\.exrc|\.devcontainer\/devcontainer\.json|\.devcontainer\.json|Makefile|makefile|GNUmakefile|\.npmrc|\.yarnrc|\.yarnrc\.ya?ml|\.envrc|docker-compose\.ya?ml|compose\.ya?ml|Dockerfile|dockerfile|\.pnpmfile\.cjs)$|\.dockerfile$|\.code-workspace$/i;

/**
 * Decide which files to fetch, from the tree alone. Returns paths ordered by
 * priority; the caller applies MAX_FILES_FETCHED and the byte caps.
 *
 * The listing is put in path order first, so the selection depends on what
 * is in the tree and never on the order it arrived in. The quotas below keep
 * the first few matches of each kind and ties in the depth and size sorts
 * keep their input order, so a reversed listing of django/django picked five
 * different workflow files. The API and `git ls-files` happen to agree on an
 * order today; a verdict should not rest on that.
 */
export function selectableFiles(listing) {
  const tree = [...listing].sort((a, b) => (a.path < b.path ? -1 : a.path > b.path ? 1 : 0));
  const picks = [];
  const seen = new Set();
  const add = (p) => {
    if (!seen.has(p)) {
      seen.add(p);
      picks.push(p);
    }
  };
  const inNodeModules = (p) => p.includes("node_modules/");

  // Each category takes a quota, so one kind of file cannot spend the whole
  // budget. What a quota turns away queues here and is appended after the
  // source pass instead of being dropped: nothing a category matched may
  // leave the selection silently, or a scan could read five of seven files
  // and still report green.
  const overflow = [];
  const take = (matches, quota) => {
    matches.slice(0, quota).forEach((e) => add(e.path));
    matches.slice(quota).forEach((e) => overflow.push(e.path));
  };
  const byDepth = (a, b) => a.path.split("/").length - b.path.split("/").length;

  // 1) Manifests: package.json files (root first), then lockfiles.
  take(
    tree.filter((e) => /(^|\/)package\.json$/.test(e.path) && !inNodeModules(e.path)).sort(byDepth),
    4,
  );
  take(
    tree.filter((e) => LOCKFILE_NAMES.includes(e.path.split("/").pop()) && !inNodeModules(e.path)),
    3,
  );

  // 2) Non-npm ecosystem manifests and build scripts.
  take(tree.filter((e) => ECOSYSTEM_FILES.test(e.path) && !inNodeModules(e.path)), 6);

  // 3) Instruction files a coding agent obeys. Small, few, and read with
  // system-prompt authority, so they are worth a slot of their own.
  take(tree.filter((e) => AGENT_INSTRUCTION_FILES.test(e.path) && !inNodeModules(e.path)).sort(byDepth), 4);

  // 4) Editor, container, and make auto-run files, plus CI workflows. The
  // quota is larger than the others because a repository can carry the
  // editor, AI-agent, container and make hooks at once, and every one of
  // them runs before the victim types a command.
  // Not under node_modules, like every other category: an editor config or
  // a Dockerfile inside an installed package is not what opening or
  // building this repository runs. Two take-home repositories that had
  // committed node_modules/ were yellow for the nvm installer in a rollup
  // plugin's Dockerfile.
  take(tree.filter((e) => AUTORUN_FILES.test(e.path) && !inNodeModules(e.path)), 6);
  take(tree.filter((e) => /^\.github\/workflows\/[^/]+\.ya?ml$/.test(e.path)), 5);

  // 4) Build config files, the classic hiding spot for the payload.
  take(tree.filter((e) => CONFIG_FILE.test(e.path) && !inNodeModules(e.path)), 8);

  // 5) The README, for context signals.
  take(tree.filter((e) => /^readme\.(md|txt|rst)$/i.test(e.path)), 1);

  // 5b) Jupyter notebooks, shallow first: a common ML-lure payload carrier.
  take(tree.filter((e) => /\.ipynb$/i.test(e.path) && !inNodeModules(e.path)).sort(byDepth), 3);

  // 6) Large code files (possible obfuscated blobs), biggest first.
  take(
    tree
      .filter((e) => CODE_EXT.test(e.path) && (e.size ?? 0) > 15_000 && !inNodeModules(e.path))
      .sort((a, b) => (b.size ?? 0) - (a.size ?? 0)),
    8,
  );

  // 7) Source files, shallow first, until the cap is reached.
  //
  // A dropper sits in src/, lib/, app/ or a plausible utility file, where a
  // reviewer skimming the root never opens it, so the budget has to reach
  // there. Shallow files come first: they are more likely to be an entry
  // point or the file a lifecycle script reaches. A small planted repository
  // fits inside the cap whole; a large monorepo gets a shallow sample, and
  // the report says so. Within this pass test and vendored paths sort last,
  // since their findings are downgraded anyway; a large vendored bundle is
  // already taken by step 6 as a blob candidate.
  const deprioritized = (p) => (TEST_PATH.test(p) || TEST_PATH_CAMEL.test(p) || isLikelyVendoredPath(p) ? 1 : 0);
  tree
    .filter((e) => CODE_EXT.test(e.path) && !inNodeModules(e.path))
    .sort((a, b) => {
      const d = deprioritized(a.path) - deprioritized(b.path);
      if (d !== 0) return d;
      const depth = a.path.split("/").length - b.path.split("/").length;
      if (depth !== 0) return depth;
      return a.path < b.path ? -1 : 1;
    })
    .forEach((e) => add(e.path));

  overflow.forEach(add);
  return picks;
}

/** Path-only vendored check, for prioritizing real source over bundles in selection. */
function isLikelyVendoredPath(path) {
  return /(^|\/)(node_modules|vendor|vendored|third_party|dist|build|out|\.next|coverage|compiled|generated|__generated__|__snapshots__|\.yarn)\//i.test(
    path,
  );
}

/**
 * Local files that a package.json's lifecycle scripts or bin entries point
 * at, so the code that actually runs on install gets fetched and judged
 * instead of guessed at.
 */
/**
 * Configuration an editor or coding agent acts on by itself when the folder
 * is opened: MCP servers it launches, hook commands it runs as it works.
 */
const AGENT_CONFIG = /(^|\/)(\.mcp\.json|mcp\.json|hooks\.json)$|(^|\/)\.(claude|cursor|zed|vscode|gemini|roo)\/[\w-]+\.json$/;

/**
 * Local files an agent-hook or MCP configuration starts. The command alone
 * cannot say whether a repository runs its own linter or a dropper, so the
 * program behind it is fetched and judged on its own rather than guessed at
 * from the command string.
 */
export function referencedAutorunPaths(path, content) {
  if (!AGENT_CONFIG.test(path)) return [];
  // Read the same commands the rules read, rather than every path-shaped
  // string in the file: a config naming a dozen unrelated files would
  // otherwise spend the follow-up budget and starve the one program whose
  // contents decide the verdict.
  const commands = (mcpServers(content) ?? []).map((s) => s.command);
  for (const m of content.matchAll(/"command"\s*:\s*"((?:[^"\\]|\\.)*)"/g)) {
    commands.push(m[1].replace(/\\(["\\/])/g, "$1"));
  }
  const paths = new Set();
  for (const cmd of commands) for (const p of autorunProgramPaths(cmd)) paths.add(p);
  return [...paths];
}
