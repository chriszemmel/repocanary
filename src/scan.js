/**
 * Scan orchestration: pick files from the tree, fetch their text within the
 * hard caps, run every rule, and score the verdict. The client is injected,
 * so tests run the whole pipeline against fixture directories with no
 * network at all.
 */

import {
  FOLLOW_UP_RESERVE_BYTES,
  MAX_FILES_FETCHED,
  MAX_FILE_BYTES,
  MAX_FOLLOW_UPS,
  MAX_TOTAL_BYTES,
} from "./github.js";
import { checkFile, checkRepoMeta } from "./heuristics.js";
import { referencedScriptPaths } from "./packagejson.js";
import { referencedAutorunPaths, selectableFiles } from "./selection.js";
import { decideVerdict, sortFindings } from "./verdict.js";
import { redactBlock, redactSnippet, safeJsonParse } from "./textutil.js";

/**
 * How many findings a report lists. The verdict is always decided on all of
 * them; this only bounds what is printed and returned, so an adversarial
 * lockfile cannot turn a report into a megabyte of repetition.
 */
export const MAX_REPORTED_FINDINGS = 200;

/** Version ranges and tags resolve from the registry; anything else names its own source. */
const REGISTRY_SPEC = /^(\s*$|[\^~=<>]|\d|\*|x$|latest$|next$)/;

/** Direct dependencies of every package.json, keyed by manifest directory. */
function manifestSpecs(files) {
  const byDir = new Map();
  for (const f of files) {
    if (f.path.split("/").pop() !== "package.json") continue;
    const parsed = safeJsonParse(f.content);
    if (!parsed.ok || typeof parsed.value !== "object" || parsed.value === null) continue;
    const specs = new Map();
    for (const field of ["dependencies", "devDependencies", "optionalDependencies"]) {
      const table = parsed.value[field];
      if (!table || typeof table !== "object") continue;
      for (const [name, spec] of Object.entries(table)) if (typeof spec === "string") specs.set(name, spec);
    }
    byDir.set(f.path.slice(0, f.path.lastIndexOf("/") + 1), specs);
  }
  return byDir;
}

/**
 * A lockfile that resolves a dependency from git while the manifest beside
 * it asks for a plain version range is a poisoned lockfile: the manifest is
 * what a reviewer reads, and the lockfile is what the installer obeys. A git
 * source declared in both is only the declared caution it already raised.
 */
function crossCheckLockfiles(findings, files) {
  const manifests = manifestSpecs(files);
  // A lockfile that resolves a package from exactly the host the manifest
  // beside it names is the declared dependency, not a costume: the reader
  // of package.json already sees the URL, and its own finding says so.
  // Emergent.sh scaffolds declare two packages as tarballs on
  // assets.emergent.sh, and monster2005mac-dex/marcos was red for the
  // lockfile repeating them.
  const hostOf = (u) => {
    try {
      return new URL(u).hostname.toLowerCase();
    } catch {
      return null;
    }
  };
  findings = findings.map((f) => {
    if (f.id !== "lockfile-off-registry" || f.severity !== "high" || !f.package || !f.resolved) return f;
    const dir = f.file.slice(0, f.file.lastIndexOf("/") + 1);
    const spec = manifests.get(dir)?.get(f.package);
    if (typeof spec !== "string" || !/^https:\/\//i.test(spec)) return f;
    const host = hostOf(spec);
    if (host === null || host !== hostOf(f.resolved)) return f;
    return {
      ...f,
      severity: "medium",
      why: `${f.why} Here package.json names the same host for "${f.package}" in plain view, so the lockfile resolves what the manifest declares rather than swapping it; the caution is the declared dependency itself.`,
    };
  });
  const extra = [];
  for (const f of findings) {
    if (f.id !== "lockfile-git-dependency" || !f.package) continue;
    const dir = f.file.slice(0, f.file.lastIndexOf("/") + 1);
    const spec = manifests.get(dir)?.get(f.package);
    if (spec === undefined || !REGISTRY_SPEC.test(spec)) continue;
    extra.push({
      id: "lockfile-manifest-mismatch",
      severity: "high",
      file: f.file,
      line: f.line,
      snippet: f.snippet,
      package: f.package,
      why: `package.json asks for "${f.package}" at "${spec}", an ordinary registry version, but the lockfile resolves it from a git repository instead. The manifest is what a reviewer reads and the lockfile is what npm install obeys, so this disagreement means the installed code is not what the dependency list claims.`,
      next: "Do not run npm install. Delete the lockfile and regenerate it yourself, or compare the git ref against the registry package.",
    });
  }
  return [...findings, ...extra];
}

/**
 * An editor or agent that starts a program from the repository is the trap's
 * shape and equally how a project runs its own linter, tests or MCP server.
 * The command string cannot tell them apart, so the program itself decides:
 * one this scan read and found nothing in relaxes to a caution, because the
 * repository still chose code that runs before anyone reads it. A program
 * the scan could not read, because it is missing, binary, or past the byte
 * cap, stays high. Silence about a file nobody could open is not evidence.
 */
function relaxReadAutorunPrograms(findings, files, treeComplete = false) {
  const read = new Set();
  const suspicious = new Set();
  for (const f of files) read.add(f.path);
  for (const f of findings) if (f.severity !== "low") suspicious.add(f.file);
  return findings.map((f) => {
    if (f.severity !== "high" || !Array.isArray(f.programs) || f.programs.length === 0) return f;
    if (f.id !== "agent-hook-autorun" && f.id !== "mcp-server-autostart") return f;
    // The resolution follow() already made, not a fresh guess at it. Searching
    // the fetched list for a path ending in the program's name answered with
    // whichever file happened to be fetched first, so a benign setup.js at the
    // repository root could vouch for the tools/setup.js a config one
    // directory down actually starts: the verdict dropped from red to a
    // caution, and the report said it had read a file it had not.
    const resolved = f.resolvedPrograms ?? [];
    if (resolved.length !== f.programs.length) return f;
    // A program that is nowhere in a complete file listing is not in the
    // repository, so opening the folder cannot start it: the editor reports
    // a missing file. tandryio/tandry points its MCP config at
    // dist/tandry.cjs, its own build output, and was told it "starts a
    // program checked into this repository". Whatever builds that file is
    // itself scanned. A truncated listing proves nothing about absence, so
    // there the finding stays high.
    const missing = resolved.filter((p) => p === undefined);
    const present = resolved.filter((p) => p !== undefined);
    // Only for a path where build output lives. Anywhere else an absent
    // program may be one the listing cannot show, such as a file in a
    // submodule, and silence about a file nobody could open is not evidence.
    const missingNames = f.programs.filter((_, i) => resolved[i] === undefined);
    const buildOutput = missingNames.every((p) => /(^|\/)(dist|build|out|target|\.next|\.output)\//.test(p.replace(/^\.\//, "")));
    if (missing.length > 0 && treeComplete && buildOutput && present.every((p) => read.has(p) && !suspicious.has(p))) {
      return {
        ...f,
        severity: "medium",
        why: f.why.replace(
          "starts a program checked into this repository",
          `names a program to start, ${missingNames.map((p) => redactSnippet(p, 60)).join(", ")}, that is not in this repository and sits where build output does`,
        ) + " Nothing runs from it until that file exists, so this is a caution: read what creates it before building.",
      };
    }
    if (resolved.some((p) => p === undefined || !read.has(p) || suspicious.has(p))) return f;
    return {
      ...f,
      severity: "medium",
      why: `${f.why} RepoCanary read ${resolved.length === 1 ? `${resolved[0]}, and found` : `${resolved.join(", ")}, and found`} nothing in it that steals, downloads or hides code, so this is reported as a caution rather than a trap. It is still the repository, not you, deciding what runs here.`,
    };
  });
}

/**
 * Findings that describe a capability honest tooling has: downloading and
 * running an installer, writing a service unit, reading a browser profile,
 * sending the environment somewhere. Signatures with no honest use at all
 * (obfuscator output, code hidden off-screen, a known-malicious package, a
 * wallet extension ID, smuggled Unicode, C2 fingerprints) are not here and
 * are judged the same wherever they sit.
 */
const CAPABILITY_RULES = new Set([
  "download-and-execute",
  "python-download-execute",
  "remote-code-execution",
  "startup-persistence",
  "dockerfile-remote-exec",
  "wallet-file-access",
  "env-exfiltration",
  "env-dump-exfiltration",
  "base64-blob",
  "dynamic-code-execution",
  "sandbox-evasion",
  "ssh-backdoor",
  "tunneling-infra",
]);

/**
 * A program a maintainer runs by hand: a standalone shell or PowerShell
 * script, a container build, or anything in a directory that holds a
 * project's own tooling rather than the project.
 */
const TOOL_FILE =
  /\.(sh|bash|zsh|ksh|fish|bat|cmd|ps1|psm1)$|(^|\/)(Dockerfile[\w.-]*|Containerfile)$|\.dockerfile$|(^|\/)(scripts?|tools?|bench|deploy|deployments?|infra|ops|hack|packaging|release|installers?|contrib|misc|dev-?tools|docker|provisioning|ansible|terraform|k8s|helm)\//i;

/** Configuration a package manager, editor, agent, container or git hook acts on without being asked. */
const AUTORUN_CONFIG =
  /(^|\/)(\.yarnrc(\.ya?ml)?|\.npmrc|\.pnpmfile\.c?js|\.mcp\.json|Procfile|lefthook\.ya?ml|\.pre-commit-config\.ya?ml|(docker-)?compose(\.[\w-]+)?\.ya?ml|\.envrc)$|(^|\/)\.(vscode|devcontainer|claude|cursor|zed|husky|githooks)\//;

/** Scripts a README or a lure tells a person to run, by the name they have in package.json. */
const RUN_SCRIPT_NAMES = /^(start|dev|serve|test|build|watch|preview|setup|bootstrap|init|install|prepare|postinstall|preinstall)(:|$)/;

/**
 * The text that says what gets run on the paths a person follows: the
 * scripts a manifest runs when started, built or tested, every script the
 * README names, the Makefile and justfile, and the README itself.
 */
function runInstructions(files) {
  const readme = files.find((f) => /^readme\.(md|txt|rst)$/i.test(f.path))?.content ?? "";
  const named = new Set([...readme.matchAll(/\b(?:npm\s+run|yarn(?:\s+run)?|pnpm(?:\s+run)?|bun\s+run)\s+([\w:.-]+)/g)].map((m) => m[1]));
  const parts = [readme];
  for (const f of files) {
    const base = f.path.split("/").pop();
    if (/^(Makefile|GNUmakefile|makefile|[Jj]ustfile)$/.test(base)) parts.push(f.content);
    // Every configuration some tool acts on by itself, whole. follow() reads
    // the commands the rules know how to parse; a file named anywhere in one
    // of these may still be started by it (Yarn 1's yarn-path is one that
    // follow() does not read), and a name that merely appears there keeps
    // its finding whole, which is the safe direction to be wrong in.
    if (AUTORUN_CONFIG.test(f.path)) parts.push(f.content);
    if (base !== "package.json") continue;
    const parsed = safeJsonParse(f.content);
    const scripts = parsed.ok && parsed.value && typeof parsed.value.scripts === "object" ? parsed.value.scripts : null;
    if (!scripts) continue;
    for (const [name, cmd] of Object.entries(scripts)) {
      if (typeof cmd === "string" && (RUN_SCRIPT_NAMES.test(name) || named.has(name))) parts.push(cmd);
    }
  }
  return parts.join("\n");
}

/**
 * A capability finding in a program nobody is told to run and nothing runs
 * by itself steps down to a caution. The trap this tool exists for runs
 * when the victim installs, opens, builds or starts the project; a deploy
 * script that writes a systemd unit, a Dockerfile that pipes an installer
 * into sh, and a release helper run only when their maintainer runs them.
 * Wave 16 had eleven honest reds and every reader of them would have been
 * told "do not run it" about a script they were never going to run.
 *
 * Referenced means named anywhere in the run instructions, which is
 * deliberately loose: a README that mentions setup_vps.sh keeps its finding
 * whole, because "run this" is exactly what a lure's README says.
 */
function stepDownManualTools(findings, files, started) {
  const instructions = runInstructions(files);
  const referenced = (path) => {
    const base = path.split("/").pop();
    const escaped = base.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
    return new RegExp(`(^|[^\\w.-])${escaped}($|[^\\w-])`).test(instructions);
  };
  return findings.map((f) => {
    if ((f.severity !== "high" && f.severity !== "medium") || !CAPABILITY_RULES.has(f.id)) return f;
    // At the root, a Dockerfile or a script is how the project is meant to be
    // run: `docker build .` and `./setup.sh` need no instruction to be the
    // obvious next step, and a lure need not write one down.
    if (!f.file.includes("/")) return f;
    if (!TOOL_FILE.test(f.file) || started.has(f.file) || referenced(f.file)) return f;
    // One step, whatever the step is from: a release helper that fetches a
    // changelog and shells out to git is informational, the way a dropper
    // in the same place is a caution. ruff, bitcoin, flutter and PowerShell
    // were yellow for scripts only their maintainers run.
    if (f.severity === "medium") {
      return {
        ...f,
        severity: "low",
        manualTool: true,
        why: `${f.why} (Nothing in this repository runs ${f.file} by itself, and neither the manifest nor the README tells you to run it, so this is on the record rather than a caution.)`,
      };
    }
    return {
      ...f,
      severity: "medium",
      manualTool: true,
      why: `${f.why} (Nothing in this repository runs ${f.file} by itself, and neither the manifest nor the README tells you to run it: it is a tool the maintainers run by hand, so this is a caution rather than danger. Read it before you ever run it yourself.)`,
    };
  });
}

/**
 * A one-edit lookalike of a popular package raises a verdict only with
 * corroboration: another finding of medium or higher severity, or an install
 * script, anywhere in the scan. Alone it is reported as informational. The
 * popular list can never be complete, so a real package missing from it
 * would otherwise turn every project that uses it yellow.
 */
function corroborate(findings) {
  // Corroboration is evidence about what gets installed or run: an install
  // script, anything high, or a caution about the dependency graph itself.
  // A CI workflow or a minified asset elsewhere says nothing about whether
  // "memoize" is a lookalike of "memoizee", and ava, jotai and supabase were
  // yellow for pairs like that.
  // The lure's own context counts too: a lookalike in a repository from an
  // account made last week is the shape these campaigns send.
  const INSTALL_EVIDENCE = /^(lifecycle-script|transitive-install-script|manifest-|lockfile-|npm-alias-mismatch|known-malicious-package|scope-confusion|npmrc-|new-account|empty-org)/;
  const corroborated = findings.some(
    (f) => f.id === "lifecycle-script" || f.severity === "high" || (f.id !== "typosquat-dependency" && f.severity === "medium" && INSTALL_EVIDENCE.test(f.id)),
  );
  if (corroborated) return findings;
  return findings.map((f) =>
    f.id === "typosquat-dependency"
      ? {
          ...f,
          severity: "low",
          why: `${f.why} Nothing else in this repository corroborates it, so this is reported for your information rather than as a caution.`,
        }
      : f,
  );
}

export async function scanRepo({ owner, repo, ref = null, client, now = Date.now() }) {
  // The context rules subtract timestamps from this, so it has to be a
  // number; a clock function would turn every account age into NaN and the
  // new-account signal would never fire outside the tests.
  const at = typeof now === "function" ? now() : Number(now);
  const { meta, tree, treeTruncated, submodules, symlinks = 0, metaPartial = false } = await client.fetchRepo(owner, repo, ref);

  const candidates = selectableFiles(tree);
  const paths = candidates.slice(0, MAX_FILES_FETCHED);
  const skippedByCap = candidates.length - paths.length;
  const files = [];
  let totalBytes = 0;
  let unreadable = 0;
  let byteCapReached = false;
  let truncated = 0;
  const addFile = (path, content, executable = false) => {
    if (content.length >= MAX_FILE_BYTES) truncated += 1;
    totalBytes += content.length;
    files.push({ path, content, bytes: content.length, lines: content.split("\n").length, executable });
  };

  for (const path of paths) {
    if (totalBytes >= MAX_TOTAL_BYTES) {
      byteCapReached = true;
      break;
    }
    const content = await client.fetchFile(meta.owner, meta.repo, meta.ref, path);
    if (content === null) unreadable += 1;
    else addFile(path, content);
  }

  // Second pass: follow lifecycle scripts, bin entries, and the programs an
  // editor or coding agent starts by itself, to the local files they invoke,
  // so the code that actually runs gets scanned instead of being judged from
  // the command string that names it.
  const treePaths = new Set(tree.map((e) => e.path));
  const fetched = new Set(files.map((f) => f.path));
  // A program an editor starts by itself is queued ahead of an install
  // script's body: whether that file is a linter or a dropper is what
  // decides this scan's verdict, while a script body mostly adds detail to a
  // finding that already fired. On a repository with many manifests the
  // scripts would otherwise take every slot.
  const autorunFollowUps = [];
  const scriptFollowUps = [];
  // What each reference resolved to, so a finding can be given the body of
  // the file its script actually names. Recovering that afterwards by looking
  // for a basename inside the snippet string matched any file whose name was
  // a substring of it, and took the first one fetched.
  const resolvedScripts = new Map(); // manifest path -> [{ rel, resolved }]
  // Every file something in this repository starts by itself, whether or not
  // the selection pass had already fetched it. This used to be inferred from
  // "was it a follow-up", which is a different question: follow() skips a
  // candidate already fetched, and the selection pass fetches every ordinary
  // source file, so the flag that raises a download beside a spawn from a
  // caution to danger reached almost nothing. A dropper named setup.js got a
  // caution while the same bytes at a name the selection missed got danger.
  const started = new Set();
  // A program the manifest names that is nowhere in the file listing. Silence
  // about a file nobody could open is not evidence, so this is reported.
  const unresolvedPrograms = [];
  const follow = (into, from, rel) => {
    const dir = from.includes("/") ? from.slice(0, from.lastIndexOf("/") + 1) : "";
    const candidate = treePaths.has(dir + rel)
      ? dir + rel
      : treePaths.has(rel)
        ? rel
        : tree.find((e) => e.path.endsWith(`/${rel}`))?.path;
    if (!candidate) {
      unresolvedPrograms.push(rel);
      return;
    }
    if (!resolvedScripts.has(from)) resolvedScripts.set(from, []);
    resolvedScripts.get(from).push({ rel, resolved: candidate });
    started.add(candidate);
    if (!fetched.has(candidate)) {
      fetched.add(candidate);
      into.push(candidate);
    }
  };
  // Discovery reads crafted input too, and a throw here would lose the whole
  // scan. A file whose references cannot be read keeps its own findings; it
  // only has nothing followed from it.
  for (const f of files) {
    try {
      const base = f.path.split("/").pop();
      if (base === "package.json") {
        for (const rel of referencedScriptPaths(f.content)) follow(scriptFollowUps, f.path, rel);
      }
      for (const rel of referencedAutorunPaths(f.path, f.content)) follow(autorunFollowUps, f.path, rel);
    } catch {
      // Judged below like every other file; checkFileSafely reports it.
    }
  }
  const followUps = [...autorunFollowUps, ...scriptFollowUps];
  // The follow-ups draw on an allowance of their own rather than the
  // selection's leftovers. A repository large enough to spend the whole
  // budget on ordinary source is exactly the one whose auto-run program
  // decides a verdict, and leftovers are precisely what such a repository
  // has none of.
  const followUpsDropped = Math.max(0, followUps.length - MAX_FOLLOW_UPS);
  let followUpBytes = 0;
  for (const path of followUps.slice(0, MAX_FOLLOW_UPS)) {
    if (followUpBytes >= FOLLOW_UP_RESERVE_BYTES) {
      byteCapReached = true;
      break;
    }
    const content = await client.fetchFile(meta.owner, meta.repo, meta.ref, path);
    if (content === null) unreadable += 1;
    else {
      followUpBytes += content.length;
      addFile(path, content, true);
    }
  }
  // The selection pass fetched these before the second pass could ask for
  // them, so they carry executable: false from addFile's default. Marking
  // them here is what makes the flag mean "something starts this file"
  // rather than "the selection happened to miss this file".
  for (const f of files) if (started.has(f.path)) f.executable = true;

  // A rule that throws on crafted input would otherwise lose the whole scan,
  // and a repository that can reliably produce "no verdict" has switched the
  // scanner off. Each file is judged on its own: one failure costs that file's
  // findings and is reported, never the other files' and never silently.
  const unscannable = [];
  const checkFileSafely = (f) => {
    try {
      return checkFile(f, { owner, repo });
    } catch {
      unscannable.push(f.path);
      return [];
    }
  };

  const raw = [...files.flatMap(checkFileSafely), ...checkRepoMeta(meta, at)];
  // Hand each auto-run finding the paths follow() resolved its programs to,
  // from the config that named them, so nothing downstream has to re-derive
  // them from a bare filename.
  for (const f of raw) {
    if (!Array.isArray(f.programs)) continue;
    const named = resolvedScripts.get(f.file) ?? [];
    f.resolvedPrograms = f.programs.map((rel) => named.find((r) => r.rel === rel)?.resolved);
  }

  // A self-hosted runner reaches the reader's machine only if they register
  // one, which is what a lure's README would ask for.
  const readmeText = files.find((f) => /^readme\.(md|txt|rst)$/i.test(f.path))?.content ?? "";
  const asksForRunner = /self[- ]hosted runner|register (?:a |the |your )?(?:github )?runner|actions\/runners|config\.sh\s+--url/i.test(readmeText);
  for (const f of raw) {
    if (f.id === "workflow-self-hosted-runner" && asksForRunner) {
      f.severity = "medium";
      f.why = `${f.why} This repository's README asks the reader to set a runner up.`;
    }
  }
  const findings = corroborate(
    stepDownManualTools(relaxReadAutorunPrograms(crossCheckLockfiles(raw, files), files, !treeTruncated), files, started),
  );

  // Attach each invoked install-script's body to its lifecycle finding, so
  // the report (and the optional AI pass) shows what the script does.
  for (const f of findings) {
    if (f.id !== "lifecycle-script") continue;
    // Matched on the whole reference this manifest actually named, and only
    // among the files follow() resolved for it. Recovering the file from a
    // basename let a decoy called up.js answer for "node scripts/setup.js",
    // because the snippet contains those five letters.
    const named = (resolvedScripts.get(f.file) ?? []).find((r) => f.snippet.includes(r.rel));
    const script = named ? files.find((sf) => sf.path === named.resolved) : undefined;
    if (script) {
      // Redacted like every other excerpt. This is raw repository content and
      // it travels to the AI provider when --ai is used, so a credential
      // committed into an install script would go with it.
      f.scriptBody = redactBlock(script.content.slice(0, 600));
      f.scriptPath = script.path;
    }
  }

  const sorted = sortFindings(findings);
  const verdict = decideVerdict(sorted);

  const notes = [];
  // The verdict above was decided on every finding. What gets listed is
  // capped, because a lockfile with a thousand packages that declare install
  // scripts produces a thousand findings, and a report nobody can read is a
  // report nobody reads. The cut is after the sort, so what survives is the
  // most severe, and the note says what was left out.
  let reported = sorted;
  if (sorted.length > MAX_REPORTED_FINDINGS) {
    reported = sorted.slice(0, MAX_REPORTED_FINDINGS);
    const rest = sorted.slice(MAX_REPORTED_FINDINGS);
    const kinds = [...new Set(rest.map((f) => f.id))].sort();
    notes.push(
      `${rest.length} further finding${rest.length === 1 ? "" : "s"} (${kinds.join(", ")}) ${rest.length === 1 ? "is" : "are"} not listed; a report stops at ${MAX_REPORTED_FINDINGS}. The verdict was decided on all ${sorted.length}, and the ones shown are the most severe.`,
    );
  }
  if (treeTruncated) {
    notes.push(
      "The repository is so large that GitHub truncated its file listing; only the files RepoCanary could see were considered.",
    );
  }
  if (submodules > 0) {
    notes.push(
      `The repository contains ${submodules} git submodule${submodules === 1 ? "" : "s"}, which point at other repositories and were not scanned. Scan them separately.`,
    );
  }
  if (symlinks > 0) {
    notes.push(
      `${symlinks} symlink${symlinks === 1 ? " was" : "s were"} not followed. A symlink's content is a path rather than code, and following one is how a scanner gets walked out of the repository.`,
    );
  }
  if (metaPartial) {
    notes.push(
      "The repository owner's profile or commit history could not be read, so the account-age, commit-burst and author signals were not evaluated. Their absence from this report is not evidence that they would not have fired.",
    );
  }
  if (unscannable.length > 0) {
    notes.push(
      `${unscannable.length} file${unscannable.length === 1 ? "" : "s"} could not be examined because a rule failed on ${unscannable.length === 1 ? "it" : "them"} (${unscannable.slice(0, 5).join(", ")}${unscannable.length > 5 ? ", and others" : ""}). A file crafted to break a rule is itself a reason for suspicion, and nothing was judged about ${unscannable.length === 1 ? "its" : "their"} contents. Please report this repository so the rule can be fixed.`,
    );
  }
  if (unreadable > 0) {
    notes.push(
      `${unreadable} file${unreadable === 1 ? "" : "s"} could not be read as text (binary content, or the fetch failed) and ${unreadable === 1 ? "was" : "were"} not scanned.`,
    );
  }
  if (truncated > 0) {
    notes.push(
      `${truncated} file${truncated === 1 ? " was" : "s were"} larger than the ${MAX_FILE_BYTES / 1_000_000} MB per-file cap; only the first ${MAX_FILE_BYTES / 1_000_000} MB of ${truncated === 1 ? "it" : "each"} was scanned.`,
    );
  }
  if (followUpsDropped > 0) {
    notes.push(
      `${followUpsDropped} further file${followUpsDropped === 1 ? "" : "s"} named by an install script or an auto-run configuration ${followUpsDropped === 1 ? "was" : "were"} not fetched, because a scan follows at most ${MAX_FOLLOW_UPS}.`,
    );
  }
  // A program a manifest names and the file listing does not contain. It may
  // be a tool from PATH, and it may be a file the listing was truncated
  // before reaching; either way nothing was read, and a scan that stays quiet
  // about that reads like one that looked.
  if (unresolvedPrograms.length > 0) {
    const shown = [...new Set(unresolvedPrograms)].slice(0, 5).map((p) => redactSnippet(p, 60));
    notes.push(
      `${unresolvedPrograms.length} program${unresolvedPrograms.length === 1 ? "" : "s"} named by an install script or an auto-run configuration (${shown.join(", ")}${new Set(unresolvedPrograms).size > 5 ? ", and others" : ""}) ${unresolvedPrograms.length === 1 ? "was" : "were"} not found in this repository's file listing, so ${unresolvedPrograms.length === 1 ? "it was" : "they were"} not scanned. That is ordinary when the command names a tool from your PATH, and it is what a payload outside the listing looks like.`,
    );
  }
  // Green on a repository where nothing was read is honest only if it says
  // so. The verdict means "nothing known matched", and here nothing was
  // looked at: every file was of a kind this scanner does not read, or none
  // could be read as text.
  if (files.length === 0) {
    notes.push(
      candidates.length === 0
        ? "No file in this repository is of a kind RepoCanary reads (manifests, scripts, editor and agent configuration, lockfiles), so nothing was examined. This verdict says nothing about the repository."
        : "None of the files RepoCanary selected could be read as text, so nothing was examined. This verdict says nothing about the repository.",
    );
  }
  if (skippedByCap > 0 || byteCapReached) {
    const reason = byteCapReached
      ? `the ${MAX_TOTAL_BYTES / 1_000_000} MB total budget`
      : `the ${MAX_FILES_FETCHED} file cap, leaving ${skippedByCap} candidate file${skippedByCap === 1 ? "" : "s"} unread`;
    notes.push(
      `The scan stopped at ${reason}, so not every file in this repository was read. A payload in a file that was never fetched would not be seen.`,
    );
  }

  return {
    verdict,
    findings: reported,
    // Every finding, uncapped, for the rules that have to reason about all of
    // them rather than about a readable subset. The AI pass keeps a list of
    // signals a model may never clear to green, and it read the capped array:
    // padding a repository with two hundred cheap findings that sort ahead of
    // the guarded one pushed it out of view and the backstop stopped firing.
    // Not rendered anywhere; `findings` above is still what a report prints.
    allFindings: sorted,
    meta,
    notes,
    stats: {
      filesScanned: files.length,
      bytesScanned: totalBytes,
      // The true counts, which are what the verdict was decided on. They
      // differ from the listed findings exactly when the note above says so,
      // and consumers must use these rather than counting a capped array.
      findings: sorted.length,
      // One accumulator, mutated: the spread allocated a fresh object per
      // finding, over a list that is deliberately uncapped.
      severities: sorted.reduce(
        (acc, f) => {
          acc[f.severity] += 1;
          return acc;
        },
        { high: 0, medium: 0, low: 0 },
      ),
      treeTruncated: Boolean(treeTruncated),
    },
  };
}
