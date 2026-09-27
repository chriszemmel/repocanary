/**
 * package.json: lifecycle scripts, the files they run, and the dependency
 * fields an install actually resolves.
 *
 * npm follows `npm run` indirection without asking, so a hook is judged by
 * what it finally runs, not by the one line that delegates to it.
 */

import { MAX_MANIFEST_DEPTH, lineOfIndex, redactSnippet, safeJsonParse } from "./textutil.js";
import { checkDependencyName, isPopularPackage } from "./typosquat.js";
import { isDangerousScript } from "./ecosystems.js";
import { isKnownGitSource } from "./lockfile.js";

// Lifecycle hooks that run without the user asking. prepare and prepack also
// run when the package is installed from a git source, which is why a "safe
// looking" git dependency plus a prepare script is a complete attack.
//
// npm wraps every one of these in pre and post, and still honours the
// deprecated prepublish, so `npm install` on a bare project runs preinstall,
// install, postinstall, prepublish, preprepare, prepare and postprepare in
// that order. Listing only five of them meant renaming postinstall to
// postprepare kept install-time execution, dropped the verdict to a caution,
// and stopped the file it invokes being followed at all.
const LIFECYCLE_HOOKS = [
  "preinstall",
  "install",
  "postinstall",
  "prepublish",
  "preprepare",
  "prepare",
  "postprepare",
  "prepack",
  "postpack",
];

/**
 * A script command with `npm run x` replaced by what x actually is.
 *
 * npm follows that indirection without asking, so a hook is worth exactly
 * what the script it delegates to is worth. Reading the wrapper instead made
 * `"postinstall": "npm run setup"` a plain local hook while the dangerous
 * body was reported only as a script "that does not fire on install by
 * itself", which by then was not true. One line, and a red became a caution.
 *
 * Bounded by the scripts already visited, so a manifest that defines a cycle
 * is the manifest's problem rather than this function's. Bounded in depth
 * too: a chain of two thousand `npm run` links overflowed the stack and cost
 * the whole scan. Past the limit the rest of the chain is not dropped, which
 * would hide whatever sits at its end, but appended flat, found by a loop.
 */
// A fresh regex per use: the resolver recurses from inside its own replace
// callback, and a shared global regex carries lastIndex between callers.
const npmRunRe = () => /\b(?:npm|pnpm|yarn|bun)\s+run(?:-script)?\s+(?:-\S{1,60}\s+)*([\w:@./-]+)/g;
const NPM_RUN_MAX_DEPTH = 32;

function resolveNpmRun(scripts, cmd, seen = new Set(), depth = 0) {
  if (typeof cmd !== "string") return cmd;
  if (depth >= NPM_RUN_MAX_DEPTH) return [cmd, ...flatNpmRunChain(scripts, cmd, seen)].join(" ; ");
  return cmd.replace(npmRunRe(), (whole, name) => {
    if (seen.has(name) || typeof scripts[name] !== "string") return whole;
    seen.add(name);
    return resolveNpmRun(scripts, scripts[name], seen, depth + 1);
  });
}

/** Every script body reachable from `cmd` through `npm run`, without recursion. */
function flatNpmRunChain(scripts, cmd, seen) {
  const bodies = [];
  const queue = [cmd];
  while (queue.length > 0) {
    for (const m of queue.shift().matchAll(npmRunRe())) {
      const name = m[1];
      if (seen.has(name) || typeof scripts[name] !== "string") continue;
      seen.add(name);
      bodies.push(scripts[name]);
      queue.push(scripts[name]);
    }
  }
  return bodies;
}

// Commands whose names a package "bin" entry must never shadow. A bin entry
// named npm or node hijacks the next thing the victim types.
const SHADOWED_COMMANDS = new Set([
  "npm", "npx", "node", "yarn", "pnpm", "git", "python", "python3", "pip",
  "pip3", "code", "bash", "sh", "sudo", "make", "cargo", "go",
]);

// Packages that give an attacker eyes and hands on the machine: keylogging,
// screen capture, screen and input control, and remote desktop. Each has a
// legitimate use (accessibility, automation), so this is a caution, not a
// conviction, but none belongs in a coding-interview take-home.
const SURVEILLANCE_DEPS = new Set([
  "node-global-key-listener", "iohook", "gkm", "node-key-sender",
  "screenshot-desktop", "screenshot", "desktop-screenshot", "active-win",
  "node-window-manager", "get-windows", "robotjs", "@nut-tree/nut-js",
  "nut-js", "@jitsi/robotjs", "keysender", "node-webcam", "node-record-lpcm16",
]);

export function checkPackageJson(path, content) {
  const findings = [];
  const parsed = safeJsonParse(content);
  if (!parsed.ok || typeof parsed.value !== "object" || parsed.value === null) {
    findings.push({
      id: "broken-package-json",
      severity: "low",
      file: path,
      line: null,
      snippet: redactSnippet(content.slice(0, 120)),
      why: "This package.json is not valid JSON, which is unusual for a working project and prevents checking its scripts and dependencies.",
      next: "Treat the project as unreviewed until the manifest parses.",
    });
    return findings;
  }
  const pkg = parsed.value;
  const scripts = pkg.scripts && typeof pkg.scripts === "object" ? pkg.scripts : {};

  // technique: install-time code execution through npm lifecycle hooks
  for (const hook of LIFECYCLE_HOOKS) {
    const cmd = scripts[hook];
    if (typeof cmd !== "string") continue;
    // Judged on what npm will actually run, indirection through `npm run`
    // included; the snippet below still shows what the manifest says.
    const dangerous = isDangerousScript(resolveNpmRun(scripts, cmd));
    const gitSourceHook = hook.endsWith("prepare") || hook.endsWith("prepack");
    findings.push({
      // A dangerous script (downloads, decodes, evals) is high. A plain local
      // one is low, not medium: most real projects have a benign postinstall
      // or prepare, and the file it invokes is followed and scanned on its
      // own, so a dropper is caught there rather than by the hook's presence.
      id: "lifecycle-script",
      severity: dangerous ? "high" : "low",
      file: path,
      line: findKeyLine(content, hook),
      snippet: redactSnippet(`"${hook}": "${cmd}"`),
      why: dangerous
        ? `This package runs a "${hook}" script automatically the moment anyone types npm install${gitSourceHook ? " (or installs it as a git dependency)" : ""}, and that script downloads, decodes, or evaluates code from outside the visible project. That is the exact mechanism fake-interview malware uses to steal credentials before you ever open the code.`
        : `This package runs a "${hook}" script automatically when you type npm install${gitSourceHook ? ", and also when the package is installed from a git source" : ""}, before you review or run anything. That is common in legitimate projects (copying files, setting up tooling), but it is also the entry point malware uses.`,
      next: dangerous
        ? "Do not run npm install. Report the repository if the script fetches or decodes anything."
        : `Read what the "${hook}" script actually does (and any file it invokes) before installing.`,
    });
  }

  // Non-lifecycle scripts a README will tell the victim to run.
  for (const [name, cmd] of Object.entries(scripts)) {
    if (LIFECYCLE_HOOKS.includes(name) || typeof cmd !== "string") continue;
    // isDangerousScript, not the bare pattern: the two loops asked different
    // questions of the same manifest, so a "clean" script that deletes its
    // own dist directory was exempt as a hook and convicted as a script. The
    // guarded form is the raw one with three literal local idioms neutralised,
    // so this can only ever report less, never more.
    if (isDangerousScript(cmd)) {
      // A script is run when someone runs it. The ones a lure names are the
      // ones every project has: start, dev, test, build, setup. A release,
      // coverage or codegen helper runs when its maintainer runs it, the
      // same reading a script in tools/ gets.
      const everyday = /^(start|dev|serve|test|build|watch|preview|setup|bootstrap|init|install|seed|migrate|demo|app|main|run)(:|$)/i.test(name);
      findings.push({
        id: "dangerous-npm-script",
        severity: everyday ? "medium" : "low",
        file: path,
        line: findKeyLine(content, name),
        snippet: redactSnippet(`"${name}": "${cmd}"`),
        why: `The "${name}" script downloads, decodes, or evaluates code when run. It does not fire on install by itself, but one "just run npm run ${name}" in the README is all it takes.`,
        next: `Read the "${name}" script and everything it invokes before running it.`,
      });
    }
  }

  // Every field an install actually resolves, not just the two obvious ones.
  // npm installs optionalDependencies by default and has resolved peers since
  // npm 7, so a name hidden in either still runs on `npm install` while the
  // dependency list a reviewer reads looks ordinary. scan.js already read
  // optionalDependencies for its lockfile cross-check; these two disagreed.
  const table = (t) => (t && typeof t === "object" && !Array.isArray(t) ? t : {});
  const allDeps = {
    ...table(pkg.dependencies),
    ...table(pkg.devDependencies),
    ...table(pkg.optionalDependencies),
    ...table(pkg.peerDependencies),
  };

  for (const [dep, spec] of Object.entries(allDeps)) {
    // A local path is not a package name anyone could squat: continue's
    // "core": "file:../core" read as a lookalike of cors.
    if (!/^(file|link|workspace|portal):/i.test(String(spec))) {
      findings.push(...checkDependencyName(dep, { file: path, line: findKeyLine(content, dep), version: String(spec) }));
    }

    // technique: keylogging, screen capture, or input control dependency
    if (SURVEILLANCE_DEPS.has(dep.toLowerCase())) {
      findings.push({
        id: "surveillance-dependency",
        severity: "medium",
        file: path,
        line: findKeyLine(content, dep),
        snippet: redactSnippet(`"${dep}": "${spec}"`),
        why: `The dependency "${dep}" captures the screen, keystrokes, or control of the mouse and keyboard. These have legitimate uses in automation and accessibility tools, but in a coding-interview task they give whoever sent it eyes and hands on your machine.`,
        next: `Ask why a take-home task needs "${dep}". If there is no clear answer, do not run it.`,
      });
    }

    // technique: npm alias protocol disguising the installed package. A spec
    // like "react": "npm:evil-pkg@1" installs evil-pkg while every import and
    // the dependency list still say react. The name is a costume for a
    // different package. An alias to the SAME name (a version pin) is fine.
    if (typeof spec === "string" && /^npm:/i.test(spec)) {
      const aliasTarget = spec.slice(4).replace(/^(@[^/]+\/[^@]+|[^@]+).*/, "$1");
      // Only a BARE trusted name being redirected is the disguise. Legit
      // aliases use a descriptive local name (react-builtin, zod3, foo-cjs)
      // pointing at the real package; those keys are not themselves popular
      // package names, so gating on the key's popularity clears them.
      // "typescript": "npm:@typescript/typescript6" is TypeScript's own scope
      // publishing a preview; a scope named after the package is the same
      // publisher, not a costume.
      const sameScope = aliasTarget.toLowerCase().startsWith(`@${dep.toLowerCase()}/`);
      // "prettier": "npm:wp-prettier" names itself as a fork of the package
      // it replaces (the name ends in the original), which a reader of the
      // manifest can see; still worth a look, not a conviction. The disguise
      // starts with the trusted name and hides what it is (react-dom-helper-x).
      const labelledFork = new RegExp(`(^|/)[\\w.]+-${dep.toLowerCase().replace(/[.*+?^${}()|[\]\\]/g, "\\$&")}$`).test(aliasTarget.toLowerCase());
      // A variant that says what it is: a scoped republish keeping the
      // package's own name (@e965/xlsx, the community build of SheetJS;
      // @voidzero-dev/vite-plus-core, Vite+ from Vite's own company), or an
      // alias to another package everyone already knows (lodash-es for
      // lodash). Two take-home repositories scaffolded with Vite+ were red
      // for the first shape. A bare lookalike, react-dom-helper-x standing in
      // for react, still hides what it is.
      const targetLower = aliasTarget.toLowerCase();
      const scopedBase = targetLower.startsWith("@") ? targetLower.slice(targetLower.indexOf("/") + 1) : null;
      const depLower = dep.toLowerCase();
      const namedVariant =
        (scopedBase !== null && (scopedBase === depLower || scopedBase.startsWith(`${depLower}-`))) ||
        isPopularPackage(aliasTarget);
      if (aliasTarget && aliasTarget.toLowerCase() !== dep.toLowerCase() && !sameScope && isPopularPackage(dep)) {
        findings.push({
          id: "npm-alias-mismatch",
          severity: labelledFork || namedVariant ? "medium" : "high",
          file: path,
          line: findKeyLine(content, dep),
          snippet: redactSnippet(`"${dep}": "${spec}"`),
          why: `The dependency listed as "${dep}" actually installs a different package, "${aliasTarget}", through npm's alias protocol. Everything in the project reads as "${dep}" while the code that installs is "${aliasTarget}". Renaming a package to wear a trusted name is a deliberate disguise.`,
          next: `Do not install. Look up "${aliasTarget}" on npmjs.com; that is what actually runs, not "${dep}".`,
        });
      }
    }

    // technique: dependency pulled from git or a URL, off the public registry
    if (typeof spec === "string" && /^(git\+|git:|git@|github:|bitbucket:|gitlab:|https?:)/.test(spec)) {
      const known = isKnownGitSource(spec);
      // Pinned to a full commit, the source cannot change after review: the
      // bytes installed are the bytes at that hash. argo-cd and argo-workflows
      // pin argo-ui that way. A commit hash in a tarball URL is the same pin
      // (ramda's browserify), and a release tag is the published version
      // itself: socket.io takes uWebSockets.js at #v20.56.0. A branch, or
      // nothing, is whatever the source serves on the day of the install.
      const pinned = /#[0-9a-f]{40}$|\/[0-9a-f]{40}(?:\.(?:tar\.gz|tgz|zip))?$|#(?:semver:)?v?\d+\.\d+(?:\.\d+)?(?:-[\w.]+)?$/i.test(spec);
      findings.push({
        id: "manifest-non-registry-dependency",
        severity: known || pinned ? "low" : "medium",
        file: path,
        line: findKeyLine(content, dep),
        snippet: redactSnippet(`"${dep}": "${spec}"`),
        why: known
          ? `The dependency "${dep}" is installed from its own documented git home instead of the npm registry, which is how every project of its kind installs it. A git ref can still change without a version bump, so it is reported, but this is the ordinary shape.`
          : `The dependency "${dep}" is installed from ${/^https?:/.test(spec) ? "a direct URL" : "a git source"} instead of the npm registry. Whoever controls that source controls the code, can change it at any time without a version bump, and its prepare script runs on install.`,
        next: "Open the source URL and read the code it currently serves before installing.",
      });
    }
  }

  // overrides (npm) and resolutions (yarn) that redirect a name to a URL.
  for (const field of ["overrides", "resolutions"]) {
    const table = pkg[field];
    if (!table || typeof table !== "object") continue;
    for (const [name, spec] of Object.entries(flattenOverrides(table))) {
      if (typeof spec === "string" && /^(git\+|git:|git@|github:|https?:|file:)/.test(spec)) {
        findings.push({
          id: "override-redirect",
          severity: "medium",
          file: path,
          line: findKeyLine(content, field),
          snippet: redactSnippet(`${field}: "${name}": "${spec}"`),
          why: `The "${field}" field redirects the dependency "${name}" away from the registry to ${spec.slice(0, 60)}. Overrides silently replace what every other package thinks it is importing, deep in the tree, where nobody looks.`,
          next: "Check what the redirect target serves; a version-number override is normal, a URL override is not.",
        });
      }
    }
  }

  // technique: native build steps that compile and run during install (node-gyp)
  if (pkg.gypfile === true) {
    findings.push({
      id: "native-build-at-install",
      severity: "medium",
      file: path,
      line: findKeyLine(content, "gypfile"),
      snippet: '"gypfile": true',
      why: "This package compiles native code at install time (node-gyp). The build scripts run automatically during npm install, which gives a take-home repo a second, less obvious place to execute code.",
      next: "Read binding.gyp and any referenced build scripts before installing.",
    });
  }

  const bin = pkg.bin;
  const binEntries =
    typeof bin === "string" ? { [String(pkg.name ?? "")]: bin } : bin && typeof bin === "object" ? bin : {};
  const selfName = String(pkg.name ?? "").toLowerCase();
  const selfIsCommand = SHADOWED_COMMANDS.has(selfName);
  for (const [name, target] of Object.entries(binEntries)) {
    if (SHADOWED_COMMANDS.has(name.toLowerCase()) && !selfIsCommand) {
      findings.push({
        id: "bin-command-shadowing",
        severity: "high",
        file: path,
        line: findKeyLine(content, "bin"),
        snippet: redactSnippet(`"bin": { "${name}": "${target}" }`),
        why: `This package installs an executable named "${name}", shadowing the real ${name} command. After npm install, typing ${name} can run this package's code instead of the tool you meant, silently, every time.`,
        next: "Do not install. No legitimate package names its executable after a system command.",
      });
    }
  }

  // Frontend project that also pulls in server and network kit is a soft flag.
  const depNames = Object.keys(allDeps);
  const hasFrontend = depNames.some((d) => ["react", "vue", "next", "svelte", "vite"].includes(d));
  // Servers and sockets, not HTTP clients: axios and node-fetch sit in
  // almost every frontend, so counting them made ordinary portals odd.
  const serverish = depNames.filter((d) => ["express", "socket.io", "ws", "koa", "fastify", "request"].includes(d));
  if (hasFrontend && serverish.length >= 2) {
    findings.push({
      id: "odd-dependency-mix",
      severity: "medium",
      file: path,
      line: null,
      snippet: `frontend framework + ${serverish.join(", ")}`,
      why: `This looks like a frontend app, yet it also pulls in server and network packages (${serverish.join(", ")}). The combination can be legitimate, but it is also how hidden code phones home.`,
      next: "Search the source for where these network packages are actually used.",
    });
  }

  return findings;
}

/** Flatten one level of nested npm overrides ({a: {b: spec}}). */
function flattenOverrides(table, prefix = "", depth = 0) {
  const out = {};
  // A walk with no floor is a crash the repository chooses: a 29 KB
  // package.json of nothing but nesting overflowed the stack and aborted the
  // scan. V8 parses that JSON happily, so safeJsonParse cannot catch it.
  if (depth > MAX_MANIFEST_DEPTH) return out;
  for (const [k, v] of Object.entries(table)) {
    const key = prefix ? `${prefix} > ${k}` : k;
    if (v && typeof v === "object") Object.assign(out, flattenOverrides(v, key, depth + 1));
    else out[key] = v;
  }
  return out;
}

/**
 * Where each quoted string first appears in the file, built once per file.
 * The obvious `content.indexOf(`"${key}"`)` is a pass over the whole file per
 * key, and the callers ask once per dependency, so a manifest with twenty
 * thousand of them cost twenty thousand passes over its own text.
 *
 * Same memo shape as lineOfIndex: one file at a time, and the answer does not
 * depend on whether the cache is warm.
 */
let quotedContent = null;
let quotedAt = null;

/** Line of the first occurrence of a JSON key, for finding locations. */
function findKeyLine(content, key) {
  if (content !== quotedContent) {
    const at = new Map();
    // The same strings `indexOf` would have found, including keys that appear
    // as values; picking the first occurrence keeps that behaviour exactly.
    for (const m of content.matchAll(/"((?:[^"\\]|\\.)*)"/g)) if (!at.has(m[1])) at.set(m[1], m.index);
    quotedContent = content;
    quotedAt = at;
  }
  const idx = quotedAt.get(key);
  return idx === undefined ? null : lineOfIndex(content, idx);
}

export function referencedScriptPaths(pkgJsonContent) {
  const parsed = safeJsonParse(pkgJsonContent);
  if (!parsed.ok || typeof parsed.value !== "object" || parsed.value === null) return [];
  const pkg = parsed.value;
  const paths = new Set();

  const scripts = pkg.scripts && typeof pkg.scripts === "object" ? pkg.scripts : {};
  // Two shapes: the argument an interpreter is given, and a bare ./program.
  // The extension is no longer required. checkFile already says a file an
  // install script runs is read as code whatever it is called, because
  // "bin/setup" is exactly where a dropper hides, but this could not produce
  // such a path: it demanded a suffix, nothing else selects an extensionless
  // file, and a postinstall pointing at one was never fetched at all.
  const re =
    /(?:^|[\s;&|(])(?:node|ts-node|tsx|python3?|sh|bash|zsh|ruby|perl|php)\s+(?:-\S{1,60}\s+)*(\.{0,2}\/?[\w.\/-]+)|(?:^|[\s;&|(])(\.\/[\w.\/-]+)/g;
  for (const hook of LIFECYCLE_HOOKS) {
    // A hook that runs another of this manifest's scripts is that script:
    // npm follows the indirection without asking, so judging the wrapper let
    // one extra line ("postinstall": "npm run setup") turn a conviction into
    // a caution and leave the body's own file unfollowed.
    const cmd = resolveNpmRun(scripts, scripts[hook]);
    if (typeof cmd !== "string") continue;
    let m;
    while ((m = re.exec(cmd)) !== null) {
      const p = (m[1] ?? m[2]).replace(/^\.\//, "");
      // follow() only ever resolves against paths already in the tree, so a
      // traversal cannot leave the repository; it is dropped here as well.
      if (p && !p.startsWith("/") && !p.includes("..")) paths.add(p);
    }
  }

  const bin = pkg.bin;
  const binEntries = typeof bin === "string" ? [bin] : bin && typeof bin === "object" ? Object.values(bin) : [];
  for (const target of binEntries) {
    if (typeof target === "string") paths.add(target.replace(/^\.\//, ""));
  }

  return [...paths];
}
