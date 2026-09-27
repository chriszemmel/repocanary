/**
 * Lockfile rules: package-lock.json, npm-shrinkwrap.json, yarn.lock,
 * pnpm-lock.yaml.
 *
 * Lockfiles are a favorite hiding place because reviewers skim past them and
 * installers obey them blindly. A poisoned lockfile can resolve a familiar
 * dependency name to an attacker's tarball URL, pin a git ref nobody audited,
 * or pull in a transitive package that runs an install script. RepoCanary
 * reads the resolution URLs, not the code, so none of this ever executes.
 */

import { lineOfIndex, MAX_MANIFEST_DEPTH, redactSnippet, safeJsonParse } from "./textutil.js";
import { KNOWN_MALICIOUS_PACKAGES } from "./typosquat.js";

/** Registry hosts a resolution URL may legitimately point at. */
const REGISTRY_HOSTS = new Set([
  "registry.npmjs.org",
  "registry.yarnpkg.com",
  "npm.jsr.io",
  // Public mirrors of the npm registry that whole regions install from.
  "registry.npmmirror.com",
  "registry.npm.taobao.org",
  "registry.npmjs.com",
  "registry.nlark.com",
  "mirrors.cloud.tencent.com",
  "mirrors.tencent.com",
  "registry.npmmirror.org",
  // cnpm's own hosts, which predate npmmirror and are still in lockfiles.
  // LeetCode-OpenSource/vscode-leetcode resolves packages from r.cnpmjs.org
  // and r2.cnpmjs.org in the same file and turned red for both.
  "r.cnpmjs.org",
  "registry.cnpmjs.org",
]);

/**
 * Mirror domains whose subdomains are all the same operator's replicas, so
 * the numbered ones (r2, r3) count without listing each. Matched as a real
 * suffix on a dot, never as a substring: "evil-cnpmjs.org" and
 * "cnpmjs.org.attacker.net" are different hosts and are not covered.
 */
const REGISTRY_DOMAINS = ["cnpmjs.org", "npmmirror.com"];

function isRegistryHost(host) {
  if (host === null) return false;
  if (REGISTRY_HOSTS.has(host)) return true;
  return REGISTRY_DOMAINS.some((d) => host === d || host.endsWith(`.${d}`));
}

/**
 * A mirror that cannot be reached from outside its own network: a leaked
 * corporate Artifactory in a checked-in lockfile (gradio's client), not a
 * source an attacker can serve a payload from.
 */
/**
 * Publishers that distribute their own package from their own host, by
 * documented instruction (SheetJS moved xlsx off npm). Off registry, but the
 * package's own source: a caution, not a hijack.
 */
const OFFICIAL_TARBALL_HOSTS = new Set(["cdn.sheetjs.com"]);

/** Hosted registry providers: a company's private or mirrored feed, a caution rather than a hijack. */
const HOSTED_REGISTRY = /(^|\.)pkgs\.dev\.azure\.com$|\.pkgs\.visualstudio\.com$|\.jfrog\.io$|^npm\.pkg\.github\.com$|^npm\.cloudsmith\.io$|^gitlab\.com$/i;

const INTERNAL_HOST = /\.(local|internal|corp|lan|intranet|home)$|^localhost$|^127\.|^10\.|^192\.168\.|^172\.(1[6-9]|2\d|3[01])\./i;

/**
 * Packages known to ship install scripts as part of normal operation
 * (native builds, browser downloads, git hooks). Their presence in a
 * lockfile is expected, so they are not flagged.
 */
const KNOWN_INSTALL_SCRIPT_PACKAGES = new Set([
  "esbuild", "sharp", "puppeteer", "playwright", "cypress", "node-sass",
  "sqlite3", "better-sqlite3", "bcrypt", "fsevents", "core-js", "core-js-pure",
  "canvas", "grpc", "husky", "sentry-cli", "electron", "node-gyp",
  "prebuild-install", "node-pre-gyp", "cwebp-bin", "mozjpeg", "pngquant-bin",
  "gifsicle", "optipng-bin", "phantomjs-prebuilt", "chromedriver",
  "geckodriver", "protobufjs", "nodemon", "workerd", "argon2", "keytar",
  "leveldown", "re2", "swc", "dtrace-provider", "unix-dgram", "bufferutil",
  "utf-8-validate", "msgpackr-extract", "ssh2", "cpu-features", "iltorb",
  "deasync", "libpq", "zeromq", "serialport", "usb", "spawn-sync", "es5-ext",
  "nx", "dprint", "@vscode/vsce-sign", "@apollo/protobufjs",
  "playwright-chromium", "playwright-firefox", "playwright-webkit",
  "unrs-resolver", "vue-demi", "mongodb-memory-server", "@fortawesome/fontawesome-free", "yarn",
]);

const KNOWN_INSTALL_SCRIPT_PREFIXES = [
  "@esbuild/", "@swc/", "@sentry/", "@parcel/", "@prisma/", "@img/",
  "@napi-rs/", "@node-rs/", "esbuild-", "turbo-", "workerd-", "@playwright/", "@serialport/",
];

/**
 * Every package name some entry in the lockfile asks for, from the root
 * project down. A package that appears here is part of the tree the project
 * declared, however deep; one that appears nowhere is in the lockfile
 * without anything depending on it, which is what a planted entry looks
 * like. A lockfile that carries no dependency maps at all yields an empty
 * set, so nothing is relaxed on a format this cannot read.
 */
function declaredNames(entries) {
  const names = new Set();
  const FIELDS = ["dependencies", "devDependencies", "optionalDependencies", "peerDependencies", "requires"];
  for (const [, info] of entries) {
    if (typeof info !== "object" || info === null) continue;
    for (const field of FIELDS) {
      const table = info[field];
      if (table && typeof table === "object" && !Array.isArray(table)) {
        for (const dep of Object.keys(table)) names.add(dep);
      }
    }
  }
  return names;
}

function isKnownInstallScriptPackage(name) {
  if (KNOWN_INSTALL_SCRIPT_PACKAGES.has(name)) return true;
  return KNOWN_INSTALL_SCRIPT_PREFIXES.some((p) => name.startsWith(p));
}

function hostOf(url) {
  try {
    return new URL(url).hostname;
  } catch {
    return null;
  }
}

/**
 * Git sources that are the documented, canonical home of a package its whole
 * ecosystem installs from git: forge-std is how every Foundry project gets
 * its test library, and a caution on each of them teaches the people this
 * tool is for -- web3 is the campaigns' favourite lure -- that yellow means
 * nothing. Matched on the exact owner and repository, so a fork under
 * another owner is still the caution it should be.
 */
const KNOWN_GIT_SOURCES = ["foundry-rs/forge-std"];

export function isKnownGitSource(spec) {
  const m = String(spec).match(/(?:github\.com[/:]|^github:|^)([\w.-]+\/[\w.-]+?)(?:\.git)?(?:[#@].*)?$/i);
  if (!m) return false;
  const repo = m[1].toLowerCase();
  return KNOWN_GIT_SOURCES.some((k) => k.toLowerCase() === repo);
}

/** GitHub and GitLab source hosts. A tarball from one is a source pin, the
 * same risk class as a git dependency, not an anonymous off-registry host. */
const GIT_SOURCE_HOSTS = /(^|\.)(github\.com|codeload\.github\.com|gitlab\.com|bitbucket\.org)$/i;

function offRegistryFinding(file, line, name, resolved) {
  return { ...offRegistryShape(file, line, name, resolved), package: name, resolved };
}

function offRegistryShape(file, line, name, resolved) {
  const host = hostOf(resolved);
  if (host !== null && HOSTED_REGISTRY.test(host)) {
    return {
      id: "lockfile-off-registry",
      severity: "medium",
      file,
      line,
      snippet: redactSnippet(`${name} -> ${resolved}`),
      why: `The lockfile resolves "${name}" from "${host}", a hosted registry provider where companies keep private or mirrored feeds. Whoever controls that feed controls the package, so this deserves a look, but it is how many organisations install.`,
      next: "Check whose feed this is and that the project openly documents using it.",
    };
  }
  const isGit =
    /^(git\+|git:|git@|ssh:)/.test(resolved) ||
    /\.git(#|$)/.test(resolved) ||
    (host !== null && GIT_SOURCE_HOSTS.test(host));
  if (isGit) {
    const known = isKnownGitSource(resolved);
    // A lockfile pins the commit: `#<40 hex>` or a codeload tarball of one.
    // Those bytes cannot be swapped after review, which is the risk a git
    // dependency carries, so it is a note like a known source.
    const pinned = /[#/][0-9a-f]{40}(\b|$)/i.test(resolved);
    return {
      id: "lockfile-git-dependency",
      severity: known || pinned ? "low" : "medium",
      file,
      line,
      snippet: redactSnippet(`${name} -> ${resolved}`),
      why: known
        ? `The lockfile resolves "${name}" from its own documented git home rather than the npm registry, which is how every project of its kind installs it. A git ref can still change under you, so it is reported, but this is the ordinary shape.`
        : `The lockfile resolves "${name}" from a git repository instead of the npm registry. Registry packages are public and versioned; a git ref can be changed or force-pushed by whoever controls that repository, and prepare scripts of git dependencies run on install.`,
      next: "Open the referenced repository and read what it contains before installing anything.",
    };
  }
  if (host !== null && OFFICIAL_TARBALL_HOSTS.has(host)) {
    return {
      id: "lockfile-off-registry",
      severity: "medium",
      file,
      line,
      snippet: redactSnippet(`${name} -> ${resolved}`),
      why: `The lockfile resolves "${name}" from "${host}", which is that package's own publisher distributing it outside npm by documented instruction. It is still code the registry never saw, so check that the version matches what the project's manifest asks for.`,
      next: "Compare the tarball URL with the publisher's own installation instructions before installing.",
    };
  }
  if (host !== null && INTERNAL_HOST.test(host)) {
    return {
      id: "lockfile-off-registry",
      severity: "medium",
      file,
      line,
      snippet: redactSnippet(`${name} -> ${resolved}`),
      why: `The lockfile resolves "${name}" from "${host}", an internal mirror that only exists on some company's network. Installing from outside it fails rather than fetching anything, so this is a leaked lockfile, not a hijack, but the lockfile is not the one the project actually uses.`,
      next: "Ask why the lockfile points at a private mirror, and install from a lockfile generated against the public registry.",
    };
  }
  if (resolved.startsWith("http://") && isRegistryHost(host)) {
    return {
      id: "lockfile-insecure-registry-url",
      severity: "low",
      file,
      line,
      snippet: redactSnippet(`${name} -> ${resolved}`),
      why: `The lockfile fetches "${name}" from the npm registry over plain http rather than https. Old versions of npm wrote registry URLs this way and many long-lived projects still carry them; the integrity hash next to the URL is what the installer checks, so this is a sign of age rather than of a hijack.`,
      next: "Regenerate the lockfile with a current npm if you maintain the project; otherwise nothing to do.",
    };
  }
  if (resolved.startsWith("http://")) {
    return {
      id: "lockfile-off-registry",
      severity: "high",
      file,
      line,
      snippet: redactSnippet(`${name} -> ${resolved}`),
      why: `The lockfile downloads "${name}" over plain, unencrypted http from ${host ?? "an unknown host"}. No legitimate project does this; it means the installed code is whatever that server (or anyone in between) decides to serve.`,
      next: "Do not run npm install. This lockfile is not fetching what its dependency names claim.",
    };
  }
  return {
    id: "lockfile-off-registry",
    severity: "high",
    file,
    line,
    snippet: redactSnippet(`${name} -> ${resolved}`),
    why: `The lockfile resolves "${name}" to a tarball on ${host ?? "an unknown host"} instead of the npm registry. The name in package.json is a costume: what actually installs is whatever that URL serves, and installers follow lockfile URLs without asking.`,
    next: "Do not run npm install. Compare the lockfile entry against the same package on registry.npmjs.org.",
  };
}

function findLine(content, needle) {
  const idx = content.indexOf(needle);
  return idx === -1 ? null : lineOfIndex(content, idx);
}

/**
 * Flatten a lockfile v1 `dependencies` tree into the {path, info} pairs the
 * v2/v3 `packages` map already provides, so one code path judges both.
 */
function flattenV1Dependencies(deps, prefix = "", out = [], depth = 0) {
  if (typeof deps !== "object" || deps === null) return out;
  // A walk with no floor is a crash the repository chooses: a 112 KB lockfile
  // of nothing but nesting overflowed the stack and aborted the scan. Real
  // trees are a few levels deep; MAX_MANIFEST_DEPTH is far past any of them.
  if (depth > MAX_MANIFEST_DEPTH) return out;
  for (const [name, info] of Object.entries(deps)) {
    if (typeof info !== "object" || info === null) continue;
    const pkgPath = `${prefix}node_modules/${name}`;
    out.push([pkgPath, { ...info, name }]);
    if (info.dependencies) flattenV1Dependencies(info.dependencies, `${pkgPath}/`, out, depth + 1);
  }
  return out;
}

/** package-lock.json and npm-shrinkwrap.json, lockfile v1 through v3. */
function checkNpmLockfile(path, content) {
  const findings = [];
  const parsed = safeJsonParse(content);
  if (!parsed.ok || typeof parsed.value !== "object" || parsed.value === null || Array.isArray(parsed.value)) {
    findings.push({
      id: "unparseable-lockfile",
      severity: "low",
      file: path,
      line: null,
      snippet: redactSnippet(content.slice(0, 120)),
      why: "This lockfile is not valid JSON, which is unusual for a working project and prevents checking where its dependencies come from.",
      next: "Treat the dependency tree as unreviewed; do not install without regenerating the lockfile yourself.",
    });
    return findings;
  }

  // v2 and v3 carry a flat `packages` map; v1 carries a nested
  // `dependencies` tree. A v1 lockfile is a hand-written evasion otherwise.
  const entries = parsed.value.packages
    ? Object.entries(parsed.value.packages)
    : flattenV1Dependencies(parsed.value.dependencies);
  const declared = declaredNames(entries);
  const seenNames = new Set();
  for (const [pkgPath, info] of entries) {
    if (!pkgPath || typeof info !== "object" || info === null) continue; // "" is the root project
    // String(): every other field here is type-guarded, and a lockfile is
    // written by whoever wrote the repository. A number or an object here used
    // to reach .toLowerCase() and abort the entire scan.
    const name = String(info.name ?? pkgPath.split("node_modules/").pop() ?? "");

    // A workspace link or a local path is not a download. npm marks a
    // workspace with link:true and a scheme-less relative "resolved" (for
    // example "packages/web"), which is a directory inside this repository
    // and therefore already covered by the rest of the scan. Treating those
    // as off-registry fetches would fire on every monorepo.
    const resolved = typeof info.resolved === "string" ? info.resolved : "";
    const isLocal = info.link === true || resolved.startsWith("file:") || !/^[a-z][a-z0-9+.-]*:/i.test(resolved);
    if (resolved.length > 0 && !isLocal) {
      const host = hostOf(resolved);
      const isRegistry = host !== null && isRegistryHost(host) && resolved.startsWith("https://");
      if (!isRegistry) {
        findings.push(offRegistryFinding(path, findLine(content, resolved), name, resolved));
      }
    }

    if (info.hasInstallScript === true && !isKnownInstallScriptPackage(name)) {
      // Something in the tree asked for this package, so it is part of what
      // the project depends on: native builds are full of install scripts,
      // the list of them can never be complete, and the author usually does
      // not know the package is there. A package nothing in the lockfile
      // declares is the other thing entirely, and the one the campaigns use.
      const orphan = !declared.has(name);
      findings.push({
        id: "transitive-install-script",
        severity: orphan ? "medium" : "low",
        file: path,
        line: findLine(content, `node_modules/${name}`),
        snippet: `${name} (hasInstallScript: true)`,
        why: orphan
          ? `The dependency "${name}" declares an install script, so its code runs automatically during npm install, and nothing else in this lockfile asks for it. A package no dependency declares, that still runs on install, is how a poisoned lockfile plants code.`
          : `The dependency "${name}" declares an install script, so its code runs automatically during npm install even though nothing in this repository visibly mentions it. Another package in the tree does depend on it, and native builds legitimately need install scripts, so this is reported for your information.`,
        next: `Look up "${name}" on npmjs.com and read its install script before installing this project.`,
      });
    }

    // Only the exact known-malicious list runs against transitive names. The
    // one-edit lookalike check stays on direct dependencies: large trees
    // legitimately contain names one edit apart (xtend and extend, color and
    // colors).
    if (!seenNames.has(name) && KNOWN_MALICIOUS_PACKAGES.has(name.toLowerCase())) {
      seenNames.add(name);
      findings.push({
        id: "known-malicious-package",
        severity: "high",
        file: path,
        line: findLine(content, `node_modules/${name}`),
        snippet: `${name}@${info.version ?? "?"} (from lockfile)`,
        why: `The lockfile installs "${name}", a package name confirmed malicious in fake-interview malware campaigns. It may be buried several dependencies deep, but npm install still runs it.`,
        next: "Do not run npm install. Report the repository to GitHub at https://github.com/contact/report-abuse.",
      });
    }
  }
  return findings;
}

/** yarn.lock, classic (v1) and berry formats, parsed line by line. */
function checkYarnLockfile(path, content) {
  const findings = [];
  const lines = content.split("\n");
  let currentName = "unknown";
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    // Entry headers look like: "pkg@^1.0.0", pkg@npm:1.0.0: or "@scope/pkg@...":
    const header = line.match(/^"?(@?[^\s@"]+)@/);
    if (header && !line.startsWith(" ")) currentName = header[1];

    const resolved =
      line.match(/^\s+resolved\s+"([^"]+)"/) ?? line.match(/^\s+resolution:\s+"[^"]*?@(https?:[^"]+|git(\+[a-z]+:|:|@)[^"]+)"/);
    if (resolved) {
      const url = resolved[1];
      if (/^https?:/.test(url)) {
        const host = hostOf(url);
        const isRegistry = host !== null && isRegistryHost(host) && url.startsWith("https://");
        if (!isRegistry) findings.push(offRegistryFinding(path, i + 1, currentName, url));
      } else if (/^git/.test(url)) {
        findings.push(offRegistryFinding(path, i + 1, currentName, url));
      }
    }
  }
  return findings;
}

/** pnpm-lock.yaml, parsed line by line rather than as YAML. */
function checkPnpmLockfile(path, content) {
  const findings = [];
  const lines = content.split("\n");
  let currentName = "unknown";
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    // An entry header at two-space indent: /name@1.0.0:, name@1.0.0(peer):,
    // '@scope/name@1.0.0':, or name@https://host/x.tgz: for a URL package.
    const entry = line.match(/^\s{2}'?(\/?@?[^\s'@:]+(?:@[^\s':]*)?)'?:/);
    if (entry) currentName = entry[1].replace(/^\//, "").replace(/(.)@.*$/, "$1");

    // pnpm 6 and later write the resolution as an inline map,
    // {integrity: ..., tarball: ...} or {commit: ..., repo: ..., type: git},
    // so the keys are matched anywhere in the line rather than at its start.
    const tarball = line.match(/\btarball:\s*['"]?(https?:[^\s'",}]+)/);
    if (tarball) {
      const host = hostOf(tarball[1]);
      const isRegistry = host !== null && isRegistryHost(host) && tarball[1].startsWith("https://");
      if (!isRegistry) findings.push(offRegistryFinding(path, i + 1, currentName, tarball[1]));
    }
    const gitRepo = line.match(/\brepo:\s*['"]?([^\s'",}]+)/);
    if (gitRepo) {
      findings.push(offRegistryFinding(path, i + 1, currentName, `git+${gitRepo[1]}`));
    }
  }
  return findings;
}

/**
 * A plain-http registry URL is a property of the lockfile's age, not of any
 * one entry, so the note is reported once however many entries carry it.
 */
function onePerLockfile(findings) {
  let seen = false;
  return findings.filter((f) => {
    if (f.id !== "lockfile-insecure-registry-url") return true;
    if (seen) return false;
    seen = true;
    return true;
  });
}

/** Route a lockfile to its checker by filename; empty array for other files. */
export function checkLockfile(path, content) {
  const base = path.split("/").pop();
  if (base === "package-lock.json" || base === "npm-shrinkwrap.json") {
    return onePerLockfile(checkNpmLockfile(path, content));
  }
  if (base === "yarn.lock") return onePerLockfile(checkYarnLockfile(path, content));
  if (base === "pnpm-lock.yaml") return onePerLockfile(checkPnpmLockfile(path, content));
  return [];
}
