import "./helpers.js";
import test from "node:test";
import assert from "node:assert/strict";
import { checkLockfile } from "../src/lockfile.js";

function npmLock(packages) {
  return JSON.stringify({ name: "x", version: "1.0.0", lockfileVersion: 3, packages }, null, 2);
}

const registryEntry = (name, version) => ({
  version,
  resolved: `https://registry.npmjs.org/${name}/-/${name}-${version}.tgz`,
  integrity: "sha512-abc",
});

test("REGRESSION: cnpm's own hosts are registry mirrors like npmmirror", () => {
  // LeetCode-OpenSource/vscode-leetcode resolves every package from
  // r.cnpmjs.org, the mirror that predates npmmirror, and turned red for it.
  const lock = JSON.stringify({
    lockfileVersion: 3,
    packages: {
      "node_modules/axios": { version: "1.6.8", resolved: "https://r.cnpmjs.org/axios/-/axios-1.6.8.tgz", integrity: "sha512-x" },
    },
  });
  assert.equal(checkLockfile("package-lock.json", lock).filter((f) => f.id === "lockfile-off-registry").length, 0);

  // The numbered replicas of the same mirror count too, without listing each.
  const r2 = JSON.stringify({
    lockfileVersion: 3,
    packages: { "node_modules/a": { version: "1.0.0", resolved: "https://r2.cnpmjs.org/a/-/a.tgz", integrity: "sha512-x" } },
  });
  assert.equal(checkLockfile("package-lock.json", r2).filter((f) => f.id === "lockfile-off-registry").length, 0);

  // The suffix is matched on a dot, so a lookalike is a different host.
  for (const host of ["evil-cnpmjs.org", "cnpmjs.org.attacker.net"]) {
    const fake = JSON.stringify({
      lockfileVersion: 3,
      packages: { "node_modules/a": { version: "1.0.0", resolved: `https://${host}/a/-/a.tgz`, integrity: "sha512-x" } },
    });
    assert.ok(
      checkLockfile("package-lock.json", fake).some((f) => f.id === "lockfile-off-registry"),
      `${host} must not pass as a mirror`,
    );
  }

  // A host that is not a mirror still convicts.
  const evil = JSON.stringify({
    lockfileVersion: 3,
    packages: {
      "node_modules/axios": { version: "1.6.8", resolved: "https://cdn.evil.dev/axios.tgz", integrity: "sha512-x" },
    },
  });
  assert.ok(checkLockfile("package-lock.json", evil).some((f) => f.id === "lockfile-off-registry"));
});

test("registry-resolved packages produce no findings", () => {
  const lock = npmLock({
    "": { name: "x", version: "1.0.0" },
    "node_modules/express": registryEntry("express", "4.18.2"),
    "node_modules/lodash": registryEntry("lodash", "4.17.21"),
  });
  assert.deepEqual(checkLockfile("package-lock.json", lock), []);
});

test("a dependency resolved to an off-registry tarball fires high", () => {
  const lock = npmLock({
    "": { name: "x", version: "1.0.0" },
    "node_modules/lodash": {
      version: "4.17.21",
      resolved: "https://cdn.paylods.example/lodash-4.17.21.tgz",
    },
  });
  const findings = checkLockfile("package-lock.json", lock);
  assert.equal(findings.length, 1);
  assert.equal(findings[0].id, "lockfile-off-registry");
  assert.equal(findings[0].severity, "high");
  assert.equal(typeof findings[0].line, "number");
});

test("a plain-http tarball fires high with its own explanation", () => {
  const lock = npmLock({
    "": {},
    "node_modules/lodash": { version: "4.17.21", resolved: "http://mirror.example/lodash.tgz" },
  });
  const findings = checkLockfile("package-lock.json", lock);
  assert.equal(findings[0].id, "lockfile-off-registry");
  assert.ok(findings[0].why.includes("unencrypted"));
});

test("a git-resolved dependency fires medium", () => {
  const lock = npmLock({
    "": {},
    "node_modules/leftpad": { version: "1.0.0", resolved: "git+ssh://git@github.com/someone/leftpad.git#abc123" },
  });
  const findings = checkLockfile("package-lock.json", lock);
  assert.equal(findings[0].id, "lockfile-git-dependency");
  assert.equal(findings[0].severity, "medium");
});

test("an unknown transitive package with an install script fires medium", () => {
  const lock = npmLock({
    "": {},
    "node_modules/totally-normal-utils": {
      ...registryEntry("totally-normal-utils", "2.1.0"),
      hasInstallScript: true,
    },
  });
  const findings = checkLockfile("package-lock.json", lock);
  assert.equal(findings.length, 1);
  assert.equal(findings[0].id, "transitive-install-script");
});

test("packages known to need install scripts (esbuild, sharp) do not fire", () => {
  const lock = npmLock({
    "": {},
    "node_modules/esbuild": { ...registryEntry("esbuild", "0.19.0"), hasInstallScript: true },
    "node_modules/sharp": { ...registryEntry("sharp", "0.33.0"), hasInstallScript: true },
    "node_modules/@esbuild/linux-x64": { ...registryEntry("linux-x64", "0.19.0"), hasInstallScript: true },
  });
  assert.deepEqual(checkLockfile("package-lock.json", lock), []);
});

test("a known-malicious package in the lockfile fires high even transitively", () => {
  const lock = npmLock({
    "": {},
    "node_modules/express/node_modules/loadash": registryEntry("loadash", "0.0.1"),
  });
  const findings = checkLockfile("package-lock.json", lock);
  assert.equal(findings[0].id, "known-malicious-package");
  assert.equal(findings[0].severity, "high");
});

test("an unparseable package-lock.json fires low, not a crash", () => {
  const findings = checkLockfile("package-lock.json", "{ definitely not json");
  assert.equal(findings.length, 1);
  assert.equal(findings[0].id, "unparseable-lockfile");
  assert.equal(findings[0].severity, "low");
});

test("yarn.lock off-registry resolution fires; registry does not", () => {
  const clean = [
    'lodash@^4.17.21:',
    '  version "4.17.21"',
    '  resolved "https://registry.yarnpkg.com/lodash/-/lodash-4.17.21.tgz#abc"',
    '  integrity sha512-xyz',
  ].join("\n");
  assert.deepEqual(checkLockfile("yarn.lock", clean), []);

  const dirty = [
    'lodash@^4.17.21:',
    '  version "4.17.21"',
    '  resolved "https://files.dropbox.example/lodash-4.17.21.tgz"',
  ].join("\n");
  const findings = checkLockfile("yarn.lock", dirty);
  assert.equal(findings.length, 1);
  assert.equal(findings[0].id, "lockfile-off-registry");
  assert.equal(findings[0].line, 3);
  assert.ok(findings[0].snippet.includes("lodash"));
});

test("pnpm-lock.yaml off-registry tarball and git repo fire", () => {
  const dirty = [
    "packages:",
    "  /some-pkg@1.0.0:",
    "    resolution:",
    "      tarball: https://storage.example/some-pkg-1.0.0.tgz",
    "  /other-pkg@2.0.0:",
    "    resolution:",
    "      repo: https://github.com/x/other-pkg.git",
    "      commit: abc123",
  ].join("\n");
  const findings = checkLockfile("pnpm-lock.yaml", dirty);
  assert.equal(findings.length, 2);
  assert.equal(findings[0].id, "lockfile-off-registry");
  assert.equal(findings[1].id, "lockfile-git-dependency");
});

test("pnpm-lock.yaml with registry tarballs is clean", () => {
  const clean = [
    "packages:",
    "  /left-pad@1.3.0:",
    "    resolution:",
    "      tarball: https://registry.npmjs.org/left-pad/-/left-pad-1.3.0.tgz",
  ].join("\n");
  assert.deepEqual(checkLockfile("pnpm-lock.yaml", clean), []);
});

test("non-lockfiles are ignored", () => {
  assert.deepEqual(checkLockfile("src/index.js", "resolved \"http://x\""), []);
});

test("an npm workspace link is not an off-registry download", () => {
  // npm records a workspace as link:true with a scheme-less relative path.
  // Flagging that would fire a high finding on every monorepo.
  const lock = npmLock({
    "": { name: "root", version: "1.0.0", workspaces: ["web"] },
    web: { name: "root-web", version: "1.0.0" },
    "node_modules/root-web": { resolved: "web", link: true },
    "node_modules/express": registryEntry("express", "4.18.2"),
  });
  assert.deepEqual(checkLockfile("package-lock.json", lock), []);
});

test("a scheme-less local path resolution is treated as local, not a fetch", () => {
  const lock = npmLock({
    "": {},
    "node_modules/local-pkg": { version: "1.0.0", resolved: "packages/local-pkg" },
  });
  assert.deepEqual(checkLockfile("package-lock.json", lock), []);
});

test("a real off-registry URL still fires alongside workspace links", () => {
  // The workspace exemption must not swallow an actual remote tarball.
  const lock = npmLock({
    "": { workspaces: ["web"] },
    "node_modules/root-web": { resolved: "web", link: true },
    "node_modules/lodash": { version: "4.17.21", resolved: "https://cdn.evil.example.invalid/lodash.tgz" },
  });
  const findings = checkLockfile("package-lock.json", lock);
  assert.equal(findings.length, 1);
  assert.equal(findings[0].id, "lockfile-off-registry");
  assert.ok(findings[0].snippet.includes("lodash"));
});

test("a lockfile v1 dependency tree is judged, not read as empty", () => {
  const v1 = JSON.stringify({
    lockfileVersion: 1,
    dependencies: {
      lodash: { version: "1.0.0", resolved: "https://cdn.evil.example.invalid/lodash.tgz" },
      outer: {
        version: "2.0.0",
        resolved: "https://registry.npmjs.org/outer/-/outer-2.0.0.tgz",
        dependencies: {
          inner: { version: "1.0.0", resolved: "git+https://github.com/evil/inner.git" },
        },
      },
    },
  });
  const findings = checkLockfile("package-lock.json", v1);
  assert.ok(findings.some((f) => f.id === "lockfile-off-registry" && f.severity === "high"));
  assert.ok(findings.some((f) => f.id === "lockfile-git-dependency"));
});

test("a lockfile v1 install script is judged the same as v3", () => {
  const v1 = JSON.stringify({
    lockfileVersion: 1,
    dependencies: { "some-pkg": { version: "1.0.0", requires: {}, hasInstallScript: true } },
  });
  const findings = checkLockfile("package-lock.json", v1);
  assert.ok(findings.some((f) => f.id === "transitive-install-script"));
});

test("a lockfile whose body is a JSON array is reported, not ignored", () => {
  const findings = checkLockfile("package-lock.json", "[1,2,3]");
  assert.equal(findings.length, 1);
  assert.equal(findings[0].id, "unparseable-lockfile");
});

test("a plain-http URL to the official registry is a low note, reported once per lockfile", () => {
  // Old npm wrote http://registry.npmjs.org into lockfiles; lodash still
  // carries dozens of them. The integrity hash is what the installer checks.
  const v1 = JSON.stringify({
    lockfileVersion: 1,
    dependencies: {
      a: { version: "1.0.0", resolved: "http://registry.npmjs.org/a/-/a-1.0.0.tgz", integrity: "sha1-x" },
      b: { version: "1.0.0", resolved: "http://registry.npmjs.org/b/-/b-1.0.0.tgz", integrity: "sha1-y" },
      c: { version: "1.0.0", resolved: "http://registry.yarnpkg.com/c/-/c-1.0.0.tgz", integrity: "sha1-z" },
    },
  });
  const findings = checkLockfile("package-lock.json", v1);
  assert.equal(findings.length, 1);
  assert.equal(findings[0].id, "lockfile-insecure-registry-url");
  assert.equal(findings[0].severity, "low");
});

test("a plain-http URL to any other host is still an off-registry high", () => {
  const lock = npmLock({
    "": {},
    "node_modules/lodash": { version: "4.17.21", resolved: "http://registry.npmjs.org.evil.example.invalid/lodash.tgz" },
  });
  const findings = checkLockfile("package-lock.json", lock);
  assert.equal(findings[0].id, "lockfile-off-registry");
  assert.equal(findings[0].severity, "high");
});

test("pnpm v9 inline resolution maps are judged: tarball, git repo, and registry integrity", () => {
  const lock = [
    "lockfileVersion: '9.0'",
    "packages:",
    "  lodash@4.17.21:",
    "    resolution: {integrity: sha512-abc}",
    "  '@scope/thing@1.0.0':",
    "    resolution: {tarball: https://storage.example.invalid/thing-1.0.0.tgz}",
    "  gitdep@1.2.3:",
    "    resolution: {commit: abc123, repo: https://github.com/x/gitdep.git, type: git}",
    "  react@18.2.0(patch_hash=xyz):",
    "    resolution: {integrity: sha512-def}",
  ].join("\n");
  const findings = checkLockfile("pnpm-lock.yaml", lock);
  assert.deepEqual(
    findings.map((f) => [f.id, f.line]),
    [
      ["lockfile-off-registry", 6],
      ["lockfile-git-dependency", 8],
    ],
  );
  assert.match(findings[0].snippet, /^@scope\/thing -> https:\/\/storage\.example\.invalid\/thing-1\.0\.0\.tgz$/);
  assert.match(findings[1].snippet, /^gitdep -> /);
});

test("yarn berry resolutions are judged: npm, patch and workspace are clean, a URL or git is not", () => {
  const lock = [
    '"@scope/pkg@npm:^1.0.0, @scope/pkg@npm:^1.2.0":',
    '  resolution: "@scope/pkg@npm:1.2.3"',
    '"typescript@patch:typescript@npm%3A5.3.3#optional!builtin<compat/typescript>":',
    '  resolution: "typescript@patch:typescript@npm%3A5.3.3#optional!builtin<compat/typescript>::version=5.3.3&hash=e012d7"',
    '"app@workspace:packages/app":',
    '  resolution: "app@workspace:packages/app"',
    '"evil-lib@https://cdn.example.invalid/evil-lib.tgz":',
    '  resolution: "evil-lib@https://cdn.example.invalid/evil-lib.tgz"',
    '"@acme/gitdep@https://github.com/acme/gitdep.git#commit=abc":',
    '  resolution: "@acme/gitdep@https://github.com/acme/gitdep.git#commit=abc"',
  ].join("\n");
  const findings = checkLockfile("yarn.lock", lock);
  assert.deepEqual(
    findings.map((f) => [f.id, f.line]),
    [
      ["lockfile-off-registry", 8],
      ["lockfile-git-dependency", 10],
    ],
  );
  assert.match(findings[0].snippet, /^evil-lib -> /);
  assert.match(findings[1].snippet, /^@acme\/gitdep -> /);
});
