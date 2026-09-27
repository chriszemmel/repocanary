/**
 * Typosquat detection for dependency names.
 *
 * Three layers, most precise first:
 *   1. An embedded list of package names confirmed malicious in fake-interview
 *      campaigns. An exact match is red.
 *   2. Scope confusion: a scope one edit away from a well-known npm scope
 *      (like @typcs instead of @types). Scopes are namespaces people trust
 *      blindly, so a spoofed scope is red.
 *   3. One-edit lookalikes of an embedded list of the most-downloaded npm
 *      packages. Real packages can innocently sit one edit from a big name,
 *      so this alone is only yellow.
 *
 * The popular list is embedded, not fetched, so the check is deterministic,
 * offline, and cannot be poisoned at scan time.
 */

/** Package names confirmed malicious in these campaigns. Exact matches only.
 * Sources: Socket.dev "Contagious Interview" advisories, Lazarus npm writeups,
 * and classic dropper packages. */
export const KNOWN_MALICIOUS_PACKAGES = new Set([
  "require",
  "crossenv",
  "cross-env.js",
  "loadash",
  "lodahs",
  "electorn",
  "expresss",
  "axois",
  "mongose",
  "reactt",
  "babelcli",
  "node-fetchs",
  "node-fetch2",
  "web3-essential",
  "ethers-provider2",
  "ethers-providerz",
  "solana-web3js",
  "discordjs-api",
  // "colors-cli" was here until 2026-09-06 and was wrong. The malicious
  // series is "colors-XX", typosquats of "colors" carrying a token stealer.
  // colors-cli is a real, maintained package by a named author, and listing
  // it turned every lockfile containing it red: zabbix, in a blind batch.
  // An exact-match list is an accusation, so an entry needs a source that
  // names the package, not one that names something adjacent to it.
  "sync-request-legacy",
  // npm replaced this with its 0.0.1-security holding package, which is how
  // the registry itself records a package removed as malware. Found in wave
  // 16 as a dependency of HZCX404/memecoin-trading-bots, beside an
  // obfuscated loader hidden after 382 spaces on the first line of a file
  // that `npm start` runs.
  "main-util-validation",
  "node-nvm-ssh",
  "passports-js",
  "bcrypts-js",
  "blockscan-api",
  "metamask-api",
  "react-router-html",
  "react-redirect-router",
  "vite-plugin-react-ping",
  "vvite-plugin-react",
  "webpack-css-branch-loader",
  "nodemailer-helper",
  "nodemon-pkg",
  "http-helmet",
  "morgan-logger",
  "dotevn",
  "boby-parser",
  "boby_parser",
  "vaildator",
  "truffel",
  "ganacche",
  "foudry",
  "epxres",
  "epxreso",
  "we3.js",
  "wb3.js",
  "ethres.js",
  "ethes.js",
]);

/**
 * The most-downloaded npm packages plus the staple tooling of frontend and
 * crypto projects, which is what these lures imitate. Comparison targets for
 * the one-edit check; membership in this list also clears a name.
 */
export const POPULAR_PACKAGES = [
  "lodash", "lodash-es", "react", "react-dom", "chalk", "commander", "express", "axios",
  "tslib", "inherits", "semver", "debug", "moment", "prop-types", "classnames",
  "uuid", "vue", "rxjs", "yargs", "glob", "minimist", "colors", "dotenv",
  "bluebird", "webpack", "babel-core", "typescript", "eslint", "prettier",
  "jest", "mocha", "chai", "sinon", "supertest", "nodemon", "concurrently",
  "rimraf", "mkdirp", "fs-extra", "path-to-regexp", "qs", "body-parser",
  "cookie-parser", "cors", "helmet", "morgan", "compression", "multer",
  "jsonwebtoken", "bcrypt", "bcryptjs", "passport", "mongoose", "sequelize",
  "knex", "pg", "mysql", "mysql2", "sqlite3", "redis", "ioredis", "mongodb",
  "socket.io", "ws", "node-fetch", "request", "superagent", "got", "undici",
  "cheerio", "puppeteer", "playwright", "selenium-webdriver", "jsdom",
  "next", "nuxt", "gatsby", "svelte", "solid-js", "preact", "angular",
  "vite", "rollup", "esbuild", "parcel", "browserify", "gulp", "grunt",
  "tailwindcss", "postcss", "autoprefixer", "sass", "less", "styled-components",
  "emotion", "bootstrap", "jquery", "d3", "three", "chart.js", "leaflet",
  "redux", "react-redux", "react-router", "react-router-dom", "react-query",
  "zustand", "mobx", "immer", "reselect", "formik", "react-hook-form", "yup",
  "zod", "joi", "ajv", "validator", "date-fns", "dayjs", "luxon", "ms",
  "nanoid", "shortid", "slugify", "marked", "markdown-it", "highlight.js",
  "prismjs", "dompurify", "sanitize-html", "he", "entities", "iconv-lite",
  "form-data", "mime", "mime-types", "content-type", "raw-body", "send",
  "serve-static", "connect", "koa", "fastify", "hapi", "restify", "nest",
  "electron", "electron-builder", "cross-env", "env-cmd", "husky",
  "lint-staged", "standard", "xo", "np", "release-it", "semantic-release",
  "ts-node", "tsx", "ts-jest", "babel-jest", "babel-loader", "css-loader",
  "style-loader", "file-loader", "url-loader", "html-webpack-plugin",
  "webpack-cli", "webpack-dev-server", "core-js", "regenerator-runtime",
  "object-assign", "extend", "deepmerge", "clone", "shallowequal",
  "fast-deep-equal", "json5", "js-yaml", "yaml", "toml", "ini", "xml2js",
  "csv-parse", "csv-parser", "papaparse", "xlsx", "pdfkit", "sharp", "jimp", "canvas",
  "ffmpeg-static", "fluent-ffmpeg", "archiver", "unzipper", "adm-zip", "tar",
  "node-gyp", "prebuild-install", "node-pre-gyp", "bindings", "nan",
  "node-addon-api", "open", "opn", "execa", "shelljs", "cross-spawn",
  "which", "find-up", "read-pkg", "pkg-dir", "cosmiconfig", "inquirer",
  "prompts", "enquirer", "ora", "listr", "boxen", "figlet", "cli-table",
  "cli-progress", "progress", "log-symbols", "signale", "winston", "pino",
  "bunyan", "log4js", "loglevel", "eventemitter3", "mitt", "p-queue",
  "p-limit", "p-retry", "p-map", "async", "neo-async", "promise", "q",
  "co", "generic-pool", "lru-cache", "quick-lru", "node-cache", "keyv",
  "memoizee", "throttle-debounce", "web3", "ethers", "hardhat", "truffle",
  "ganache", "foundry-rs", "@solana/web3.js", "bitcoinjs-lib", "bip39",
  "ethereumjs-util", "solc", "openzeppelin-solidity", "wagmi", "viem",
  "discord.js", "telegraf", "node-telegram-bot-api", "twit", "openai",
  "stripe", "twilio", "nodemailer", "aws-sdk", "firebase", "firebase-admin",
  "graphql", "apollo-server", "relay-runtime", "urql", "prisma", "typeorm",
  "drizzle-orm", "vitest", "cypress", "storybook", "expo", "react-native",
  "ionic", "cordova", "capacitor", "pm2", "forever", "serve", "http-server",
  "json-server", "express-session",
  // Not top downloads themselves, but real, widely used packages sitting one
  // edit from a name above; listing them keeps them from being flagged.
  "color", "colord", "xtend", "inherit", "yazl", "yauzl", "mqtt",
  // Staples of the modern frontend stack these lures imitate. Missing
  // entries here are what cause false positives: a real package is only
  // flagged when it is absent from this list and one edit from a name on it.
  "clsx", "tailwind-merge", "class-variance-authority", "lucide-react",
  "framer-motion", "react-icons", "swr", "sonner", "cmdk", "recharts",
  "next-auth", "next-themes", "vaul", "embla-carousel-react", "react-select",
  "react-table", "react-window", "react-virtualized", "downshift", "floating-ui",
  "radix-ui", "headlessui", "heroicons", "tanstack-query", "jotai", "valtio",
  "swiper", "lenis", "gsap", "lottie-react", "qrcode", "jsbarcode",
  "vuex", "object.assign", "aws-cdk", "mssql", "jsdoc", "nano", "tarn",
];

/** Well-known npm scopes people trust as namespaces. */
const POPULAR_SCOPES = [
  "@types", "@babel", "@angular", "@vue", "@aws-sdk", "@azure", "@google-cloud",
  "@typescript-eslint", "@eslint", "@jest", "@testing-library", "@storybook",
  "@emotion", "@mui", "@material-ui", "@chakra-ui", "@radix-ui", "@headlessui",
  "@heroicons", "@fortawesome", "@tailwindcss", "@nestjs", "@next",
  "@sveltejs", "@remix-run", "@tanstack", "@reduxjs", "@apollo", "@graphql",
  "@octokit", "@sentry", "@prisma", "@swc", "@esbuild", "@rollup", "@vitejs",
  "@playwright", "@cypress", "@docusaurus", "@expo", "@react-native",
  "@react-navigation", "@solana", "@ethersproject", "@openzeppelin",
  "@polkadot", "@walletconnect", "@metamask", "@shopify", "@stripe", "@slack",
  "@discordjs", "@actions", "@npmcli", "@commitlint", "@changesets",
  "@opentelemetry", "@smithy", "@firebase", "@supabase", "@trpc", "@clerk",
  "@nuxtjs", "@nuxt", "@mux", "@vercel", "@astrojs", "@sanity", "@datadog",
];

const POPULAR_SET = new Set(POPULAR_PACKAGES);

/** Is this exact name a well-known popular package? */
export function isPopularPackage(name) {
  return POPULAR_SET.has(String(name).toLowerCase());
}
const SCOPE_SET = new Set(POPULAR_SCOPES);

/**
 * Real scopes that sit one keystroke from a popular one. They are neither
 * lookalikes nor targets: listing @mdi as popular made Mozilla's @mdn a
 * lookalike of it and turned esbuild red.
 */
// @vinejs is VineJS, the validation library from the AdonisJS team, one
// keystroke from @vitejs.
const KNOWN_SCOPES = new Set(["@mdi", "@mdn", "@bazel", "@graphiql", "@vinejs"]);

/**
 * Optimal string alignment (Damerau-Levenshtein with adjacent transposition).
 * Bails out early and returns max + 1 when the distance exceeds max.
 */
export function damerauDistance(a, b, max = 2) {
  if (Math.abs(a.length - b.length) > max) return max + 1;
  const rows = a.length + 1;
  const cols = b.length + 1;
  const d = Array.from({ length: rows }, () => new Array(cols).fill(0));
  for (let i = 0; i < rows; i++) d[i][0] = i;
  for (let j = 0; j < cols; j++) d[0][j] = j;
  for (let i = 1; i < rows; i++) {
    let rowMin = Infinity;
    for (let j = 1; j < cols; j++) {
      const cost = a[i - 1] === b[j - 1] ? 0 : 1;
      d[i][j] = Math.min(d[i - 1][j] + 1, d[i][j - 1] + 1, d[i - 1][j - 1] + cost);
      if (i > 1 && j > 1 && a[i - 1] === b[j - 2] && a[i - 2] === b[j - 1]) {
        d[i][j] = Math.min(d[i][j], d[i - 2][j - 2] + 1);
      }
      rowMin = Math.min(rowMin, d[i][j]);
    }
    if (rowMin > max) return max + 1;
  }
  return d[a.length][b.length];
}

/**
 * The popular package one edit away from name, or null.
 *
 * The first character must match: every documented squat in these campaigns
 * keeps the first letter (loadash, axois, dotevn), and a name differing there
 * reads as a different word (clsx against xlsx). Names under four characters
 * are skipped, since they sit one edit from too many real packages.
 */
function isVersionAlias(name) {
  const withoutTrailingDigits = name.replace(/\d+$/, "");
  return withoutTrailingDigits !== name && POPULAR_SET.has(withoutTrailingDigits);
}

export function nearestPopularPackage(name) {
  if (name.length < 4 || POPULAR_SET.has(name)) return null;
  if (isVersionAlias(name)) return name.replace(/\d+$/, "");
  // A trailing-digit alias of a popular name is a version convention, not a
  // squat: zod3, cli-table3, chalk4 read as "version N of X", a visibly
  // different name rather than an identical-looking one. Real maintained
  // forks use exactly this. Only fires when stripping the digits lands on a
  // popular name, so an unrelated name ending in a digit is unaffected.
  // ...but only ever a step down, not a clearance: axios2 and react2 read
  // the same way, and an attacker registers exactly those. The caller
  // reports a version-shaped lookalike as informational.
  for (const popular of POPULAR_PACKAGES) {
    if (popular[0] !== name[0]) continue;
    if (damerauDistance(name, popular, 1) === 1) return popular;
  }
  return null;
}

/**
 * Findings for one dependency name (with the manifest file and line for
 * context). Used for package.json dependencies and lockfile entries alike.
 */
export function checkDependencyName(name, { file, line = null, version = "" }) {
  const findings = [];
  const lower = name.toLowerCase();

  if (KNOWN_MALICIOUS_PACKAGES.has(lower)) {
    findings.push({
      id: "known-malicious-package",
      severity: "high",
      file,
      line,
      snippet: `"${name}": "${version}"`,
      why: `The dependency "${name}" is a package name confirmed malicious in fake-interview malware campaigns. Installing this project would install that package and run its code.`,
      next: "Do not run npm install. Report the repository to GitHub at https://github.com/contact/report-abuse.",
    });
    return findings;
  }

  if (lower.startsWith("@")) {
    const slash = lower.indexOf("/");
    if (slash > 1) {
      const scope = lower.slice(0, slash);
      const base = lower.slice(slash + 1);
      if (!SCOPE_SET.has(scope) && !KNOWN_SCOPES.has(scope)) {
        for (const known of POPULAR_SCOPES) {
          // Same first-letter rule as package names: a scope differing at
          // its opening letter reads as a different word (@clack, @slack).
          if (known[1] !== scope[1]) continue;
          if (damerauDistance(scope, known, 1) === 1) {
            // A caution rather than a conviction: three honest scopes one
            // keystroke from a popular one turned up in 505 repositories,
            // so a lookalike scope alone cannot be the thing only malware has.
            findings.push({
              id: "scope-confusion",
              severity: "medium",
              file,
              line,
              snippet: `"${name}": "${version}"`,
              why: `The dependency "${name}" uses the scope "${scope}", which is one keystroke away from the well-known scope "${known}". Scopes are trusted namespaces; imitating one is a deliberate disguise, not a typo a project would leave in place.`,
              next: `Do not install. Check ${known}/${base} on npmjs.com to see what this is imitating.`,
            });
            break;
          }
        }
      }
      return findings;
    }
  }

  const popular = nearestPopularPackage(lower);
  if (popular) {
    const alias = isVersionAlias(lower);
    findings.push({
      id: "typosquat-dependency",
      severity: alias ? "low" : "medium",
      file,
      line,
      snippet: `"${name}": "${version}"`,
      why: alias
        ? `The dependency "${name}" is the popular package "${popular}" with a version number attached. Real forks are named this way (cli-table3, zod3), and so are lookalikes an attacker registers, so it is reported for your information.`
        : `The dependency "${name}" is one keystroke away from the popular package "${popular}". Attackers publish lookalike names so that a hurried reader sees the name they expect. It could be an unrelated legitimate package, but the resemblance is exactly what typosquatting exploits.`,
      next: `Look up "${name}" on npmjs.com: check its weekly downloads and publish date before trusting it.`,
    });
  }
  return findings;
}
