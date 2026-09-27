import "./helpers.js";
import test from "node:test";
import assert from "node:assert/strict";
import { checkDependencyName, damerauDistance, nearestPopularPackage } from "../src/typosquat.js";

const ctx = { file: "package.json", line: 3, version: "^1.0.0" };

test("damerauDistance counts substitution, deletion, insertion, transposition", () => {
  assert.equal(damerauDistance("lodash", "lodash"), 0);
  assert.equal(damerauDistance("lodash", "lodasg"), 1); // substitution
  assert.equal(damerauDistance("lodash", "lodas"), 1); // deletion
  assert.equal(damerauDistance("lodash", "lodashh"), 1); // insertion
  assert.equal(damerauDistance("lodash", "lodsah"), 1); // transposition
  assert.equal(damerauDistance("lodash", "react", 2), 3); // bailed out at max+1
});

test("a known malicious package name fires high", () => {
  const findings = checkDependencyName("axois", ctx);
  assert.equal(findings.length, 1);
  assert.equal(findings[0].id, "known-malicious-package");
  assert.equal(findings[0].severity, "high");
});

test("a one-edit lookalike of a popular package fires medium", () => {
  const findings = checkDependencyName("lodasg", ctx);
  assert.equal(findings.length, 1);
  assert.equal(findings[0].id, "typosquat-dependency");
  assert.equal(findings[0].severity, "medium");
  assert.ok(findings[0].why.includes("lodash"));
});

test("scope confusion (@typs imitating @types) is a caution", () => {
  const findings = checkDependencyName("@typs/node", ctx);
  assert.equal(findings.length, 1);
  assert.equal(findings[0].id, "scope-confusion");
  assert.equal(findings[0].severity, "medium");
});

test("popular packages themselves never fire", () => {
  for (const name of ["react", "lodash", "express", "vite", "color", "xtend"]) {
    assert.deepEqual(checkDependencyName(name, ctx), [], name);
  }
});

test("a known scope with an ordinary package never fires", () => {
  assert.deepEqual(checkDependencyName("@types/node", ctx), []);
  assert.deepEqual(checkDependencyName("@babel/core", ctx), []);
});

test("short names are exempt from the lookalike check", () => {
  assert.deepEqual(checkDependencyName("gt", ctx), []);
  assert.equal(nearestPopularPackage("ws"), null);
});

test("an unrelated ordinary name never fires", () => {
  assert.deepEqual(checkDependencyName("left-pad-utils", ctx), []);
  assert.deepEqual(checkDependencyName("my-company-sdk", ctx), []);
});

test("clsx is not flagged as imitating xlsx", () => {
  assert.deepEqual(checkDependencyName("clsx", ctx), []);
  assert.equal(nearestPopularPackage("clsx"), null);
});

test("a scope differing at its first letter is not scope confusion", () => {
  assert.deepEqual(checkDependencyName("@clack/prompts", ctx), []);
});

test("a lookalike must share the target's first letter", () => {
  assert.equal(nearestPopularPackage("xodash"), null);
  assert.equal(nearestPopularPackage("aeact"), null);
  // Same distance, same first character: the real squat shape.
  assert.equal(nearestPopularPackage("lodasg"), "lodash");
  assert.equal(nearestPopularPackage("expres"), "express");
});

test("every documented malicious name still resolves to its target", () => {
  // Each of these keeps its target's first letter, which is why the
  // first-letter rule still catches it. Each of
  // these is a confirmed campaign package that keeps its target's first
  // letter, which is exactly why it fools people.
  for (const [squat, target] of [
    ["loadash", "lodash"],
    ["lodahs", "lodash"],
    ["electorn", "electron"],
    ["expresss", "express"],
    ["axois", "axios"],
    ["mongose", "mongoose"],
    ["dotevn", "dotenv"],
  ]) {
    assert.equal(nearestPopularPackage(squat), target, squat);
  }
});

test("frontend staples are not flagged against each other", () => {
  for (const name of ["clsx", "swr", "sonner", "cmdk", "vaul", "recharts", "next-auth", "next-themes"]) {
    assert.deepEqual(checkDependencyName(name, ctx), [], name);
  }
});

test("a trailing-digit version alias is informational, not a typosquat caution", () => {
  // zod3 (zod's own v3 dev dep), cli-table3 (a real fork), chalk4: version
  // conventions, not disguises, so they must not raise a caution against
  // zod/cli-table/chalk. They are not cleared either: axios2 and react2 read
  // the same way, and an attacker registers exactly those, so the lookalike
  // is reported for information and corroboration can still raise it.
  assert.equal(nearestPopularPackage("zod3"), "zod");
  assert.equal(nearestPopularPackage("chalk4"), "chalk");
  assert.equal(checkDependencyName("zod3", ctx)[0]?.severity, "low");
  assert.equal(checkDependencyName("axios2", ctx)[0]?.severity, "low");
  assert.match(checkDependencyName("axios2", ctx)[0].why, /version number attached/);
  // But a lookalike that merely happens to end in a digit is still caught
  // when stripping the digit does not land on a popular name.
  assert.equal(nearestPopularPackage("lodasg"), "lodash");
});

/**
 * Real, widely used npm names that sit one edit from another popular name.
 * Each of these once produced a caution, and @nuxtjs produced a red verdict
 * on an ordinary Nuxt project, because the scope list carried @nextjs, which
 * is not a real npm scope.
 */
const REAL_PACKAGES = [
  "vuex",
  "object.assign",
  "aws-cdk",
  "mssql",
  "jsdoc",
  "nano",
  "tarn",
  "core-js",
  "semver",
  "got",
  "less",
  "tar",
  "nan",
  "clsx",
  "knex",
];

for (const name of REAL_PACKAGES) {
  test(`a real package is not called a squat: ${name}`, () => {
    assert.deepEqual(checkDependencyName(name, ctx), []);
  });
}

const REAL_SCOPES = [
  "@nuxtjs/tailwindcss",
  "@nuxt/kit",
  "@mux/mux-player",
  "@mui/material",
  "@next/font",
  "@vercel/analytics",
  "@astrojs/react",
];

for (const name of REAL_SCOPES) {
  test(`a real scope is not scope confusion: ${name}`, () => {
    assert.deepEqual(checkDependencyName(name, ctx), []);
  });
}

test("a scope imitating a real one is still caught", () => {
  for (const name of ["@nextjs/core", "@mni/material", "@typcs/node"]) {
    const findings = checkDependencyName(name, ctx);
    assert.equal(findings[0]?.id, "scope-confusion", name);
  }
});

test("a package npm has replaced with a security holding package is known malicious", () => {
  const found = checkDependencyName("main-util-validation", { file: "package.json", version: "^1.0.1" });
  assert.equal(found[0]?.id, "known-malicious-package");
  assert.equal(found[0]?.severity, "high");
});
