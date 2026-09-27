/**
 * Golden report tests: the rendered output of fixed fixtures is compared
 * byte for byte against checked-in golden files. Any change to report
 * wording or structure shows up as a diff here, on purpose.
 *
 * To regenerate after an intentional change:
 *   UPDATE_GOLDEN=1 node --test test/golden.test.js
 */

import { scanFixture, TEST_DIR } from "./helpers.js";
import test from "node:test";
import assert from "node:assert/strict";
import { mkdirSync, readFileSync, writeFileSync, existsSync } from "node:fs";
import { join } from "node:path";
import { renderHuman, renderJson, renderSarif } from "../src/report.js";

const GOLDEN_DIR = join(TEST_DIR, "golden");
const UPDATE = process.env.UPDATE_GOLDEN === "1";

async function checkGolden(fixtureName, renderName, render) {
  const { result } = await scanFixture(fixtureName);
  const actual = render(result);
  const goldenPath = join(GOLDEN_DIR, `${fixtureName}.${renderName}`);
  if (UPDATE) {
    mkdirSync(GOLDEN_DIR, { recursive: true });
    writeFileSync(goldenPath, actual);
    return;
  }
  // A missing baseline used to be written from current behaviour and pass,
  // which makes whatever the code does today correct by definition and is
  // the one thing a snapshot test must not do. Creating one is deliberate.
  assert.ok(
    existsSync(goldenPath),
    `Missing golden ${goldenPath}. Run UPDATE_GOLDEN=1 npm test to create it deliberately.`,
  );
  assert.equal(actual, readFileSync(goldenPath, "utf8"), `${goldenPath} differs; regenerate with UPDATE_GOLDEN=1 if intended`);
}

// context-signals carries a repository-level finding, whose line is null and
// whose file SARIF has to rewrite. Nothing else pins that pair of branches.
for (const fixture of ["postinstall-curl-pipe", "benign-node", "typosquat-lookalike", "context-signals"]) {
  test(`golden human report: ${fixture}`, () => checkGolden(fixture, "human.txt", renderHuman));
  test(`golden json report: ${fixture}`, () => checkGolden(fixture, "json", renderJson));
  test(`golden sarif report: ${fixture}`, () => checkGolden(fixture, "sarif", renderSarif));
}
