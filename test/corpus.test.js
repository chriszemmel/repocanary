/**
 * The corpus test: a set of small fixture repositories, some benign and some
 * carrying each attack pattern, with the expected verdict asserted for every
 * one. This is the tool's false-positive and false-negative regression net:
 * a rule change that convicts a benign fixture or clears a malicious one
 * fails here immediately.
 */

import { listFixtures, scanFixture } from "./helpers.js";
import test from "node:test";
import assert from "node:assert/strict";

const fixtures = listFixtures();

test("the corpus is not empty and covers all three verdicts", async () => {
  assert.ok(fixtures.length >= 25);
  const verdicts = new Set();
  for (const name of fixtures) {
    const { expected } = await scanFixture(name);
    verdicts.add(expected.verdict);
  }
  assert.deepEqual([...verdicts].sort(), ["green", "red", "yellow"]);
});

for (const name of fixtures) {
  test(`corpus: ${name}`, async () => {
    const { result, expected } = await scanFixture(name);
    const fired = result.findings.map((f) => f.id);

    assert.equal(
      result.verdict,
      expected.verdict,
      `expected ${expected.verdict}, got ${result.verdict}. Findings: ${JSON.stringify(
        result.findings.map((f) => `${f.severity}:${f.id}@${f.file}`),
        null,
        2,
      )}`,
    );
    for (const id of expected.mustFire ?? []) {
      assert.ok(fired.includes(id), `expected rule "${id}" to fire; fired: ${fired.join(", ") || "(none)"}`);
    }
    for (const id of expected.mustNotFire ?? []) {
      assert.ok(!fired.includes(id), `rule "${id}" must not fire on this fixture`);
    }

    // Explainability: every finding must carry a location, a reason a
    // non-expert can read, and a concrete next step.
    for (const f of result.findings) {
      assert.ok(f.id, "finding id");
      assert.ok(["high", "medium", "low"].includes(f.severity), "severity");
      assert.ok(f.file, "file");
      assert.ok(f.why && f.why.length > 40, `why for ${f.id} must actually explain`);
      assert.ok(f.next && f.next.length > 10, `next step for ${f.id}`);
      assert.ok(f.snippet.length <= 220, `snippet for ${f.id} must stay redacted and short`);
    }
  });
}
