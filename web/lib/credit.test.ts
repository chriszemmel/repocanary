import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";

// The footer names who built RepoCanary and links to his canonical page on
// zyric.de. That is the visible, human-readable half of tying this site to
// the person; the structured data points the same way.
test("the shared footer credits Chris Zemmel and links to zyric.de/about", () => {
  const src = readFileSync(new URL("../components/LegalLinks.tsx", import.meta.url), "utf8");
  assert.match(src, /href="https:\/\/zyric\.de\/about"/);
  assert.match(src, /Chris Zemmel/);
  assert.match(src, /rel="author"/);
});
