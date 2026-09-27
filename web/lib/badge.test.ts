/**
 * The badge's words are part of the contract: green never reads as safe,
 * and a scan that could not run is never green.
 */

import test from "node:test";
import assert from "node:assert/strict";
import {
  BADGE_MAX_SCANS,
  BADGE_WINDOW_MS,
  badgeFor,
  createBadgeBudget,
  createVerdictCache,
  renderBadge,
  VERDICT_TTL_MS,
} from "./badge.ts";

test("every state has its own message and green never says safe", () => {
  const states = ["red", "yellow", "green", "unavailable"] as const;
  const messages = new Set(states.map((s) => badgeFor(s).message));
  assert.equal(messages.size, states.length);
  assert.doesNotMatch(badgeFor("green").message, /safe/i);
  assert.equal(badgeFor("red").message, "do not run");
  assert.notEqual(badgeFor("unavailable").color, badgeFor("green").color);
});

test("the SVG is self-contained and carries the verdict as text", () => {
  const svg = renderBadge(badgeFor("red"));
  assert.ok(svg.startsWith("<svg "));
  assert.ok(svg.endsWith("</svg>"));
  assert.match(svg, /<title>repocanary: do not run<\/title>/);
  assert.match(svg, /aria-label="repocanary: do not run"/);
  assert.doesNotMatch(svg, /<script|href=|url\((?!#)/, "no scripts, no links, no external fetches");
});

test("text in the badge is escaped for XML", () => {
  const svg = renderBadge({ label: "a<b", message: 'x"&y', color: "#000" });
  assert.doesNotMatch(svg, /a<b/);
  assert.match(svg, /a&lt;b/);
  assert.match(svg, /x&quot;&amp;y/);
});

test("the badge budget refuses once the window is spent and recovers after it", () => {
  let at = 1_700_000_000_000;
  const budget = createBadgeBudget(() => at);
  for (let i = 0; i < BADGE_MAX_SCANS; i++) assert.equal(budget.take(), true, `scan ${i + 1}`);
  assert.equal(budget.take(), false);
  at += BADGE_WINDOW_MS;
  assert.equal(budget.take(), true);
});

test("a verdict is cached for a day; unavailable is never cached", () => {
  let at = 1_700_000_000_000;
  const cache = createVerdictCache(() => at);
  cache.set("a/b", "red");
  assert.equal(cache.get("a/b"), "red");
  at += VERDICT_TTL_MS - 1;
  assert.equal(cache.get("a/b"), "red");
  at += 1;
  assert.equal(cache.get("a/b"), undefined);
  cache.set("c/d", "unavailable");
  assert.equal(cache.get("c/d"), undefined);
  assert.equal(cache.size(), 0);
});

test("the verdict cache evicts its oldest entry at the cap", () => {
  const cache = createVerdictCache(Date.now, 2);
  cache.set("one", "green");
  cache.set("two", "green");
  cache.set("three", "yellow");
  assert.equal(cache.size(), 2);
  assert.equal(cache.get("one"), undefined);
  assert.equal(cache.get("three"), "yellow");
});
