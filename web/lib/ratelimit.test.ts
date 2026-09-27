/**
 * The window is tested against an injected clock, so ten minutes pass in
 * no time and nothing here depends on Date.now.
 */

import test from "node:test";
import assert from "node:assert/strict";
import {
  clientKey,
  createRateLimiter,
  createScanBudget,
  MAX_BUCKETS,
  MAX_REQUESTS,
  WINDOW_MS,
} from "./ratelimit.ts";

function clock(start = 1_700_000_000_000) {
  let at = start;
  return { now: () => at, advance: (ms: number) => (at += ms) };
}

test("an IP gets MAX_REQUESTS in a window and is refused on the next", () => {
  const c = clock();
  const limiter = createRateLimiter(c.now);
  for (let i = 0; i < MAX_REQUESTS; i++) assert.equal(limiter.check("1.1.1.1"), true, `request ${i + 1}`);
  assert.equal(limiter.check("1.1.1.1"), false);
});

test("the window slides: the oldest request expiring frees exactly one slot", () => {
  const c = clock();
  const limiter = createRateLimiter(c.now);
  limiter.check("1.1.1.1");
  c.advance(1000);
  for (let i = 1; i < MAX_REQUESTS; i++) limiter.check("1.1.1.1");
  assert.equal(limiter.check("1.1.1.1"), false);
  c.advance(WINDOW_MS - 1000);
  assert.equal(limiter.check("1.1.1.1"), true, "the first request has aged out");
  assert.equal(limiter.check("1.1.1.1"), false, "the rest have not");
});

test("a refused request does not extend the caller's own lockout", () => {
  const c = clock();
  const limiter = createRateLimiter(c.now);
  for (let i = 0; i < MAX_REQUESTS; i++) limiter.check("1.1.1.1");
  c.advance(WINDOW_MS - 1);
  assert.equal(limiter.check("1.1.1.1"), false);
  c.advance(1);
  assert.equal(limiter.check("1.1.1.1"), true);
});

test("IPs are independent", () => {
  const limiter = createRateLimiter(clock().now);
  for (let i = 0; i < MAX_REQUESTS; i++) limiter.check("1.1.1.1");
  assert.equal(limiter.check("1.1.1.1"), false);
  assert.equal(limiter.check("2.2.2.2"), true);
});

test("idle buckets are swept once the map grows large", () => {
  const c = clock();
  const limiter = createRateLimiter(c.now);
  for (let i = 0; i < 5001; i++) limiter.check(`10.0.${Math.floor(i / 256)}.${i % 256}`);
  assert.equal(limiter.size(), 5001);
  c.advance(WINDOW_MS);
  limiter.check("fresh");
  assert.equal(limiter.size(), 1, "every expired bucket was dropped, the live one kept");
});

test("the limiter key is the hop we control, never the one the client typed", () => {
  const key = (h: Record<string, string>) => clientKey(new Headers(h));

  // A platform header is set by the platform and cannot be spoofed.
  assert.equal(key({ "x-vercel-forwarded-for": "203.0.113.9" }), "203.0.113.9");

  // Without a trusted hop count, the leftmost X-Forwarded-For value is
  // whatever the caller typed, so it is not believed: reading it let one
  // client rotate a header and get a fresh allowance on every request.
  assert.notEqual(key({ "x-forwarded-for": "1.2.3.4, 203.0.113.9" }), "1.2.3.4");

  // An empty or comma-only header must fall through rather than becoming the
  // key "", which every visitor behind such a proxy would have shared.
  assert.equal(key({ "x-forwarded-for": "", "x-real-ip": "203.0.113.9" }), "203.0.113.9");
  assert.equal(key({ "x-forwarded-for": "  ", "x-real-ip": "203.0.113.9" }), "203.0.113.9");
  assert.equal(key({ "x-forwarded-for": ",,", "x-real-ip": "203.0.113.9" }), "203.0.113.9");
  assert.equal(key({}), "unknown");
});

test("the bucket map is bounded, and the sweep runs on a clock", () => {
  let now = 1_000_000;
  const limiter = createRateLimiter(() => now);

  // Inside a live window nothing is sweepable, so growth must be refused
  // rather than absorbed: the old size-triggered sweep walked the whole map
  // on every request and deleted nothing, which made cleanup the cost.
  for (let i = 0; i < MAX_BUCKETS + 500; i++) limiter.check(`ip-${i}`);
  assert.ok(limiter.size() <= MAX_BUCKETS, `held ${limiter.size()} buckets`);

  // Once the window has passed, one request reclaims the map.
  now += WINDOW_MS + 1;
  limiter.check("someone-else");
  assert.ok(limiter.size() < 10, `sweep left ${limiter.size()} buckets`);
});

test("the process-wide scan budget bounds a burst from many addresses", () => {
  const budget = createScanBudget(() => 1_000_000, 3);
  assert.equal(budget.take(), true);
  assert.equal(budget.take(), true);
  assert.equal(budget.take(), true);
  // A per-client limit does not help when the client picks the address.
  assert.equal(budget.take(), false);
});
