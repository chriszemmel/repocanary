/**
 * The scan cache saves GitHub quota; these tests hold it to never serving a
 * failure, never outliving its window, and never scanning twice at once.
 */

import test from "node:test";
import assert from "node:assert/strict";
import { createScanCache, SCAN_CACHE_TTL_MS, scanKey, scanOrReuse } from "./scancache.ts";

test("keys ignore case, as GitHub names do", () => {
  assert.equal(scanKey("Sindresorhus", "Slugify"), scanKey("sindresorhus", "slugify"));
  assert.notEqual(scanKey("a", "bc"), scanKey("ab", "c"));
});

test("a result is reused within the window and scanned again after it", async () => {
  let t = 0;
  const cache = createScanCache<string>(() => t);
  let scans = 0;
  const scan = async () => `result ${++scans}`;

  assert.equal(await cache.run("k", scan), "result 1");
  t = SCAN_CACHE_TTL_MS - 1;
  assert.equal(await cache.get("k"), "result 1");

  t = SCAN_CACHE_TTL_MS + 1;
  assert.equal(cache.get("k"), undefined);
  assert.equal(await cache.run("k", scan), "result 2");
});

test("the window starts when the scan lands, not when it starts", async () => {
  let t = 0;
  const cache = createScanCache<string>(() => t);
  let finish!: (v: string) => void;
  const pending = cache.run("k", () => new Promise<string>((r) => (finish = r)));
  t = SCAN_CACHE_TTL_MS * 2; // a very slow scan
  finish("done");
  await pending;
  await Promise.resolve();
  assert.equal(await cache.get("k"), "done");
});

test("simultaneous callers share one running scan", async () => {
  const cache = createScanCache<string>();
  let scans = 0;
  let finish!: (v: string) => void;
  const first = cache.run("k", () => {
    scans++;
    return new Promise<string>((r) => (finish = r));
  });
  const joined = cache.get("k");
  assert.ok(joined, "a running scan is visible to the next caller");
  finish("once");
  assert.equal(await first, "once");
  assert.equal(await joined, "once");
  assert.equal(scans, 1);
});

test("a failed scan is not kept", async () => {
  const cache = createScanCache<string>();
  await assert.rejects(cache.run("k", async () => Promise.reject(new Error("rate limited"))));
  await Promise.resolve();
  assert.equal(cache.get("k"), undefined);
  assert.equal(cache.size(), 0);
});

test("the cache is bounded and drops the oldest entry first", async () => {
  const cache = createScanCache<string>(Date.now, SCAN_CACHE_TTL_MS, 2);
  await cache.run("a", async () => "a");
  await cache.run("b", async () => "b");
  await cache.run("c", async () => "c");
  assert.equal(cache.size(), 2);
  assert.equal(cache.get("a"), undefined);
  assert.equal(await cache.get("c"), "c");
});

test("expired results are cleared before a live one is evicted", async () => {
  let t = 0;
  const cache = createScanCache<string>(() => t, 100, 2);
  await cache.run("old", async () => "old");
  t = 50;
  await cache.run("fresh", async () => "fresh");
  t = 120; // "old" has expired, "fresh" has not
  await cache.run("new", async () => "new");
  assert.equal(cache.size(), 2);
  assert.equal(await cache.get("fresh"), "fresh");
  assert.equal(await cache.get("new"), "new");
});

test("a running scan is not the one evicted at capacity", async () => {
  const cache = createScanCache<string>(Date.now, SCAN_CACHE_TTL_MS, 2);
  let finish!: (v: string) => void;
  const running = cache.run("running", () => new Promise<string>((r) => (finish = r)));
  await cache.run("landed", async () => "landed");
  await cache.run("third", async () => "third");
  assert.ok(cache.get("running"), "the in-flight scan is still shared");
  assert.equal(cache.get("landed"), undefined);
  finish("done");
  assert.equal(await running, "done");
});

test("the scan budget is spent once per scan that runs and never for a cached answer", async () => {
  const cache = createScanCache<string>();
  let spent = 0;
  let scans = 0;
  const take = () => {
    spent++;
    return true;
  };
  const scan = async () => `scan ${++scans}`;

  assert.equal(await scanOrReuse(cache, "k", take, scan), "scan 1");
  for (let i = 0; i < 5; i++) assert.equal(await scanOrReuse(cache, "k", take, scan), "scan 1");
  assert.equal(spent, 1);
  assert.equal(scans, 1);
});

test("a spent budget refuses a new scan but still serves a cached one", async () => {
  const cache = createScanCache<string>();
  await scanOrReuse(cache, "cached", () => true, async () => "cached");
  const noBudget = () => false;
  assert.equal(scanOrReuse(cache, "fresh", noBudget, async () => "never"), null);
  assert.equal(await scanOrReuse(cache, "cached", noBudget, async () => "never"), "cached");
});
