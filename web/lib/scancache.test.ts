/**
 * The scan cache saves GitHub quota; these tests hold it to never serving a
 * failure, never outliving its window, and never scanning twice at once.
 */

import test from "node:test";
import assert from "node:assert/strict";
import { createScanCache, SCAN_CACHE_TTL_MS, scanKey } from "./scancache.ts";

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
