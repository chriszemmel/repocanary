/**
 * A short-lived cache of static scan results, keyed by repository.
 *
 * The site's only exhaustible resource is its GitHub quota, and one scan can
 * spend up to 175 requests of it. When a link is shared, many people scan the
 * same repository within minutes, and the page's own "Try an example" sends
 * everyone to the same one. Ten minutes of reuse turns that burst into one
 * scan, and a scan already running is joined rather than started again.
 *
 * What is kept is the engine's result for a public repository, never who
 * asked for it. Failures are not kept, so a rate-limited moment is retried
 * by the next visitor instead of being served for ten minutes. Like the rate
 * limiter this lives in one process: a new serverless instance starts empty,
 * which costs a scan and nothing else.
 */

export const SCAN_CACHE_TTL_MS = 10 * 60 * 1000;
export const SCAN_CACHE_MAX = 500;

/** GitHub owner and repository names are case-insensitive. */
export function scanKey(owner: string, repo: string): string {
  return `${owner}/${repo}`.toLowerCase();
}

export interface ScanCache<T> {
  /** A fresh or in-flight result for this key, or undefined. */
  get(key: string): Promise<T> | undefined;
  /** Start a scan for this key; later callers share it until it expires. */
  run(key: string, scan: () => Promise<T>): Promise<T>;
  /** Entries currently held, for tests. */
  size(): number;
}

export function createScanCache<T>(
  now: () => number = Date.now,
  ttl = SCAN_CACHE_TTL_MS,
  max = SCAN_CACHE_MAX,
): ScanCache<T> {
  // `at` is null while the scan is running; the clock starts when it lands.
  const entries = new Map<string, { promise: Promise<T>; at: number | null }>();

  return {
    get(key) {
      const hit = entries.get(key);
      if (!hit) return undefined;
      if (hit.at !== null && now() - hit.at >= ttl) {
        entries.delete(key);
        return undefined;
      }
      return hit.promise;
    },
    run(key, scan) {
      if (entries.size >= max) {
        // Expired results first: they are dead weight that only a repeat
        // request for the same repository would otherwise clear. The walk is
        // bounded by `max` and happens only on a miss at capacity.
        const at = now();
        for (const [k, e] of entries) {
          if (e.at !== null && at - e.at >= ttl) entries.delete(k);
        }
      }
      if (entries.size >= max) {
        // Then the oldest landed result, so a scan still running is not
        // dropped and started twice. Map keeps insertion order.
        let victim: string | undefined;
        for (const [k, e] of entries) {
          if (e.at !== null) {
            victim = k;
            break;
          }
        }
        entries.delete(victim ?? entries.keys().next().value!);
      }
      const entry: { promise: Promise<T>; at: number | null } = { promise: scan(), at: null };
      entries.delete(key);
      entries.set(key, entry);
      entry.promise.then(
        () => {
          if (entries.get(key) === entry) entry.at = now();
        },
        () => {
          if (entries.get(key) === entry) entries.delete(key);
        },
      );
      return entry.promise;
    },
    size() {
      return entries.size;
    },
  };
}

/**
 * The scan route's one decision: answer from the cache, or take a unit of
 * the scan budget and start a scan. Returns null when the budget is spent.
 * Kept here, not in the route, so a test can hold the budget to exactly one
 * unit per scan that actually runs and none for a cached answer.
 */
export function scanOrReuse<T>(
  cache: ScanCache<T>,
  key: string,
  takeBudget: () => boolean,
  scan: () => Promise<T>,
): Promise<T> | null {
  const cached = cache.get(key);
  if (cached) return cached;
  if (!takeBudget()) return null;
  return cache.run(key, scan);
}
