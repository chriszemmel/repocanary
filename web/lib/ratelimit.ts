/**
 * Simple in-memory, per-client sliding-window rate limiter.
 *
 * This is not a global limit, and it is documented as accepted rather than
 * fixed. THREAT-MODEL.md carries the same statement where someone looking
 * for the site's guarantees will find it; this is the short version.
 *
 * Two things get past it, and the second is the cheap one:
 *
 *  - The counter lives in this process. Vercel runs the route as serverless
 *    functions and starts more of them under load, and each new instance
 *    starts with an empty map, so the published ceilings are per instance.
 *  - The key is the client address. Anyone egressing from a pool of
 *    addresses -- any cloud provider, a large NAT, a botnet -- draws a fresh
 *    allowance per address without knowing anything about the first point.
 *    Measured, not assumed: an attempt to observe the limit engaging from
 *    outside on 2026-09-08 could not make it fire in 13 sequential requests
 *    against a limit of 10, because the caller's own egress address rotated
 *    across a /24 between requests.
 *
 * It is kept because it still costs an attacker something and stops the
 * single-client accident it was written for, and because nothing behind the
 * endpoint costs money to exhaust: the AI pass runs on the visitor's own
 * key, so the only shared resource is this site's GitHub quota, and
 * takeScanBudget below already fails that closed. A shared store (Redis)
 * would buy a real global limit at the price of a network dependency and a
 * standing credential, on a free tool whose worst case is an hour of "try
 * again later". If this endpoint ever spends the operator's money, that
 * trade stops being the right one and this comment should stop being true.
 */

interface Bucket {
  timestamps: number[];
}

export const WINDOW_MS = 10 * 60 * 1000; // 10 minutes
export const MAX_REQUESTS = 10; // per client per window

/**
 * How often idle buckets are swept, and how many may be held at once.
 *
 * The sweep used to run whenever the map passed a size threshold, which is
 * exactly backwards: inside a live window nothing has expired, so it walked
 * the whole map on every request and deleted nothing. Per-request cost grew
 * with the number of clients seen and the total went quadratic, which turned
 * the cleanup into the cheapest way to spend the server's CPU.
 *
 * On a clock instead, the walk happens at most once a minute. The ceiling is
 * the other half: past it the limiter stops admitting identities it has never
 * seen rather than growing, so a client inventing addresses is refused while
 * everyone already inside a window is untouched.
 */
const SWEEP_INTERVAL_MS = 60 * 1000;
export const MAX_BUCKETS = 20_000;

/**
 * Which hop of X-Forwarded-For to believe.
 *
 * The header is a list a client can prepend to, so the leftmost entry is
 * whatever the caller typed; only the rightmost entries were written by
 * infrastructure we run. This says how many of those there are: 1 behind a
 * single reverse proxy. Unset means trust nothing, which fails closed.
 */
const TRUSTED_PROXY_HOPS = Number(process.env.TRUSTED_PROXY_HOPS ?? "0");

/**
 * The key a request is counted against.
 *
 * A platform header comes first where one exists, because the platform sets
 * it and a client cannot. Everything else is derived from the trusted hop,
 * never from the leftmost value: reading that let one client rotate a header
 * and get a fresh allowance every request.
 */
export function clientKey(headers: Headers): string {
  const platform = headers.get("x-vercel-forwarded-for") ?? headers.get("cf-connecting-ip");
  if (platform?.trim()) return platform.trim();

  // filter(Boolean) matters: an empty or comma-only header used to yield the
  // key "", because ?? does not fire on an empty string, and every visitor
  // behind such a proxy then shared one bucket and locked each other out.
  const chain = (headers.get("x-forwarded-for") ?? "")
    .split(",")
    .map((s) => s.trim())
    .filter(Boolean);
  if (TRUSTED_PROXY_HOPS > 0 && chain.length > 0) {
    return chain[Math.max(0, chain.length - TRUSTED_PROXY_HOPS)];
  }
  return headers.get("x-real-ip")?.trim() || "unknown";
}

export interface RateLimiter {
  /** Returns true if the request is allowed, false if the client is over the limit. */
  check(ip: string): boolean;
  /** Buckets currently held, for tests. */
  size(): number;
}

/**
 * Build a limiter over an injectable clock, so the window can be tested
 * without waiting ten minutes. The route uses the default, Date.now.
 */
export function createRateLimiter(now: () => number = Date.now): RateLimiter {
  const buckets = new Map<string, Bucket>();
  let lastSweep = 0;

  return {
    check(ip: string): boolean {
      const at = now();

      if (at - lastSweep >= SWEEP_INTERVAL_MS) {
        lastSweep = at;
        for (const [key, b] of buckets) {
          if (b.timestamps.every((t) => at - t >= WINDOW_MS)) buckets.delete(key);
        }
      }

      const existing = buckets.get(ip);
      // A client this process has never seen, with no room left to remember
      // one, is refused rather than admitted at the cost of unbounded memory.
      if (!existing && buckets.size >= MAX_BUCKETS) return false;

      const bucket = existing ?? { timestamps: [] };
      bucket.timestamps = bucket.timestamps.filter((t) => at - t < WINDOW_MS);

      if (bucket.timestamps.length >= MAX_REQUESTS) {
        buckets.set(ip, bucket);
        return false;
      }

      bucket.timestamps.push(at);
      buckets.set(ip, bucket);
      return true;
    },
    size() {
      return buckets.size;
    },
  };
}

const shared = createRateLimiter();

/** Returns true if the request is allowed, false if the client is over the limit. */
export function checkRateLimit(ip: string): boolean {
  return shared.check(ip);
}

/**
 * A budget for scans in this process, on top of the per-client limit.
 *
 * One scan spends up to 175 requests of the operator's GitHub quota, so a
 * burst from many addresses can empty the hourly allowance and take every
 * scan and every badge down with it. The per-client limit stops one visitor;
 * this stops the window from being spent however many addresses the traffic
 * claims to come from. The badge route has had one of these all along.
 */
export const SCAN_BUDGET_WINDOW_MS = 10 * 60 * 1000;
export const SCAN_BUDGET_MAX = 300;

export function createScanBudget(now: () => number = Date.now, max = SCAN_BUDGET_MAX) {
  let stamps: number[] = [];
  return {
    take(): boolean {
      const at = now();
      stamps = stamps.filter((t) => at - t < SCAN_BUDGET_WINDOW_MS);
      if (stamps.length >= max) return false;
      stamps.push(at);
      return true;
    },
  };
}

const sharedBudget = createScanBudget();

/** Returns true if the process still has scan budget in this window. */
export function takeScanBudget(): boolean {
  return sharedBudget.take();
}
