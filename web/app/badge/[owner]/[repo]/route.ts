/**
 * GET /badge/:owner/:repo.svg, the README badge.
 *
 * The same engine and the same verdict as the page and the CLI, drawn as a
 * 20px SVG. Nothing is cloned, installed, or executed.
 *
 * Badges are loaded through GitHub's image proxy every time a README is
 * viewed, so this route is built to be cheap and to fail safe on any host:
 *   - a verdict is kept in this process for a day, so a popular README costs
 *     one scan a day, not one a view, with no cache in front of the server;
 *   - Cache-Control lets a proxy in front, and GitHub's image proxy, keep the
 *     drawing as well, and serve it stale while a fresh scan runs;
 *   - a per-process budget caps how many distinct scans a burst can trigger,
 *     so nobody can spend the operator's GitHub quota through it;
 *   - anything that is not a verdict (not found, rate limited, over budget)
 *     renders as "unavailable" with a short cache, never as green.
 */

import { NextRequest, NextResponse } from "next/server";
import { createGitHubClient } from "@engine/github.js";
import { scanRepo } from "@engine/scan.js";
import { badgeFor, createBadgeBudget, createVerdictCache, renderBadge, type BadgeState } from "@/lib/badge";

export const runtime = "nodejs";
export const maxDuration = 60;
export const dynamic = "force-dynamic";

/** A GitHub owner or repository name, as GitHub itself constrains them. */
const NAME = /^[A-Za-z0-9][A-Za-z0-9._-]{0,99}$/;

/**
 * Two budgets, not one. A README this process has already vouched for is
 * refreshing a verdict; a name never seen is what a flood is made of. With a
 * single counter, sixty requests for distinct unknown names spent the whole
 * window and every badge everywhere rendered "unavailable".
 */
const knownBudget = createBadgeBudget(Date.now, 50);
const coldBudget = createBadgeBudget(Date.now, 10);
const seen = new Set<string>();
const verdicts = createVerdictCache();

const SVG_HEADERS = {
  "Content-Type": "image/svg+xml; charset=utf-8",
  "X-Content-Type-Options": "nosniff",
  "Content-Security-Policy": "default-src 'none'; style-src 'unsafe-inline'",
};

function respond(state: BadgeState, status = 200) {
  const cache =
    state === "unavailable"
      ? "public, max-age=60, s-maxage=300"
      : "public, max-age=3600, s-maxage=86400, stale-while-revalidate=604800";
  return new NextResponse(renderBadge(badgeFor(state)), {
    status,
    headers: { ...SVG_HEADERS, "Cache-Control": cache },
  });
}

export async function GET(_req: NextRequest, context: { params: Promise<{ owner: string; repo: string }> }) {
  const { owner, repo: rawRepo } = await context.params;
  const repo = rawRepo.replace(/\.svg$/i, "");
  if (!NAME.test(owner) || !NAME.test(repo)) return respond("unavailable", 404);
  const key = `${owner}/${repo}`.toLowerCase();
  const cached = verdicts.get(key);
  if (cached) return respond(cached);
  const budget = seen.has(key) ? knownBudget : coldBudget;
  if (!budget.take()) return respond("unavailable", 429);

  try {
    const client = createGitHubClient({ token: process.env.GITHUB_TOKEN });
    const scan = await scanRepo({ owner, repo, client });
    // Known only once it has produced a verdict. Marked before the scan, a
    // made-up name that failed became "known" and drew on the budget meant
    // for real READMEs, so ten invented names and fifty repeats of them
    // turned every uncached badge "unavailable".
    seen.add(key);
    verdicts.set(key, scan.verdict);
    return respond(scan.verdict);
  } catch (err) {
    // A failed scan is not a verdict. Log the reason, draw "unavailable".
    console.error("Badge scan failed:", err instanceof Error ? err.message : "unknown error");
    return respond("unavailable");
  }
}
