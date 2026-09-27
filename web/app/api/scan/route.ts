/**
 * POST /api/scan, the single backend endpoint.
 *
 * Input:  { url: string, ai?: boolean }
 * Output: ScanResult JSON, or ScanError with an appropriate status code.
 *
 * SAFETY: this route never clones, installs, executes, or evaluates
 * anything. Detection is the shared engine in the repository root, the same
 * code the CLI runs, so the page and `npx repocanary` cannot drift apart.
 * This file only adds the things a public endpoint needs: rate limiting and
 * presentation. The optional AI pass runs on the visitor's own key or not at
 * all, so this endpoint has no AI spend to budget.
 */

import { NextRequest, NextResponse } from "next/server";
import { createGitHubClient, GitHubError, parseGitHubUrl } from "@engine/github.js";
import { scanRepo } from "@engine/scan.js";
import { PROVIDERS, configuredProviders, runAiPass, type AiIssue } from "@engine/ai.js";
import { resolveAi } from "@/lib/aikey";
import { DISCLAIMER, headline, whatItDoes, whatToDo } from "@/lib/present";
import { checkRateLimit, clientKey, takeScanBudget } from "@/lib/ratelimit";
import { createScanCache, scanKey } from "@/lib/scancache";
import type { ScanError, ScanResult } from "@/lib/types";

export const runtime = "nodejs";
export const maxDuration = 60;

function errorResponse(code: ScanError["code"], message: string, status: number) {
  return NextResponse.json({ error: message, code } satisfies ScanError, { status });
}

/** Static results by repository, shared by every request this process serves. */
const scanCache = createScanCache<Awaited<ReturnType<typeof scanRepo>>>();

/** The only field that matters is a repository URL; 8 KB is generous for that. */
const MAX_BODY_BYTES = 8_192;

/** Map the engine's error taxonomy onto HTTP, so a failed scan is never a green. */
/**
 * Engine messages are written for someone running the CLI: they name the
 * operator's token, the host that refused a connection, and up to 200
 * characters of an upstream body. A visitor gets a message written for a
 * visitor, and the detail stays in the server log.
 */
function mapGitHubError(err: GitHubError) {
  switch (err.kind) {
    case "not-found":
      // The engine's wording is written for someone running the CLI and names
      // the operator's token, which is both confusing here and a hint worth
      // withholding. The detail stays in the log, as the comment above says.
      console.error("Scan not-found:", err.message);
      return errorResponse(
        "not_found",
        "That repository could not be read. Check the owner and name; this site only scans public repositories.",
        404,
      );
    case "empty-repo":
      return errorResponse("empty_repo", "That repository is empty, so there is nothing to scan.", 422);
    case "rate-limited":
      return errorResponse(
        "github_rate_limited",
        "This site has reached GitHub's rate limit for now. Try again in a few minutes, or run the same check locally with: npx repocanary owner/repo",
        429,
      );
    default:
      return errorResponse(
        "server_error",
        "The scan could not be completed because GitHub could not be reached. Nothing was checked, so this is not a verdict. Try again shortly.",
        502,
      );
  }
}

/**
 * Read at most `max` bytes of the body and abandon the rest.
 *
 * Content-Length is the client's claim about the body, so it can bound
 * nothing: a chunked request sends no such header, Number(null ?? "0") is 0,
 * and the old check waved it through and then buffered the whole stream
 * before the second check could reject it. The only number worth trusting is
 * the count of bytes actually taken off the wire, which is also why this
 * counts bytes rather than UTF-16 units.
 */
async function readCapped(req: NextRequest, max: number): Promise<string | null> {
  const reader = req.body?.getReader();
  if (!reader) return "";
  const chunks: Uint8Array[] = [];
  let size = 0;
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    size += value.byteLength;
    if (size > max) {
      await reader.cancel();
      return null;
    }
    chunks.push(value);
  }
  return new TextDecoder().decode(Buffer.concat(chunks));
}

export async function POST(req: NextRequest) {
  if (!checkRateLimit(clientKey(req.headers))) {
    return errorResponse(
      "rate_limited",
      "Too many scans from your network. Please wait a few minutes and try again.",
      429,
    );
  }
  let url: unknown;
  let wantAi = false;
  let aiKey: string | null = null;
  let aiProvider: string | null = null;
  try {
    const raw = await readCapped(req, MAX_BODY_BYTES);
    if (raw === null) {
      return errorResponse("invalid_url", "Request body is too large.", 413);
    }
    const body = JSON.parse(raw);
    if (typeof body !== "object" || body === null || Array.isArray(body)) {
      return errorResponse("invalid_url", 'Request body must be JSON: { "url": "..." }', 400);
    }
    url = body.url;
    wantAi = body.ai === true;
    aiKey = typeof body.aiKey === "string" && body.aiKey.trim() ? body.aiKey.trim() : null;
    aiProvider = typeof body.aiProvider === "string" && body.aiProvider ? body.aiProvider : null;
  } catch {
    return errorResponse("invalid_url", 'Request body must be JSON: { "url": "..." }', 400);
  }
  if (typeof url !== "string" || url.length > 500) {
    return errorResponse("invalid_url", "Please provide a GitHub repository URL.", 400);
  }
  const parsed = parseGitHubUrl(url);
  if (!parsed) {
    return errorResponse(
      "invalid_url",
      "That doesn't look like a GitHub repository URL. Expected something like https://github.com/owner/repo",
      400,
    );
  }

  // One scan spends up to 175 requests of this site's GitHub quota, so a
  // burst spread across many addresses could empty the hourly allowance and
  // take every scan and every badge down with it. Taken only here, after the
  // request is known to be a scan: malformed bodies cost GitHub nothing and
  // must not be able to spend the budget either.
  if (!takeScanBudget()) {
    return errorResponse(
      "github_rate_limited",
      "This site is at its scan budget for the moment. Try again in a few minutes, or run the same check locally with: npx repocanary owner/repo",
      429,
    );
  }

  try {
    // A repository scanned in the last few minutes, or being scanned right
    // now, is answered from that scan and spends no quota. See scancache.ts.
    const key = scanKey(parsed.owner, parsed.repo);
    let pending = scanCache.get(key);
    if (!pending) {
      // One scan spends up to 175 requests of this site's GitHub quota, so a
      // burst spread across many addresses could empty the hourly allowance
      // and take every scan and every badge down with it.
      if (!takeScanBudget()) {
        return errorResponse(
          "github_rate_limited",
          "This site is at its scan budget for the moment. Try again in a few minutes, or run the same check locally with: npx repocanary owner/repo",
          429,
        );
      }
      const client = createGitHubClient({ token: process.env.GITHUB_TOKEN });
      pending = scanCache.run(key, () => scanRepo({ owner: parsed.owner, repo: parsed.repo, client }));
    }
    const scan = await pending;

    // Optional AI second opinion. It can raise a green to yellow or clear a yellow;
    // it can never lower a red, which the engine enforces, not this file.
    let verdict = scan.verdict;
    let aiValidated = false;
    let aiModel: string | null = null;
    const notes = [...scan.notes];

    if (wantAi) {
      const resolved = resolveAi(aiKey, aiProvider);
      if ("error" in resolved) {
        notes.push(resolved.error);
      } else if (configuredProviders(resolved.env).length === 0) {
        notes.push(
          "That key did not match any supported provider, so the second opinion was skipped. The static verdict is unaffected.",
        );
      } else {
        const issues: AiIssue[] = [];
        const ai = await runAiPass(scan, { env: resolved.env, issues });
        if (ai) {
          aiValidated = true;
          aiModel = `${PROVIDERS[ai.provider]?.label ?? ai.provider}, ${ai.model}`;
          verdict = ai.verdict;
          // Say who gave the opinion before giving it. A second opinion is
          // worth what its author is worth, and the model is configurable.
          if (ai.assessment) notes.push(`Second opinion from ${aiModel}: ${ai.assessment}`);
        } else {
          // A safety refusal is stated plainly rather than passed off as
          // agreement; the static verdict is unaffected either way.
          const refusal = issues.find((i) => i.kind === "refusal");
          if (refusal) {
            notes.push(
              `${PROVIDERS[refusal.provider]?.label ?? refusal.provider} (${refusal.model}) declined to judge these findings on safety grounds. That is a provider policy decision, not a verdict. Reading malware signatures is exactly what such a filter is built to refuse, so another provider may well answer.`,
            );
          } else {
            notes.push(
              "The AI second opinion could not be completed with that key. Check the key and the provider, then try again.",
            );
          }
        }
      }
    }

    // The scan's own tally, not a count of scan.findings, which is capped for
    // readability. Counting the listed ones would contradict the total below.
    const counts = scan.stats.severities;

    // The AI lowered a yellow to green: the one green where signatures did
    // fire, so it must not be worded as one where none did.
    const aiCleared = scan.verdict !== "green" && verdict === "green";

    const result: ScanResult = {
      verdict,
      headline: headline(verdict, parsed.owner, parsed.repo, aiCleared),
      whatItDoes: whatItDoes(verdict, scan.findings, aiCleared),
      findings: scan.findings,
      whatToDo: whatToDo(verdict, aiCleared),
      notes,
      disclaimer: DISCLAIMER,
      repo: { owner: scan.meta.owner, repo: scan.meta.repo, ref: scan.meta.ref },
      stats: {
        filesScanned: scan.stats.filesScanned,
        // Every finding, matching the severity tally above; scan.findings is
        // the listed subset when a report is capped.
        findings: scan.stats.findings,
        ...counts,
        aiValidated,
        aiModel,
      },
    };

    // no-store because a report is about someone's specific repository and
    // has no business sitting in a shared cache.
    return NextResponse.json(result, { headers: { "Cache-Control": "no-store" } });
  } catch (err) {
    if (err instanceof GitHubError) return mapGitHubError(err);
    // Log the error only, never the request body: it may carry an API key.
    console.error("Scan failed:", err instanceof Error ? err.message : "unknown error");
    return errorResponse("server_error", "Something went wrong while scanning. Please try again.", 500);
  }
}
