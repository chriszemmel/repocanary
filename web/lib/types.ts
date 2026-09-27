/**
 * Types for the web front end.
 *
 * Detection types come from the shared engine (@engine/*). Only the
 * presentation shape lives here: what POST /api/scan returns to the browser.
 */

import type { Finding } from "@engine/scan.js";
import type { Verdict } from "@engine/verdict.js";

export type { Finding, Verdict };

/** The JSON shape returned to the front end by POST /api/scan. */
export interface ScanResult {
  verdict: Verdict;
  headline: string;
  whatItDoes: string;
  /**
   * The findings themselves, straight from the shared engine, so the page
   * can show the same file, line, severity, reason, and next step the CLI
   * shows. Ordered most serious first.
   */
  findings: Finding[];
  whatToDo: string[];
  /** Scan caveats: truncated trees, submodules, AI pass outcome. */
  notes: string[];
  disclaimer: string;
  repo: { owner: string; repo: string; ref: string };
  stats: {
    filesScanned: number;
    findings: number;
    high: number;
    medium: number;
    low: number;
    /** True when the optional AI pass returned a judgement. */
    aiValidated: boolean;
    /** Provider and model that gave the second opinion, or null when none ran. */
    aiModel?: string | null;
  };
}

export interface ScanError {
  error: string;
  code:
    | "invalid_url"
    | "not_found"
    | "github_rate_limited"
    | "rate_limited"
    | "empty_repo"
    | "server_error";
}
