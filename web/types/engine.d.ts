/**
 * Types for the shared detection engine, which is plain JavaScript in the
 * repository root so the published CLI can stay dependency free. Declaring
 * the surface here keeps the web app type-checked against it, and makes the
 * engine's public API explicit in one readable place.
 */

declare module "@engine/verdict.js" {
  export type Verdict = "green" | "yellow" | "red";
  export const EXIT_CODES: Record<Verdict | "error", number>;
  export const GREEN_MEANING: string;
}

declare module "@engine/github.js" {
  export interface RepoMeta {
    owner: string;
    repo: string;
    defaultBranch: string;
    ref: string;
    description: string | null;
    topics: string[];
    stars: number;
    isFork: boolean;
    ownerType: "User" | "Organization";
    ownerCreatedAt: string | null;
    ownerPublicRepos: number | null;
    orgPublicMembers: number | null;
    commitAuthorNames: string[];
    commitDates: string[];
  }

  export type GitHubErrorKind =
    | "not-found"
    | "rate-limited"
    | "auth"
    | "network"
    | "server"
    | "empty-repo"
    | "bad-response";

  export class GitHubError extends Error {
    kind: GitHubErrorKind;
    status: number;
  }

  export function parseGitHubUrl(input: string): { owner: string; repo: string } | null;
  export function createGitHubClient(options?: { token?: string; fetchImpl?: typeof fetch }): unknown;
  export const MAX_FILES_FETCHED: number;
}

declare module "@engine/scan.js" {
  import type { RepoMeta } from "@engine/github.js";
  import type { Verdict } from "@engine/verdict.js";

  /** One rule hit, with everything needed to explain it to a non-expert. */
  export interface Finding {
    id: string;
    severity: "high" | "medium" | "low";
    file: string;
    line: number | null;
    snippet: string;
    why: string;
    next: string;
    scriptPath?: string;
    scriptBody?: string;
  }

  export interface ScanOutcome {
    verdict: Verdict;
    /** What a report lists, capped so an adversarial lockfile cannot fill it. */
    findings: Finding[];
    /**
     * Every finding the verdict was decided on, uncapped. For rules that have
     * to see all of them rather than a readable subset: the AI pass reads this
     * for the signals a model may never clear, because reading the capped
     * array meant padding a repository could push one out of view.
     */
    allFindings: Finding[];
    meta: RepoMeta;
    notes: string[];
    stats: {
      filesScanned: number;
      bytesScanned: number;
      /** Every finding, including any the report did not list. */
      findings: number;
      /** Counted over every finding, not over the listed ones. */
      severities: { high: number; medium: number; low: number };
      treeTruncated: boolean;
    };
  }

  export function scanRepo(options: {
    owner: string;
    repo: string;
    ref?: string | null;
    client: unknown;
    now?: number;
  }): Promise<ScanOutcome>;
}

declare module "@engine/ai.js" {
  import type { ScanOutcome } from "@engine/scan.js";
  import type { Verdict } from "@engine/verdict.js";

  export interface AiIssue {
    provider: string;
    model: string;
    kind: "http" | "unreadable" | "refusal" | "contract" | "error";
    detail: string;
  }

  export function runAiPass(
    result: ScanOutcome,
    options?: {
      env?: Record<string, string | undefined>;
      fetchImpl?: typeof fetch;
      provider?: string | null;
      issues?: AiIssue[];
    },
  ): Promise<{ verdict: Verdict; assessment: string; provider: string; model: string } | null>;

  export const PROVIDERS: Record<string, { label: string; envKey: string; defaultModel: string }>;
  export const PROVIDER_ORDER: string[];
  /** Guess a provider from an API key's prefix, or null if unrecognized. */
  export function providerFromKey(key: string): string | null;
  export function configuredProviders(
    env: Record<string, string | undefined>,
    forced?: string | null,
  ): string[];
}
