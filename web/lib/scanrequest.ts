/**
 * The page's client state, as plain functions: what the form sends to
 * POST /api/scan, and how the reply becomes a result or an error message.
 * app/page.tsx only wires these to React state, so the decisions that used
 * to live inside the component can be tested without a browser.
 */

import type { ScanError, ScanResult } from "./types";

/**
 * Providers a visitor can pick, matching the shared engine's registry.
 * The free-tier ones are listed first and labelled, because whether a key
 * costs money decides whether this feature is usable at all for someone who
 * came here worried about money in the first place.
 */
export const AI_PROVIDERS = [
  { value: "", label: "Detect from the key" },
  { value: "gemini", label: "Gemini (free tier)" },
  { value: "groq", label: "Groq (free tier)" },
  { value: "openai", label: "OpenAI (paid)" },
  { value: "anthropic", label: "Anthropic (paid)" },
] as const;

export interface ScanForm {
  url: string;
  useAi: boolean;
  aiKey: string;
  aiProvider: string;
}

export interface ScanRequestBody {
  url: string;
  ai: boolean;
  aiKey?: string;
  aiProvider?: string | null;
}

/** Whether the form can be submitted at all. */
export function canScan(form: Pick<ScanForm, "url">, loading: boolean): boolean {
  return form.url.trim().length > 0 && !loading;
}

/**
 * The request body for a scan. A key travels only when the AI pass is on
 * and the key is non-blank; with the pass off, the key stays in the tab.
 * An empty provider means "detect from the key" and is sent as null.
 */
export function buildScanRequest(form: ScanForm): ScanRequestBody {
  const key = form.aiKey.trim();
  const body: ScanRequestBody = { url: form.url, ai: form.useAi };
  if (form.useAi && key) {
    body.aiKey = key;
    body.aiProvider = form.aiProvider || null;
  }
  return body;
}

export const NETWORK_ERROR = "Couldn't reach the scanner. Check your connection and try again.";
export const GENERIC_ERROR = "Something went wrong. Please try again.";

export type ScanOutcome = { kind: "result"; result: ScanResult } | { kind: "error"; message: string };

/**
 * Turn an HTTP reply into what the page shows. A non-2xx reply carries the
 * server's own message when it has one; a body that is not the expected
 * shape falls back to the generic message rather than rendering nothing,
 * so a failed scan is never mistaken for a clean one.
 */
export function interpretScanResponse(ok: boolean, data: unknown): ScanOutcome {
  if (!ok) {
    const message =
      typeof data === "object" && data !== null && typeof (data as ScanError).error === "string"
        ? (data as ScanError).error
        : GENERIC_ERROR;
    return { kind: "error", message };
  }
  if (
    typeof data !== "object" ||
    data === null ||
    !["green", "yellow", "red"].includes((data as ScanResult).verdict) ||
    !Array.isArray((data as ScanResult).findings)
  ) {
    return { kind: "error", message: GENERIC_ERROR };
  }
  return { kind: "result", result: data as ScanResult };
}
