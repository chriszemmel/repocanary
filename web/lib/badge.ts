/**
 * The README badge: a verdict as a small SVG, in the shape every developer
 * already reads at the top of a README.
 *
 * The words are chosen with the same care as the site's. Green says "no
 * known traps", never "safe", because green means nothing known matched and
 * nothing more. A scan that could not run says so; it is never green.
 */

import type { Verdict } from "@engine/verdict.js";

export type BadgeState = Verdict | "unavailable";

export interface Badge {
  label: string;
  message: string;
  /** Fill of the message half. */
  color: string;
}

const LABEL = "repocanary";

/** The badge for a state. Exhaustive, so a new verdict is a type error here. */
export function badgeFor(state: BadgeState): Badge {
  switch (state) {
    case "red":
      return { label: LABEL, message: "do not run", color: "#dc2626" };
    case "yellow":
      return { label: LABEL, message: "flagged", color: "#d97706" };
    case "green":
      return { label: LABEL, message: "no known traps", color: "#15803d" };
    case "unavailable":
      return { label: LABEL, message: "unavailable", color: "#52525b" };
  }
}

/** The only characters that mean anything inside SVG text or attributes. */
function escapeXml(s: string): string {
  return s.replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&apos;" })[c] ?? c);
}

/**
 * Text width at 11px Verdana, the badge convention, estimated per
 * character. The estimate only sizes the boxes: textLength then makes the
 * glyphs fit the box exactly, so a wide font on the reader's machine cannot
 * spill the text out of its half.
 */
function textWidth(s: string): number {
  let w = 0;
  for (const ch of s) {
    if (/[ilj.,:;'|! ]/.test(ch)) w += 3.5;
    else if (/[mwMW]/.test(ch)) w += 9.5;
    else if (/[A-Z]/.test(ch)) w += 7.5;
    else w += 6.3;
  }
  return Math.round(w);
}

/**
 * Render the badge as a flat, 20px high SVG. Self-contained: no fonts
 * fetched, no scripts, no external references, so it renders identically
 * through GitHub's image proxy and in any README.
 */
export function renderBadge(badge: Badge): string {
  const pad = 6;
  const gap = 4;
  const canary = 14;
  const labelText = textWidth(badge.label);
  const messageText = textWidth(badge.message);
  const leftWidth = pad + canary + gap + labelText + pad;
  const rightWidth = pad + messageText + pad;
  const width = leftWidth + rightWidth;
  const height = 20;
  const title = `${badge.label}: ${badge.message}`;
  const label = escapeXml(badge.label);
  const message = escapeXml(badge.message);
  const textX = pad + canary + gap;

  return (
    `<svg xmlns="http://www.w3.org/2000/svg" width="${width}" height="${height}" role="img" aria-label="${escapeXml(title)}">` +
    `<title>${escapeXml(title)}</title>` +
    `<clipPath id="r"><rect width="${width}" height="${height}" rx="3" fill="#fff"/></clipPath>` +
    `<g clip-path="url(#r)">` +
    `<rect width="${leftWidth}" height="${height}" fill="#0c0c0d"/>` +
    `<rect x="${leftWidth}" width="${rightWidth}" height="${height}" fill="${escapeXml(badge.color)}"/>` +
    `</g>` +
    // The canary, scaled from its 176-unit box down to 14px, in the brand yellow.
    `<g transform="translate(${pad} 3) scale(${(canary / 176).toFixed(4)}) translate(-40 -40)" fill="#f8ba32">` +
    `<path fill-rule="evenodd" d="${CANARY_PATH}"/>` +
    `</g>` +
    `<g fill="#fff" text-anchor="start" font-family="Verdana,Geneva,DejaVu Sans,sans-serif" font-size="11">` +
    `<text x="${textX}" y="14" fill="#f8ba32" textLength="${labelText}" lengthAdjust="spacingAndGlyphs">${label}</text>` +
    `<text x="${leftWidth + pad}" y="14" textLength="${messageText}" lengthAdjust="spacingAndGlyphs">${message}</text>` +
    `</g>` +
    `</svg>`
  );
}

/**
 * A budget for badge scans in this process. Badges are fetched by GitHub's
 * image proxy, so every request looks like the same few addresses and a
 * per-IP limit would block every README at once. The verdict cache below
 * absorbs repeat loads; this cap is what stops a burst of distinct
 * repositories from spending the operator's GitHub quota on scans.
 */
export const BADGE_WINDOW_MS = 10 * 60 * 1000;
export const BADGE_MAX_SCANS = 60;

export interface BadgeBudget {
  /** Take one scan from the budget; false when the window is spent. */
  take(): boolean;
}

export function createBadgeBudget(now: () => number = Date.now, max = BADGE_MAX_SCANS): BadgeBudget {
  let stamps: number[] = [];
  return {
    take() {
      const at = now();
      stamps = stamps.filter((t) => at - t < BADGE_WINDOW_MS);
      if (stamps.length >= max) return false;
      stamps.push(at);
      return true;
    },
  };
}

/**
 * A verdict cache in this process, so a README that is viewed all day costs
 * one scan a day on any host, whether or not a cache sits in front of the
 * server. Cache-Control on the response lets any proxy, and GitHub's image
 * proxy, cache the drawing as well; this is the part that does not depend
 * on one being there.
 */
export const VERDICT_TTL_MS = 24 * 60 * 60 * 1000;
export const VERDICT_CACHE_MAX = 5000;

export interface VerdictCache {
  get(key: string): BadgeState | undefined;
  set(key: string, state: BadgeState): void;
  /** Entries currently held, for tests. */
  size(): number;
}

export function createVerdictCache(now: () => number = Date.now, max = VERDICT_CACHE_MAX): VerdictCache {
  const entries = new Map<string, { state: BadgeState; at: number }>();
  return {
    get(key) {
      const hit = entries.get(key);
      if (!hit) return undefined;
      if (now() - hit.at >= VERDICT_TTL_MS) {
        entries.delete(key);
        return undefined;
      }
      return hit.state;
    },
    set(key, state) {
      // Only a verdict is worth a day. "unavailable" is a moment's failure and
      // is asked again next time, so a rate-limited hour does not paint a
      // repository grey until tomorrow.
      if (state === "unavailable") return;
      if (entries.size >= max) {
        const oldest = entries.keys().next().value;
        if (oldest !== undefined) entries.delete(oldest);
      }
      entries.delete(key);
      entries.set(key, { state, at: now() });
    },
    size() {
      return entries.size;
    },
  };
}

/** The canary outline, the same path as the site's icon. */
const CANARY_PATH =
  "M176.58 44.52C184.89 45.59 191.3 49.12 196.55 55.44L197.59 56.73L207.56 58.91C213.03 60.14 217.54 61.15 217.6 61.21C217.66 61.24 216.77 62.04 215.6 62.93C206.49 70.17 202.38 73.76 201.95 74.83C200.81 77.75 201.06 82.59 202.69 88.45C206.49 102.2 207.47 107.72 207.69 116.87C208.15 134.88 201.89 150.55 189.28 163.01C180.23 171.97 167.49 179.4 154.27 183.51L151.14 184.46L152.09 186.21C154.55 190.56 162.28 203.36 162.89 204.03C163.94 205.17 165.22 205.57 169.73 206.06C177.28 206.89 179.68 207.71 181.03 210.02C181.45 210.75 181.79 211.43 181.79 211.52C181.79 211.64 176.33 211.7 169.61 211.67L157.46 211.58L157.06 209.74C156.33 206.24 155.31 204.4 148.07 193.51L143.01 185.9L141.75 186.08C141.08 186.18 138.13 186.36 135.22 186.48C130.83 186.64 129.94 186.76 130.09 187.1C130.28 187.59 138.1 201 139.48 203.17C140.53 204.8 141.17 205.17 143.99 205.6C148.9 206.36 151.2 207.9 152.15 211.03L152.37 211.73L135.65 211.73C124.14 211.73 118.89 211.64 118.89 211.43C118.89 211.24 119.11 210.69 119.36 210.23C120.46 208.05 122.98 206.98 128.9 206.06C130.74 205.78 132.36 205.41 132.52 205.29C132.67 205.14 130.43 201.36 127.45 196.67C124.51 192.07 121.72 187.68 121.23 186.88C120.37 185.47 120.34 185.47 117.7 184.92C113.53 184.06 108.03 182.1 103.65 179.92L99.63 177.89L98.25 178.72C96.01 180.01 90.85 184.89 78.98 196.95L67.81 208.33L65.42 208.63C62.32 209.06 55.17 209.06 52.16 208.63C46.88 207.9 41.52 206 39.4 204.09C38.23 203.02 38.2 202.96 38.72 202.35C39.03 201.98 41.33 200.17 43.88 198.36C46.39 196.52 54.19 190.84 61.21 185.75C68.21 180.65 75.02 175.84 76.34 175.04C81.31 172.03 86.53 170.37 98.18 168.17C115.73 164.85 125.55 161.45 134.39 155.56C138.5 152.82 143.84 147.64 146.17 144.08C150.56 137.42 152.95 129.81 152.95 122.63C152.95 119.87 152.43 116.01 152.06 116.01C151.97 116.01 151.57 117.14 151.17 118.55C150.28 121.87 146.72 128.92 144.15 132.57C139.97 138.44 132.27 145.43 125.09 149.85C112.14 157.86 90.39 165.1 73.33 167.09C68.88 167.61 64.59 167.71 64.59 167.28C64.59 166.69 74.81 153.65 82.66 144.26C92.2 132.82 97.51 127.05 114.66 109.47C122.21 101.74 127.09 96.49 127.95 95.2C129.63 92.6 130.25 90.76 131.63 84.1C134.17 71.86 138.19 63.2 144.45 56.58C152.86 47.71 165.25 43.08 176.58 44.52ZM177.37 57.86C172.96 59.43 171.58 65.57 174.95 68.79C176.79 70.57 177.9 71 180.26 70.84C183.82 70.66 186.24 68.39 186.61 64.95C186.85 62.68 186.15 60.9 184.43 59.31C182.44 57.47 179.92 56.94 177.37 57.86Z";
