/**
 * GitHub REST API client, read only.
 *
 * SAFETY: RepoCanary never clones, installs, executes, evaluates, or imports
 * any repository content. This module only fetches file contents as plain
 * text over the GitHub REST API, with hard caps on file count and size.
 * Every check downstream is pure string and regex matching.
 *
 * The scanned URL is sent to api.github.com and nowhere else, and it is
 * never written to disk. The ETag cache below is in-memory only for exactly
 * that reason.
 */

import { safeJsonParse } from "./textutil.js";

const GITHUB_API = "https://api.github.com";

/**
 * Hard caps bounding how much a single scan can ever fetch. The tree
 * selection takes up to 150 files; scan.js follows up to 20 more that an
 * install script or an auto-run editor configuration names, so the ceiling
 * is 170 files.
 *
 * The number that actually bounds a scan is MAX_TOTAL_BYTES, not the file
 * count. A recruiter take-home is a working application, sixty to a hundred
 * and fifty files, and almost all of them tiny: two hundred such files come
 * to about thirty kilobytes, half a percent of the byte budget. At forty
 * files the count bit roughly three hundred times sooner than the bytes did,
 * so a normal recruiter repo was cut off with two thirds of it unread and a
 * plain-source stealer two directories deep was never fetched. The file cap
 * exists only so a pathological tree of millions of empty files cannot spend
 * the whole budget on API round-trips; the bytes are what stop a scan from
 * reading forever, and a hostile file is bounded by them whatever the count.
 */
export const MAX_FILES_FETCHED = 150;
export const MAX_FILE_BYTES = 1_000_000;
export const MAX_TOTAL_BYTES = 6_000_000;
export const MAX_FOLLOW_UPS = 20;

/**
 * A separate allowance for the files an install script or an editor hook
 * actually runs, on top of the selection's budget. Those files decide a
 * verdict, and a repository big enough to spend the whole budget on
 * ordinary source is the one least likely to have anything left for them.
 * A scan therefore reads at most MAX_TOTAL_BYTES plus this.
 */
export const FOLLOW_UP_RESERVE_BYTES = 400_000;

/**
 * How long one request to GitHub may take before it is abandoned.
 *
 * Node has no default request timeout, so a slow endpoint holds the call
 * until the platform kills the whole invocation. A scan makes up to 175
 * requests in sequence, which means one that never answers costs the scan.
 */
const REQUEST_TIMEOUT_MS = 15_000;

/**
 * Error taxonomy for everything that can stop a scan. Every kind maps to a
 * clear message and exit code 3; a failed scan is never reported as green.
 */
export class GitHubError extends Error {
  constructor(message, kind, status = 0) {
    super(message);
    this.name = "GitHubError";
    this.kind = kind; // not-found | rate-limited | auth | network | server | empty-repo | bad-response
    this.status = status;
  }
}

/**
 * Parse a GitHub repo reference into owner/repo. Accepts "owner/repo",
 * "github.com/owner/repo", and full https URLs. Rejects everything else.
 */
export function parseGitHubUrl(input) {
  const trimmed = String(input ?? "").trim();
  let url;
  try {
    const candidate = /^[\w.-]+\/[\w.-]+$/.test(trimmed)
      ? `https://github.com/${trimmed}`
      : trimmed.startsWith("http")
        ? trimmed
        : `https://${trimmed}`;
    url = new URL(candidate);
  } catch {
    return null;
  }
  if (url.hostname !== "github.com" && url.hostname !== "www.github.com") return null;

  const parts = url.pathname.split("/").filter(Boolean);
  if (parts.length < 2) return null;
  const owner = parts[0];
  const repo = parts[1].replace(/\.git$/, "");
  if (!/^[A-Za-z0-9-]{1,39}$/.test(owner)) return null;
  // A name that is only dots is not a repository. ".git" is stripped after
  // the URL constructor has already normalised the path, so "owner/..git"
  // survives as "." and then silently resolves to a different endpoint.
  if (!/^[\w.-]{1,100}$/.test(repo) || /^\.+$/.test(repo)) return null;
  return { owner, repo };
}

function rateLimitMessage(res, token) {
  const reset = res.headers.get("x-ratelimit-reset");
  const resetText = reset
    ? ` The limit resets at ${new Date(Number(reset) * 1000).toISOString()}.`
    : "";
  if (!token) {
    return (
      "GitHub's unauthenticated rate limit (60 requests per hour per IP) stopped this scan." +
      resetText +
      " Set a GITHUB_TOKEN environment variable (any fine-grained token with public repo read access) to raise the limit to 5,000 per hour."
    );
  }
  return `GitHub's API rate limit stopped this scan.${resetText} Try again after the reset.`;
}

/**
 * Create the real GitHub client. Tests inject their own client instead, so
 * no test ever touches the network.
 */
/**
 * A response body as text, reading at most `maxBytes` of it. The cap is in
 * bytes so that it holds whatever the encoding; callers cut to characters.
 */
async function readCappedText(res, maxBytes) {
  if (!res.body?.getReader) return res.text();
  const reader = res.body.getReader();
  const decoder = new TextDecoder();
  let text = "";
  let read = 0;
  try {
    while (read < maxBytes) {
      const { done, value } = await reader.read();
      if (done) break;
      const chunk = value.byteLength > maxBytes - read ? value.subarray(0, maxBytes - read) : value;
      read += chunk.byteLength;
      text += decoder.decode(chunk, { stream: true });
    }
  } finally {
    reader.cancel().catch(() => {});
  }
  return text + decoder.decode();
}

export function createGitHubClient({ token = process.env.GITHUB_TOKEN, fetchImpl = fetch, allowPrivate = false } = {}) {
  // Conditional requests: remember ETags per URL for this process only.
  // Never persisted, because the scanned URL must never be stored anywhere.
  const etags = new Map();

  function headers(raw) {
    const h = {
      Accept: raw ? "application/vnd.github.raw+json" : "application/vnd.github+json",
      "X-GitHub-Api-Version": "2022-11-28",
      "User-Agent": "RepoCanary",
    };
    if (token) h.Authorization = `Bearer ${token}`;
    return h;
  }

  async function request(path, { raw = false } = {}) {
    const url = `${GITHUB_API}${path}`;
    const h = headers(raw);
    const cached = etags.get(url);
    if (cached) h["If-None-Match"] = cached.etag;

    let res;
    try {
      res = await fetchImpl(url, {
        headers: h,
        redirect: "follow",
        signal: AbortSignal.timeout(REQUEST_TIMEOUT_MS),
      });
    } catch (err) {
      const timedOut = err?.name === "TimeoutError" || err?.name === "AbortError";
      // fetch reports every network failure as "fetch failed"; the reason
      // (ECONNREFUSED, ENOTFOUND, a certificate error) is on its cause.
      const cause = err?.cause?.code ?? err?.cause?.message;
      const detail = [err instanceof Error ? err.message : String(err), cause].filter(Boolean).join(": ");
      throw new GitHubError(
        timedOut
          ? `api.github.com did not answer within ${REQUEST_TIMEOUT_MS / 1000} seconds. A scan makes many requests in sequence, so one that never returns would hold the whole scan open. Try again shortly.`
          : `Could not reach api.github.com (${detail}). Check your network connection; GitHub itself may also be down.`,
        "network",
      );
    }

    if (res.status === 304 && cached) {
      return { status: 200, ok: true, text: cached.body, headers: res.headers };
    }
    if (res.status === 401) {
      throw new GitHubError(
        "GitHub rejected the provided GITHUB_TOKEN (401). The token is invalid or expired; unset it or replace it.",
        "auth",
        401,
      );
    }
    if (res.status === 403 || res.status === 429) {
      const remaining = res.headers.get("x-ratelimit-remaining");
      if (remaining === "0" || res.status === 429) {
        throw new GitHubError(rateLimitMessage(res, token), "rate-limited", res.status);
      }
      throw new GitHubError(
        "GitHub declined the request (403). The repository may restrict API access.",
        "server",
        403,
      );
    }
    if (res.status >= 500) {
      throw new GitHubError(
        `GitHub returned a server error (${res.status}). GitHub may be having an outage; try again in a few minutes.`,
        "server",
        res.status,
      );
    }

    // A file's text is cut to MAX_FILE_BYTES anyway, so reading more of it
    // is only memory: raw contents are served up to 100 MB, and a repository
    // of a few such files would otherwise be pulled whole into every scan.
    const text = raw ? await readCappedText(res, MAX_FILE_BYTES * 4) : await res.text();
    const etag = res.headers.get("etag");
    if (res.ok && etag) etags.set(url, { etag, body: text });
    return { status: res.status, ok: res.ok, text, headers: res.headers };
  }

  /** Request a JSON endpoint with the parse guarded (invariant: never blind-parse). */
  async function requestJson(path) {
    const res = await request(path);
    const parsed = safeJsonParse(res.text);
    if (!res.ok) {
      return { ...res, json: parsed.ok ? parsed.value : null };
    }
    if (!parsed.ok) {
      throw new GitHubError(
        `GitHub returned status ${res.status} with a non-JSON body: ${res.text.trim().slice(0, 200)}`,
        "bad-response",
        res.status,
      );
    }
    return { ...res, json: parsed.value };
  }

  /** Fetch repo metadata, owner info, recent commits, and the file tree. */
  async function fetchRepo(owner, repo, ref = null) {
    const repoRes = await requestJson(`/repos/${owner}/${repo}`);
    if (repoRes.status === 404) {
      throw new GitHubError(
        `Repository ${owner}/${repo} was not found. It may be private, deleted, or the name may be wrong. RepoCanary can only scan public repositories (or private ones a GITHUB_TOKEN can read).`,
        "not-found",
        404,
      );
    }
    if (!repoRes.ok) {
      throw new GitHubError(
        `GitHub returned ${repoRes.status} for ${owner}/${repo}: ${String(repoRes.text).trim().slice(0, 200)}`,
        "server",
        repoRes.status,
      );
    }
    const repoJson = repoRes.json;
    // A hosted deployment scans on the operator's token, so whoever pasted
    // the URL is not the person that token belongs to: reading a private
    // repository for them would hand out file paths, line numbers and source
    // excerpts from something they cannot see. The CLI passes allowPrivate,
    // because there the token and the person holding it are the same.
    // Fails closed: only an explicit `private: false` counts as public.
    if (repoJson.private !== false && !allowPrivate) {
      throw new GitHubError(
        `Repository ${owner}/${repo} is private. This deployment only scans public repositories; run it locally with your own token: npx repocanary ${owner}/${repo}`,
        "not-found",
        404,
      );
    }
    const defaultBranch = repoJson.default_branch ?? "main";
    const scanRef = ref ?? defaultBranch;

    // Owner profile and recent commits are soft context signals; failures
    // here never block the scan.
    let ownerCreatedAt = null;
    let ownerPublicRepos = null;
    let orgPublicMembers = null;
    // These calls are soft, and a failure used to be indistinguishable from
    // a repository that simply had nothing to report: the account-age,
    // commit-burst and author rules read exactly these fields and quietly did
    // not fire. Silence about something nobody could read is not evidence,
    // which is the rule the byte caps already follow, so it is reported.
    let metaPartial = false;
    try {
      const ownerRes = await requestJson(`/users/${encodeURIComponent(owner)}`);
      if (ownerRes.ok) {
        ownerCreatedAt = ownerRes.json.created_at ?? null;
        ownerPublicRepos = ownerRes.json.public_repos ?? null;
      }
      if (repoJson.owner?.type === "Organization") {
        const membersRes = await requestJson(`/orgs/${encodeURIComponent(owner)}/public_members?per_page=30`);
        if (membersRes.ok && Array.isArray(membersRes.json)) {
          orgPublicMembers = membersRes.json.length;
        }
      }
    } catch (err) {
      if (err instanceof GitHubError && err.kind === "rate-limited") throw err;
      metaPartial = true;
    }

    let commitAuthorNames = [];
    let commitDates = [];
    try {
      const commitsRes = await requestJson(`/repos/${owner}/${repo}/commits?per_page=30`);
      if (commitsRes.ok && Array.isArray(commitsRes.json)) {
        commitAuthorNames = [
          ...new Set(commitsRes.json.map((c) => c?.commit?.author?.name).filter(Boolean)),
        ];
        commitDates = commitsRes.json.map((c) => c?.commit?.author?.date).filter(Boolean);
      }
    } catch (err) {
      if (err instanceof GitHubError && err.kind === "rate-limited") throw err;
      metaPartial = true;
    }

    const treeRes = await requestJson(
      `/repos/${owner}/${repo}/git/trees/${encodeURIComponent(scanRef)}?recursive=1`,
    );
    if (treeRes.status === 409) {
      throw new GitHubError(
        `Repository ${owner}/${repo} is empty; there is nothing to scan.`,
        "empty-repo",
        409,
      );
    }
    if (treeRes.status === 404) {
      throw new GitHubError(
        `Branch or ref "${scanRef}" was not found in ${owner}/${repo}.`,
        "not-found",
        404,
      );
    }
    if (!treeRes.ok) {
      throw new GitHubError(
        `Could not read the file tree of ${owner}/${repo} (status ${treeRes.status}).`,
        "server",
        treeRes.status,
      );
    }

    const rawTree = Array.isArray(treeRes.json?.tree) ? treeRes.json.tree : [];
    // Symlinks (mode 120000) are skipped: their content is a path, not code,
    // and following them is how scanners get walked out of the repo.
    // Submodules (type "commit") point at other repositories and are counted
    // but never fetched.
    const tree = rawTree.filter(
      (e) => e && e.type === "blob" && typeof e.path === "string" && e.mode !== "120000",
    );
    const submodules = rawTree.filter((e) => e && e.type === "commit").length;
    const symlinks = rawTree.filter((e) => e && e.mode === "120000").length;

    const meta = {
      owner,
      repo,
      defaultBranch,
      ref: scanRef,
      description: repoJson.description ?? null,
      topics: Array.isArray(repoJson.topics) ? repoJson.topics : [],
      stars: repoJson.stargazers_count ?? 0,
      createdAt: repoJson.created_at ?? null,
      pushedAt: repoJson.pushed_at ?? null,
      isFork: Boolean(repoJson.fork),
      ownerType: repoJson.owner?.type === "Organization" ? "Organization" : "User",
      ownerCreatedAt,
      ownerPublicRepos,
      orgPublicMembers,
      commitAuthorNames,
      commitDates,
    };

    return { meta, tree, treeTruncated: Boolean(treeRes.json?.truncated), submodules, symlinks, metaPartial };
  }

  /**
   * Fetch one file's raw text, size-capped. Returns null when the file is
   * missing, binary, or unreadable; only a rate limit aborts the whole scan.
   */
  async function fetchFile(owner, repo, ref, path) {
    try {
      const segments = path.split("/");
      // encodeURIComponent leaves "." and ".." alone, and fetch resolves them,
      // so such a segment would reach a different API endpoint with the token.
      if (segments.some((s) => s === "" || s === "." || s === "..")) return null;
      const encoded = segments.map(encodeURIComponent).join("/");
      const res = await request(`/repos/${owner}/${repo}/contents/${encoded}?ref=${encodeURIComponent(ref)}`, {
        raw: true,
      });
      if (!res.ok) return null;
      let text = res.text;
      if (text.length > MAX_FILE_BYTES) text = text.slice(0, MAX_FILE_BYTES);
      // Crude binary sniff: NUL bytes mean this is not text we can judge.
      if (text.includes("\u0000")) return null;
      return text;
    } catch (err) {
      if (err instanceof GitHubError && (err.kind === "rate-limited" || err.kind === "network")) {
        throw err;
      }
      return null;
    }
  }

  return { fetchRepo, fetchFile };
}
