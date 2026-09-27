import "./helpers.js";
import test from "node:test";
import assert from "node:assert/strict";
import { createGitHubClient, GitHubError, parseGitHubUrl, MAX_FILE_BYTES } from "../src/github.js";

/** Minimal Response stand-in for the injected fetch. */
function response(status, body, headers = {}) {
  const map = new Map(Object.entries(headers).map(([k, v]) => [k.toLowerCase(), String(v)]));
  return {
    status,
    ok: status >= 200 && status < 300,
    headers: { get: (k) => map.get(k.toLowerCase()) ?? null },
    text: async () => (typeof body === "string" ? body : JSON.stringify(body)),
  };
}

function clientWith(routes) {
  const calls = [];
  const fetchImpl = async (url, init) => {
    calls.push({ url, init });
    for (const [pattern, res] of routes) {
      if (url.includes(pattern)) return typeof res === "function" ? res(url, init) : res;
    }
    return response(404, { message: "Not Found" });
  };
  return { client: createGitHubClient({ token: "", fetchImpl }), calls };
}

test("parseGitHubUrl accepts the shapes people paste and rejects the rest", () => {
  assert.deepEqual(parseGitHubUrl("owner/repo"), { owner: "owner", repo: "repo" });
  assert.deepEqual(parseGitHubUrl("https://github.com/owner/repo"), { owner: "owner", repo: "repo" });
  assert.deepEqual(parseGitHubUrl("github.com/owner/repo.git"), { owner: "owner", repo: "repo" });
  assert.deepEqual(parseGitHubUrl("https://github.com/owner/repo/tree/main/src"), { owner: "owner", repo: "repo" });
  assert.equal(parseGitHubUrl("https://gitlab.com/owner/repo"), null);
  assert.equal(parseGitHubUrl("https://github.com/onlyowner"), null);
  assert.equal(parseGitHubUrl("owner/repo; rm -rf /"), null);
  assert.equal(parseGitHubUrl(""), null);
});

test("a 404 repo raises a not-found error that names the repo", async () => {
  const { client } = clientWith([["repos/acme/gone", response(404, { message: "Not Found" })]]);
  await assert.rejects(
    () => client.fetchRepo("acme", "gone"),
    (err) => err instanceof GitHubError && err.kind === "not-found" && err.message.includes("acme/gone"),
  );
});

test("an exhausted unauthenticated rate limit says exactly that", async () => {
  const { client } = clientWith([
    [
      "repos/acme/widget",
      response(403, { message: "rate limited" }, { "x-ratelimit-remaining": "0", "x-ratelimit-reset": "1767225600" }),
    ],
  ]);
  await assert.rejects(
    () => client.fetchRepo("acme", "widget"),
    (err) =>
      err.kind === "rate-limited" &&
      err.message.includes("unauthenticated rate limit") &&
      err.message.includes("GITHUB_TOKEN"),
  );
});

test("a bad token raises auth, a 500 raises server, a thrown fetch raises network", async () => {
  const cases = [
    [response(401, { message: "Bad credentials" }), "auth"],
    [response(500, "Internal Server Error"), "server"],
  ];
  for (const [res, kind] of cases) {
    const { client } = clientWith([["repos/", res]]);
    await assert.rejects(
      () => client.fetchRepo("acme", "widget"),
      (err) => err.kind === kind,
    );
  }

  const network = createGitHubClient({
    token: "",
    fetchImpl: async () => {
      throw new Error("getaddrinfo ENOTFOUND api.github.com");
    },
  });
  await assert.rejects(
    () => network.fetchRepo("acme", "widget"),
    (err) => err.kind === "network" && err.message.includes("api.github.com"),
  );
});

test("an empty repository raises empty-repo from the tree endpoint", async () => {
  const { client } = clientWith([
    ["/repos/acme/empty/git/trees/", response(409, { message: "Git Repository is empty." })],
    ["/repos/acme/empty/commits", response(200, [])],
    ["/repos/acme/empty", response(200, { default_branch: "main", private: false, owner: { type: "User" } })],
    ["/users/acme", response(200, { created_at: "2020-01-01T00:00:00Z", public_repos: 3 })],
  ]);
  await assert.rejects(
    () => client.fetchRepo("acme", "empty"),
    (err) => err.kind === "empty-repo" && err.message.includes("empty"),
  );
});

test("INVARIANT: a non-JSON body surfaces status and trimmed text, not a parser error", async () => {
  const { client } = clientWith([["repos/", response(200, "<html>maintenance page</html>")]]);
  await assert.rejects(
    () => client.fetchRepo("acme", "widget"),
    (err) => err.kind === "bad-response" && err.message.includes("maintenance page") && err.message.includes("200"),
  );
});

test("symlinks are dropped from the tree and submodules are counted", async () => {
  const tree = [
    { path: "index.js", type: "blob", mode: "100644", size: 10 },
    { path: "evil-link", type: "blob", mode: "120000", size: 20 },
    { path: "sub", type: "commit", mode: "160000" },
  ];
  const { client } = clientWith([
    ["/git/trees/", response(200, { tree, truncated: false })],
    ["/commits", response(200, [])],
    ["/users/acme", response(200, {})],
    ["/repos/acme/widget", response(200, { default_branch: "main", private: false, owner: { type: "User" } })],
  ]);
  const data = await client.fetchRepo("acme", "widget");
  assert.deepEqual(data.tree.map((e) => e.path), ["index.js"]);
  assert.equal(data.submodules, 1);
});

test("file fetches cap size, reject NUL bytes, and survive 404s", async () => {
  const big = "a".repeat(MAX_FILE_BYTES + 1000);
  const { client } = clientWith([
    ["contents/big.js", response(200, big)],
    ["contents/binary.dat", response(200, "abc\u0000def")],
    ["contents/missing.js", response(404, { message: "Not Found" })],
  ]);
  const bigText = await client.fetchFile("acme", "widget", "main", "big.js");
  assert.equal(bigText.length, MAX_FILE_BYTES);
  assert.equal(await client.fetchFile("acme", "widget", "main", "binary.dat"), null);
  assert.equal(await client.fetchFile("acme", "widget", "main", "missing.js"), null);
});

test("a rate limit mid-fetch aborts the scan instead of returning null", async () => {
  const { client } = clientWith([
    ["contents/", response(429, { message: "too many" }, { "x-ratelimit-remaining": "0" })],
  ]);
  await assert.rejects(
    () => client.fetchFile("acme", "widget", "main", "x.js"),
    (err) => err.kind === "rate-limited",
  );
});

test("ETags are remembered in memory and 304 responses reuse the cached body", async () => {
  let hits = 0;
  const fetchImpl = async (url, init) => {
    hits++;
    if (init.headers["If-None-Match"] === '"abc"') return response(304, "");
    return response(200, "cached content", { etag: '"abc"' });
  };
  const client = createGitHubClient({ token: "", fetchImpl });
  const first = await client.fetchFile("acme", "widget", "main", "x.js");
  const second = await client.fetchFile("acme", "widget", "main", "x.js");
  assert.equal(first, "cached content");
  assert.equal(second, "cached content");
  assert.equal(hits, 2);
});

test("the token is sent to api.github.com requests when configured", async () => {
  const seen = [];
  const fetchImpl = async (url, init) => {
    seen.push(init.headers.Authorization);
    return response(200, "x");
  };
  const client = createGitHubClient({ token: "tok_123", fetchImpl });
  await client.fetchFile("acme", "widget", "main", "x.js");
  assert.deepEqual(seen, ["Bearer tok_123"]);
});

test("a raw file is read only up to the cap, not downloaded whole", async () => {
  let pulled = 0;
  const chunk = new TextEncoder().encode("a".repeat(64 * 1024));
  const body = new ReadableStream({
    pull(controller) {
      pulled += chunk.byteLength;
      if (pulled > 50 * MAX_FILE_BYTES) controller.close();
      else controller.enqueue(chunk);
    },
  });
  const { client } = clientWith([["/contents/", { ...response(200, ""), body }]]);
  const text = await client.fetchFile("o", "r", "main", "huge.js");
  assert.equal(text.length, MAX_FILE_BYTES);
  assert.ok(pulled < 5 * MAX_FILE_BYTES, `pulled ${pulled} bytes`);
});

test("a repository whose visibility is not stated is treated as private", async () => {
  const { client } = clientWith([["/repos/acme/vague", response(200, { default_branch: "main", owner: { type: "User" } })]]);
  await assert.rejects(client.fetchRepo("acme", "vague"), (err) => err instanceof GitHubError && err.kind === "not-found");
});

test("a path segment of . or .. is never sent to the API", async () => {
  const { client, calls } = clientWith([["/contents/", response(200, "x")]]);
  for (const path of ["../../../../users/x", "a/./b.js", "a//b.js"]) {
    assert.equal(await client.fetchFile("o", "r", "main", path), null);
  }
  assert.equal(calls.length, 0);
});
