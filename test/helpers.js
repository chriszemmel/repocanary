/**
 * Shared test helpers.
 *
 * Importing this module disables the network for the whole test process:
 * global fetch is replaced with a function that throws. Every test file
 * imports it first, so no test can ever touch the network, by construction.
 */

import { readdirSync, readFileSync, statSync } from "node:fs";
import { join, relative, sep } from "node:path";
import { fileURLToPath } from "node:url";
import { dirname } from "node:path";
import { scanRepo } from "../src/scan.js";

globalThis.fetch = () => {
  throw new Error("A test tried to touch the network. Tests must be fully offline.");
};

export const TEST_DIR = dirname(fileURLToPath(import.meta.url));
export const FIXTURES_DIR = join(TEST_DIR, "fixtures");
export const CORPUS_DIR = join(FIXTURES_DIR, "corpus");

/** Fixed clock so context signals (account age, bursts) are deterministic. */
export const FIXED_NOW = Date.parse("2026-01-01T00:00:00Z");

/** A boring, established repo and owner. Overridden per fixture as needed. */
export function defaultMeta(overrides = {}) {
  return {
    owner: "acme",
    repo: "widget",
    defaultBranch: "main",
    ref: "main",
    description: "A small widget service",
    topics: [],
    stars: 12,
    createdAt: "2021-03-01T00:00:00Z",
    pushedAt: "2025-11-20T00:00:00Z",
    isFork: false,
    ownerType: "User",
    ownerCreatedAt: "2015-06-01T00:00:00Z",
    ownerPublicRepos: 24,
    orgPublicMembers: null,
    commitAuthorNames: ["acme"],
    commitDates: [
      "2025-02-03T10:00:00Z",
      "2025-04-11T10:00:00Z",
      "2025-06-24T10:00:00Z",
      "2025-09-02T10:00:00Z",
      "2025-11-20T10:00:00Z",
    ],
    ...overrides,
  };
}

/**
 * Build an injectable client from an in-memory {path: content} map, exactly
 * mirroring the shape src/github.js returns.
 */
export function makeClient(files, { meta = {}, treeTruncated = false, submodules = 0 } = {}) {
  const fullMeta = defaultMeta(meta);
  // A null value means the file is in the tree but cannot be read as text,
  // which is what the real client returns for a binary or failed fetch.
  const tree = Object.entries(files).map(([path, content]) => ({
    path,
    type: "blob",
    size: content?.length ?? 0,
  }));
  return {
    fetchRepo: async () => ({ meta: fullMeta, tree, treeTruncated, submodules }),
    fetchFile: async (owner, repo, ref, path) => (path in files ? files[path] : null),
  };
}

function walkFiles(dir, base = dir) {
  const out = {};
  for (const entry of readdirSync(dir)) {
    const full = join(dir, entry);
    if (statSync(full).isDirectory()) Object.assign(out, walkFiles(full, base));
    // Repository paths use "/" whatever the host OS, as GitHub's tree does.
    else out[relative(base, full).split(sep).join("/")] = readFileSync(full, "utf8");
  }
  return out;
}

/** Load one corpus fixture directory into { files, expected, meta }. */
export function loadFixture(name) {
  const dir = join(CORPUS_DIR, name);
  const expected = JSON.parse(readFileSync(join(dir, "expected.json"), "utf8"));
  let meta = {};
  try {
    meta = JSON.parse(readFileSync(join(dir, "meta.json"), "utf8"));
  } catch {
    // Fixture uses the default meta.
  }
  const files = walkFiles(join(dir, "files"));
  return { files, expected, meta };
}

export function listFixtures() {
  return readdirSync(CORPUS_DIR).filter((e) => statSync(join(CORPUS_DIR, e)).isDirectory()).sort();
}

/** Run a full scan over a corpus fixture, offline. */
export async function scanFixture(name) {
  const { files, expected, meta } = loadFixture(name);
  const client = makeClient(files, { meta });
  const result = await scanRepo({ owner: "acme", repo: "widget", client, now: FIXED_NOW });
  return { result, expected };
}
