import test from "node:test";
import assert from "node:assert/strict";
import { buildScanRequest, canScan, GENERIC_ERROR, interpretScanResponse } from "./scanrequest.ts";

const form = { url: "https://github.com/acme/widget", useAi: false, aiKey: "", aiProvider: "" };

test("the form submits only with a non-blank URL and no scan in flight", () => {
  assert.equal(canScan({ url: "   " }, false), false);
  assert.equal(canScan({ url: "acme/widget" }, true), false);
  assert.equal(canScan({ url: "acme/widget" }, false), true);
});

test("without the AI pass the key never leaves the tab", () => {
  const body = buildScanRequest({ ...form, aiKey: "sk-secret", aiProvider: "openai" });
  assert.deepEqual(body, { url: form.url, ai: false });
});

test("with the AI pass and a key, the key and the chosen provider are sent; blank provider means detect", () => {
  assert.deepEqual(buildScanRequest({ ...form, useAi: true, aiKey: "  AIza-key  ", aiProvider: "" }), {
    url: form.url,
    ai: true,
    aiKey: "AIza-key",
    aiProvider: null,
  });
  assert.equal(buildScanRequest({ ...form, useAi: true, aiKey: "gsk_key", aiProvider: "groq" }).aiProvider, "groq");
});

test("with the AI pass and no key, the request asks for the shared allowance", () => {
  assert.deepEqual(buildScanRequest({ ...form, useAi: true, aiKey: "   " }), { url: form.url, ai: true });
});

test("a server error message is shown verbatim; a shapeless failure gets the generic message", () => {
  assert.deepEqual(interpretScanResponse(false, { error: "Too many scans.", code: "rate_limited" }), {
    kind: "error",
    message: "Too many scans.",
  });
  assert.deepEqual(interpretScanResponse(false, "<html>502</html>"), { kind: "error", message: GENERIC_ERROR });
  assert.deepEqual(interpretScanResponse(false, null), { kind: "error", message: GENERIC_ERROR });
});

test("a 2xx reply that is not a scan result is an error, never a blank verdict", () => {
  assert.equal(interpretScanResponse(true, {}).kind, "error");
  assert.equal(interpretScanResponse(true, { verdict: "safe", findings: [] }).kind, "error");
  assert.equal(interpretScanResponse(true, { verdict: "green" }).kind, "error");
});

test("a well-formed result passes through untouched", () => {
  const result = { verdict: "green", findings: [], headline: "x", notes: [] };
  const outcome = interpretScanResponse(true, result);
  assert.equal(outcome.kind, "result");
  if (outcome.kind === "result") assert.equal(outcome.result, result);
});
