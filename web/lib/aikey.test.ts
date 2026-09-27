import test from "node:test";
import assert from "node:assert/strict";
import { MAX_KEY_LENGTH, resolveAi } from "./aikey.ts";

test("INVARIANT: without a key the pass does not run, on anyone else's account", () => {
  // The site holds no provider key, so there is nothing here to fall back to
  // and nothing to ration. Rationing would mean identifying visitors.
  const resolved = resolveAi(null, null);
  assert.ok("error" in resolved, "no key must not resolve to an environment");
  assert.match(resolved.error, /your own API key/);
});

test("INVARIANT: a key reaches exactly one provider's variable and no other", () => {
  const resolved = resolveAi("sk-ant-visitor-key", "anthropic");
  assert.ok("env" in resolved);
  assert.deepEqual(resolved.env, { ANTHROPIC_API_KEY: "sk-ant-visitor-key" });
  // Not merged over process.env: the engine takes the first provider it finds
  // a key for, so a stray variable in the server's environment could send a
  // visitor's request somewhere they did not choose.
  assert.equal(Object.keys(resolved.env).length, 1);
});

test("the provider is detected from the key when the visitor did not say", () => {
  for (const [key, variable] of [
    ["sk-ant-x", "ANTHROPIC_API_KEY"],
    ["gsk_x", "GROQ_API_KEY"],
    ["AIzaX", "GEMINI_API_KEY"],
    ["sk-proj-x", "OPENAI_API_KEY"],
  ] as const) {
    const resolved = resolveAi(key, null);
    assert.ok("env" in resolved, `${key} should resolve`);
    assert.deepEqual(Object.keys(resolved.env), [variable]);
  }
});

test("an ambiguous key prefix is asked about rather than guessed", () => {
  // "sk-" is minted by OpenRouter, DeepSeek, Fireworks, Together and anything
  // running vLLM or LiteLLM. Guessing OpenAI would post a live secret to a
  // company the visitor never chose, so this is the one place a convenience
  // is worth giving up. Naming the provider explicitly still works.
  for (const key of ["sk-x", "sk-or-v1-x", "sk-deepseek-x"]) {
    const resolved = resolveAi(key, null);
    assert.ok("error" in resolved, `${key} must not be routed by guess`);
    assert.match(resolved.error, /provider/i);
  }
  const explicit = resolveAi("sk-or-v1-x", "openai");
  assert.ok("env" in explicit);
  assert.deepEqual(Object.keys(explicit.env), ["OPENAI_API_KEY"]);
});

test("an unrecognised key is refused rather than guessed at", () => {
  const resolved = resolveAi("not-a-key-shape", null);
  assert.ok("error" in resolved);
  assert.match(resolved.error, /Nothing was sent anywhere/);
});

test("an oversized key is refused before it is forwarded", () => {
  const resolved = resolveAi(`sk-${"x".repeat(MAX_KEY_LENGTH)}`, "openai");
  assert.ok("error" in resolved);
  assert.match(resolved.error, /Nothing was sent anywhere/);
});

test("an unknown provider name cannot invent an environment variable", () => {
  // The name comes from the request body, so it is attacker-controlled.
  const resolved = resolveAi("sk-x", "constructor");
  assert.ok("error" in resolved, "a prototype key must not resolve to a provider");
});
