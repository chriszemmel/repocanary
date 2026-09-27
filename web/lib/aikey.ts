/**
 * Where a visitor's AI key goes, and where it does not.
 *
 * This lives apart from the route because it is the security-relevant half of
 * the AI pass: it decides which provider a pasted secret is sent to. A route
 * handler cannot export anything a test can call, and an invariant nobody can
 * test is an invariant nobody is keeping.
 */

// Relative rather than the "@engine/*" alias: this module is unit tested by
// `node --test`, which resolves imports itself and knows nothing of the
// tsconfig paths Next applies. The alias would make the invariants below
// untestable, which is the situation this file exists to end.
import { PROVIDERS, providerFromKey } from "../../src/ai.js";

/** A key longer than this is not a key; refuse it rather than forward it. */
export const MAX_KEY_LENGTH = 400;

export type ResolvedAi = { env: Record<string, string | undefined> } | { error: string };

/**
 * The visitor's key or nothing. There is no shared, operator-funded tier: a
 * pool of free AI calls attached to a public URL is a thing to drain, and
 * defending it would mean identifying visitors, which is the one thing a tool
 * for people who are being targeted must not do. Nobody is asked who they
 * are, so nobody can be given someone else's quota.
 *
 * The key goes into an environment object holding nothing but that key. The
 * engine picks the first configured provider it finds, so handing it the
 * server's environment could send a visitor's request to a provider they did
 * not choose.
 *
 * The key is never written to disk, logged, or returned. It lives for the
 * length of one request and no longer.
 */
export function resolveAi(aiKey: string | null, aiProvider: string | null): ResolvedAi {
  if (!aiKey) {
    return {
      error:
        "The AI second opinion runs on your own API key, which is never stored. Paste one above to use it. Gemini and Groq both issue free keys. The static verdict below does not depend on it.",
    };
  }
  if (aiKey.length > MAX_KEY_LENGTH) {
    return { error: "That API key looks too long to be a key. Nothing was sent anywhere." };
  }
  const provider = aiProvider ?? providerFromKey(aiKey);
  // hasOwnProperty, not a plain lookup: the name comes from the request body,
  // and "constructor" or "toString" would otherwise find something on the
  // prototype and read an envKey off it.
  const providers = PROVIDERS as Record<string, { envKey: string } | undefined>;
  const spec = provider && Object.prototype.hasOwnProperty.call(providers, provider) ? providers[provider] : undefined;
  if (!spec) {
    return {
      error:
        "Couldn't tell which provider that key belongs to. Pick the provider explicitly and try again. Nothing was sent anywhere.",
    };
  }
  return { env: { [spec.envKey]: aiKey } };
}
