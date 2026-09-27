// @ts-check

/**
 * Plain ESM, deliberately not next.config.ts.
 *
 * Next cannot read a TypeScript config without TypeScript, so it resolves the
 * `typescript` package from the app directory and calls into it before it will
 * look at a single setting. In a workspace, on a builder that restored a
 * partial node_modules cache, that resolution found something without a
 * Node-side `sys`, and the deploy died on
 *   TypeError: Cannot read properties of undefined (reading 'fileExists')
 * having never reached the config. The file only ever needed TypeScript for
 * one type annotation, which the JSDoc below provides at no cost: tsc still
 * checks this file, and nothing has to resolve a compiler to read it.
 *
 * The page holds a visitor's API key in a form field for the length of one
 * scan, so connect-src is the header that matters most here: it decides where
 * a script on this page could send that key if one ever got in. Nothing on
 * the site sets HTML from a string, so this is depth rather than a fix, which
 * is the right posture for the one control that would still hold if that
 * changed.
 *
 * 'unsafe-inline' for scripts is Next's hydration bootstrap; swap it for a
 * nonce if the app ever grows middleware. Styles need it for the same reason.
 */
const csp = [
  "default-src 'self'",
  "script-src 'self' 'unsafe-inline'",
  "style-src 'self' 'unsafe-inline'",
  "img-src 'self' data:",
  "connect-src 'self'",
  "font-src 'self'",
  "object-src 'none'",
  "base-uri 'none'",
  "form-action 'self'",
  "frame-ancestors 'none'",
].join("; ");

/** Security headers applied to every route. Safe defaults for a static, no-auth tool. */
const securityHeaders = [
  { key: "Content-Security-Policy", value: csp },
  { key: "X-Content-Type-Options", value: "nosniff" },
  { key: "X-Frame-Options", value: "DENY" },
  { key: "Referrer-Policy", value: "strict-origin-when-cross-origin" },
  { key: "X-DNS-Prefetch-Control", value: "on" },
  {
    key: "Strict-Transport-Security",
    value: "max-age=63072000; includeSubDomains; preload",
  },
  {
    key: "Permissions-Policy",
    value: "camera=(), microphone=(), geolocation=(), browsing-topics=()",
  },
];

/** @type {import("next").NextConfig} */
const nextConfig = {
  reactStrictMode: true,
  poweredByHeader: false,
  async headers() {
    return [{ source: "/:path*", headers: securityHeaders }];
  },
};

export default nextConfig;
