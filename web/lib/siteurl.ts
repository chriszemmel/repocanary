/**
 * The site's own absolute URL, for canonical links, the sitemap, robots.txt
 * and social images, which all need a full origin.
 *
 * NEXT_PUBLIC_SITE_URL wins when set. Otherwise a production build assumes
 * the canonical domain and a development server assumes localhost. No
 * hosting platform is consulted: the site runs wherever Node runs.
 */
export const CANONICAL_SITE_URL = "https://repocanary.com";

export const SITE_URL =
  process.env.NEXT_PUBLIC_SITE_URL?.replace(/\/+$/, "") ||
  (process.env.NODE_ENV === "production" ? CANONICAL_SITE_URL : "http://localhost:3000");
