import type { MetadataRoute } from "next";
import { SITE_URL as siteUrl } from "@/lib/siteurl";

export default function robots(): MetadataRoute.Robots {
  return {
    rules: { userAgent: "*", allow: "/", disallow: ["/api/", "/badge/"] },
    sitemap: `${siteUrl}/sitemap.xml`,
    host: siteUrl,
  };
}
