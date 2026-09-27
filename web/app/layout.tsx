import type { Metadata, Viewport } from "next";
import "./globals.css";
import { SITE_URL } from "@/lib/siteurl";

// metadataBase makes the Open Graph and Twitter image URLs absolute, which
// social platforms require. See lib/siteurl.ts for how the origin is chosen.
const siteUrl = SITE_URL;

const title = "RepoCanary: Is that GitHub repo a trap?";
const description =
  "Free scanner for fake-interview malware. Paste a GitHub repo link and get a red/yellow/green verdict before you install it or open it in an editor. Static analysis only, no code is ever executed.";

export const metadata: Metadata = {
  metadataBase: new URL(siteUrl),
  title: {
    default: title,
    template: "%s · RepoCanary",
  },
  description,
  applicationName: "RepoCanary",
  keywords: [
    "fake job interview scam",
    "contagious interview",
    "malware repo scanner",
    "npm install malware",
    "GitHub repo safety",
    "developer security",
    "crypto stealer",
    "BeaverTail",
    "recruiter scam",
  ],
  authors: [{ name: "RepoCanary" }],
  creator: "RepoCanary",
  category: "security",
  alternates: { canonical: "/" },
  openGraph: {
    type: "website",
    url: siteUrl,
    siteName: "RepoCanary",
    title,
    description:
      "Paste a GitHub repo link, get a red/yellow/green verdict before you install it or open it in an editor. Built for anyone sent a repository by someone they cannot verify.",
  },
  twitter: {
    card: "summary_large_image",
    title,
    description:
      "Free scanner for fake-interview malware. Check a repo before you run it, or open it.",
  },
  robots: {
    index: true,
    follow: true,
    googleBot: { index: true, follow: true, "max-image-preview": "large" },
  },
};

export const viewport: Viewport = {
  width: "device-width",
  initialScale: 1,
  themeColor: "#0c0c0d",
};

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en" className="dark">
      <body className="min-h-screen bg-slate-950 text-slate-100 antialiased">
        {children}
      </body>
    </html>
  );
}
