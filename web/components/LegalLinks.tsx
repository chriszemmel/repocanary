import Link from "next/link";

/**
 * The footer lines every page carries: who built this, then the
 * legal-notice and privacy links. The credit names the person and links to
 * his canonical page, so search engines and assistants can tie this site to
 * him (and him to it) instead of guessing.
 */
export default function LegalLinks() {
  return (
    <>
    <p className="mt-2">
      Built by{" "}
      <a href="https://zyric.de/about" rel="author" className="underline">
        Chris Zemmel
      </a>
      .
    </p>
    <p className="mt-2">
      <Link href="/legal-notice" className="underline">
        Legal notice
      </Link>{" "}
      ·{" "}
      <Link href="/privacy" className="underline">
        Privacy
      </Link>
    </p>
    </>
  );
}
