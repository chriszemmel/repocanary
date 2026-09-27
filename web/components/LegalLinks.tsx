import Link from "next/link";

/** The legal-notice and privacy links every page's footer carries. */
export default function LegalLinks() {
  return (
    <p className="mt-2">
      <Link href="/legal-notice" className="underline">
        Legal notice
      </Link>{" "}
      ·{" "}
      <Link href="/privacy" className="underline">
        Privacy
      </Link>
    </p>
  );
}
