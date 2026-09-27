import type { Metadata } from "next";
import Link from "next/link";
import LegalShell from "@/components/LegalShell";
import { OPERATOR } from "@/lib/operator";

export const metadata: Metadata = {
  title: "Legal notice",
  description: "Provider identification (Impressum) for RepoCanary.",
  alternates: { canonical: "/legal-notice" },
};

export default function LegalNotice() {
  return (
    <LegalShell title="Legal notice" subtitle="Impressum · provider identification">
      <section>
        <h2>Information pursuant to § 5 DDG</h2>
        <p>
          {OPERATOR.name}
          <br />
          {OPERATOR.street}
          <br />
          {OPERATOR.city}
          <br />
          {OPERATOR.country}
        </p>
      </section>

      <section>
        <h2>Contact</h2>
        <p>
          Email: <a href={`mailto:${OPERATOR.email}`}>{OPERATOR.email}</a>
        </p>
        <p>
          Bugs and false results are best reported as an issue on{" "}
          <a href="https://github.com/chriszemmel/repocanary/issues" target="_blank" rel="noopener noreferrer">
            GitHub
          </a>
          . Security issues in RepoCanary itself are reported privately, as{" "}
          <a
            href="https://github.com/chriszemmel/repocanary/blob/main/SECURITY.md"
            target="_blank"
            rel="noopener noreferrer"
          >
            SECURITY.md
          </a>{" "}
          describes.
        </p>
      </section>

      <section>
        <h2>Responsible for the content pursuant to § 18 (2) MStV</h2>
        <p>
          {OPERATOR.name}
          <br />
          Address as above
        </p>
      </section>

      <section>
        <h2>Consumer dispute resolution</h2>
        <p>
          I am neither willing nor obliged to participate in dispute resolution proceedings before a
          consumer arbitration board.
        </p>
      </section>

      <section>
        <h2>Liability for content</h2>
        <p>
          As a service provider, I am responsible for my own content on these pages in accordance with
          § 7 (1) DDG under general law. According to §§ 8 to 10 DDG, however, I am not obliged as a
          service provider to monitor transmitted or stored third-party information, or to investigate
          circumstances that indicate illegal activity. Obligations to remove or block the use of
          information under general law remain unaffected.
        </p>
        <p>
          RepoCanary is an automated heuristic, not a guarantee. A scan result describes which known
          patterns matched in a repository&rsquo;s files; it is not a statement about the people behind
          that repository, and a green result does not prove that a repository is safe.
        </p>
      </section>

      <section>
        <h2>Liability for links</h2>
        <p>
          This site contains links to external third-party websites over whose content I have no
          influence. I therefore cannot accept any liability for this third-party content. The
          respective provider or operator of the linked pages is always responsible for their content.
        </p>
      </section>

      <section>
        <h2>Source code and license</h2>
        <p>
          RepoCanary is open source under the MIT license. The license covers the software; this legal
          notice covers this website.
        </p>
      </section>

      <p>
        See also the <Link href="/privacy">privacy policy</Link>.
      </p>
    </LegalShell>
  );
}
