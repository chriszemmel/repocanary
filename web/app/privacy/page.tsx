import type { Metadata } from "next";
import Link from "next/link";
import LegalShell from "@/components/LegalShell";
import { OPERATOR } from "@/lib/operator";

export const metadata: Metadata = {
  title: "Privacy policy",
  description:
    "What RepoCanary processes when you scan a repository: no account, no cookies, no analytics, and nothing written to disk.",
  alternates: { canonical: "/privacy" },
};

export default function Privacy() {
  return (
    <LegalShell title="Privacy policy" subtitle="Datenschutzerklärung · last updated 27 September 2026">
      <section>
        <h2>In short</h2>
        <p>
          No account, no cookies, no analytics, no tracking and no database. A scan sends the repository
          link you enter to this site&rsquo;s server, which reads that repository&rsquo;s public files
          from GitHub and returns the result to your browser. Apart from the hosting logs and a
          short-lived request counter described below, nothing about you is kept, and nothing about a
          scan is written to disk.
        </p>
      </section>

      <section>
        <h2>1. Controller</h2>
        <p>The controller within the meaning of the General Data Protection Regulation (GDPR) is:</p>
        <p>
          {OPERATOR.name}
          <br />
          {OPERATOR.street}
          <br />
          {OPERATOR.city}, {OPERATOR.country}
          <br />
          Email: <a href={`mailto:${OPERATOR.email}`}>{OPERATOR.email}</a>
        </p>
      </section>

      <section>
        <h2>2. Hosting</h2>
        <p>
          This website is hosted by Vercel Inc., USA, which acts as a processor. When you open a page or
          run a scan, technically necessary access data is processed to deliver the page and keep the
          service secure and working: your IP address, the time of access, the requested path, the
          volume of data transferred, the referring page and your browser&rsquo;s user agent. When a scan
          fails, the server writes the error to its log; such an entry can contain the name of the
          repository you tried to scan, but never your IP address or an API key. These logs are kept for
          the retention period Vercel applies to them.
        </p>
        <p>
          The legal basis is Art. 6 (1) (f) GDPR (legitimate interest in the secure and stable operation
          of the site). Vercel is certified under the EU-U.S. Data Privacy Framework, so the transfer to
          the USA rests on the adequacy decision of the European Commission (Art. 45 GDPR).
        </p>
      </section>

      <section>
        <h2>3. Scanning a repository</h2>
        <p>
          When you press Scan, your browser sends the repository link you entered to this site&rsquo;s
          server. The server then reads that repository&rsquo;s public files and metadata from the GitHub
          API (GitHub, Inc., USA). The request to GitHub is made by the server, not by your browser, so
          GitHub does not receive your IP address from it. The repository is never cloned, installed or
          run.
        </p>
        <p>
          The result is sent back to your browser. So that a repository many people check at once is
          not read from GitHub again for each of them, the server keeps the scan result for that
          repository in its memory for up to ten minutes and answers the same question from it. This
          cached result describes the public repository only; it does not record who asked. There is
          no database, and nothing about a scan is written to disk.
        </p>
        <p>
          To stop a single client from overloading the service, the server counts requests per IP
          address. Requests older than ten minutes no longer count and are cleared out at the next routine
          sweep; the counter lives only in the server&rsquo;s memory, disappears when the server instance
          stops, and is never written to disk or shared.
        </p>
        <p>
          The legal basis is Art. 6 (1) (b) GDPR (providing the scan you asked for) and, for the request
          counter, Art. 6 (1) (f) GDPR (legitimate interest in protecting the service from abuse).
        </p>
      </section>

      <section>
        <h2>4. Optional AI second opinion</h2>
        <p>
          Only if you tick the AI box and enter your own API key, the scan&rsquo;s findings (file paths,
          shortened and redacted code snippets, the reasons for each finding, and up to 600 redacted
          bytes of an install script a finding points at), the repository&rsquo;s address and its public
          metadata are sent, together with your key, to the provider you chose: Google (Gemini), Groq,
          OpenAI or Anthropic, all based in the USA. Nothing from your own computer is included.
        </p>
        <p>
          Your key passes through this site&rsquo;s server only to make that one request to your
          provider. It is never stored, never logged and never written to disk, and your browser keeps it
          only in the open page, not in local storage. The provider processes the request under your own
          agreement with it and its privacy policy.
        </p>
        <p>
          The legal basis is Art. 6 (1) (a) GDPR (your consent, given by switching the option on and
          entering a key) and Art. 6 (1) (b) GDPR. Without the option, nothing is sent to any AI provider.
        </p>
      </section>

      <section>
        <h2>5. README badges</h2>
        <p>
          A RepoCanary badge in a README is loaded by GitHub&rsquo;s image proxy, not by the reader&rsquo;s
          browser, so this site does not learn who views a README. To keep this cheap, the server keeps a
          badge&rsquo;s verdict in memory for up to one day. That verdict describes the repository, not a
          person.
        </p>
      </section>

      <section>
        <h2>6. Cookies, analytics and external content</h2>
        <p>
          This site sets no cookies and uses no local storage. It runs no analytics, no reach measurement
          and no tracking. It loads no fonts, scripts or images from other servers; the page&rsquo;s
          content security policy only allows connections to this site itself. Links to other sites, for
          example to GitHub or to a provider&rsquo;s key page, only transfer data to that site once you
          click them.
        </p>
      </section>

      <section>
        <h2>7. Command-line tool</h2>
        <p>
          <code>npx repocanary</code> runs on your own computer. It contacts only the GitHub API, with your
          own token if you set one, and, with <code>--ai</code>, the AI provider you choose. It sends
          nothing to this site or to me and has no telemetry. Downloading the package through npm is
          subject to npm&rsquo;s own privacy statement.
        </p>
      </section>

      <section>
        <h2>8. Contact by email</h2>
        <p>
          If you write to me by email, I process your email address and your message to answer you. The
          legal basis is Art. 6 (1) (f) GDPR (legitimate interest in answering enquiries) or Art. 6 (1)
          (b) GDPR where your enquiry concerns a contract. I delete the correspondence once it is settled,
          unless statutory retention obligations require otherwise.
        </p>
      </section>

      <section>
        <h2>9. Your rights</h2>
        <p>
          You have the right of access (Art. 15 GDPR), rectification (Art. 16), erasure (Art. 17),
          restriction of processing (Art. 18), data portability (Art. 20) and to object to processing
          based on Art. 6 (1) (f) GDPR (Art. 21). Where processing rests on your consent, you can withdraw
          it at any time with effect for the future (Art. 7 (3)). An email to the address above is enough.
          Because this site keeps nothing that identifies you, there is usually nothing on record to hand over.
        </p>
      </section>

      <section>
        <h2>10. Right to lodge a complaint</h2>
        <p>
          You have the right to lodge a complaint with a data protection supervisory authority. The
          authority competent for me is the State Commissioner for Data Protection and Freedom of
          Information of Baden-Württemberg (Der Landesbeauftragte für den Datenschutz und die
          Informationsfreiheit Baden-Württemberg).
        </p>
      </section>

      <p>
        See also the <Link href="/legal-notice">legal notice</Link>.
      </p>
    </LegalShell>
  );
}
