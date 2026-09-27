"use client";

import { useEffect, useState } from "react";
import LegalLinks from "@/components/LegalLinks";
import ResultCard from "@/components/ResultCard";
import { ArrowRight, Briefcase, Check, Wordmark } from "@/components/icons";
import type { ScanResult } from "@/lib/types";
import { AI_PROVIDERS, buildScanRequest, canScan, interpretScanResponse, NETWORK_ERROR } from "@/lib/scanrequest";

const EXAMPLE_URL = "https://github.com/sindresorhus/slugify";

export default function Home() {
  const [url, setUrl] = useState("");
  const [useAi, setUseAi] = useState(false);
  // The key lives in component state for as long as the tab is open and
  // nowhere else. It is deliberately never put in localStorage: this page
  // exists to warn people about credential theft.
  const [aiKey, setAiKey] = useState("");
  const [aiProvider, setAiProvider] = useState("");
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [result, setResult] = useState<ScanResult | null>(null);

  // A badge in a README links here with ?repo=owner/repo. Prefill the field
  // and nothing more: a link must not be able to start a scan by itself.
  useEffect(() => {
    const repo = new URLSearchParams(window.location.search).get("repo");
    if (repo && /^[A-Za-z0-9][A-Za-z0-9._-]*\/[A-Za-z0-9][A-Za-z0-9._-]*$/.test(repo)) {
      setUrl(`https://github.com/${repo}`);
    }
  }, []);

  async function scan(target: string) {
    if (!canScan({ url: target }, loading)) return;
    setLoading(true);
    setError(null);
    setResult(null);
    try {
      const res = await fetch("/api/scan", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(buildScanRequest({ url: target, useAi, aiKey, aiProvider })),
      });
      const outcome = interpretScanResponse(res.ok, await res.json());
      if (outcome.kind === "error") setError(outcome.message);
      else setResult(outcome.result);
    } catch {
      setError(NETWORK_ERROR);
    } finally {
      setLoading(false);
    }
  }

  return (
    <main className="mx-auto max-w-2xl px-4 pt-14 pb-10 sm:pt-20">
      {/* Hero */}
      <header className="text-center">
        <div className="flex items-center justify-center">
          <Wordmark />
        </div>
        <h1 className="mt-6 text-3xl font-semibold tracking-tight sm:text-4xl">
          Is that GitHub repo a trap?
        </h1>
        <p className="mx-auto mt-3 max-w-md text-base text-slate-500 dark:text-slate-400">
          Paste a repo link and check it for fake-interview malware before you run it.
        </p>
        <p className="mt-3 text-sm">
          <a href="/coverage" className="font-medium text-blue-600 underline dark:text-blue-400">
            See what it detects
          </a>
          <span className="text-slate-400 dark:text-slate-400"> · every technique, measured</span>
        </p>
      </header>

      {/* Scan form */}
      <form
        className="mt-8 flex flex-col gap-3 sm:flex-row"
        onSubmit={(e) => {
          e.preventDefault();
          scan(url);
        }}
      >
        <input
          type="text"
          inputMode="url"
          value={url}
          onChange={(e) => setUrl(e.target.value)}
          placeholder="https://github.com/owner/repo"
          aria-label="GitHub repository URL"
          className="w-full flex-1 rounded-xl border border-slate-300 bg-white px-4 py-3 text-base shadow-sm outline-none placeholder:text-slate-400 focus:border-blue-500 focus:ring-2 focus:ring-blue-500/30 dark:border-slate-700 dark:bg-slate-900"
        />
        <button
          type="submit"
          disabled={loading || !url.trim()}
          aria-busy={loading}
          className="rounded-xl bg-blue-600 px-6 py-3 font-semibold text-slate-950 shadow-sm transition hover:bg-blue-400 focus-visible:ring-2 focus-visible:ring-blue-500/40 focus-visible:outline-none disabled:cursor-not-allowed disabled:opacity-50"
        >
          {loading ? "Scanning…" : "Scan"}
        </button>
      </form>

      <label className="mt-3 flex cursor-pointer items-start gap-2 text-sm text-slate-500 select-none dark:text-slate-400">
        <input
          type="checkbox"
          checked={useAi}
          onChange={(e) => setUseAi(e.target.checked)}
          disabled={loading}
          className="mt-0.5 h-4 w-4 rounded border-slate-300 accent-blue-600"
        />
        Add an AI second opinion that double-checks the findings in plainer English.
      </label>

      {/* Bring your own key: optional, and never stored anywhere. */}
      {useAi && (
        <div className="mt-3 rounded-xl border border-slate-200 bg-slate-50 p-4 dark:border-slate-800 dark:bg-slate-900/60">
          <div className="flex flex-col gap-2.5 sm:flex-row">
            <input
              type="password"
              value={aiKey}
              onChange={(e) => setAiKey(e.target.value)}
              disabled={loading}
              placeholder="Your own API key"
              aria-label="Your own AI provider API key"
              autoComplete="off"
              autoCorrect="off"
              autoCapitalize="off"
              spellCheck={false}
              className="w-full flex-1 rounded-lg border border-slate-300 bg-white px-3 py-2 font-mono text-sm shadow-sm outline-none placeholder:font-sans placeholder:text-slate-400 focus:border-blue-500 focus:ring-2 focus:ring-blue-500/30 dark:border-slate-700 dark:bg-slate-900"
            />
            <select
              value={aiProvider}
              onChange={(e) => setAiProvider(e.target.value)}
              disabled={loading}
              aria-label="AI provider"
              className="rounded-lg border border-slate-300 bg-white px-3 py-2 text-sm shadow-sm outline-none focus:border-blue-500 focus:ring-2 focus:ring-blue-500/30 dark:border-slate-700 dark:bg-slate-900"
            >
              {AI_PROVIDERS.map((p) => (
                <option key={p.value} value={p.value}>
                  {p.label}
                </option>
              ))}
            </select>
          </div>
          <p className="mt-2.5 text-xs leading-relaxed text-slate-500 dark:text-slate-400">
            The key is yours, used for this one request and never stored. This site keeps no key of its own,
            so there is nothing here for anyone to drain and no reason to ask who you are.{" "}
            <strong className="font-medium text-slate-600 dark:text-slate-300">
              You do not have to pay for this.
            </strong>{" "}
            Gemini and Groq both hand out free API keys with no billing details, at{" "}
            <a
              href="https://aistudio.google.com/apikey"
              target="_blank"
              rel="noopener noreferrer"
              className="underline underline-offset-2 hover:text-slate-700 dark:hover:text-slate-200"
            >
              aistudio.google.com/apikey
            </a>{" "}
            and{" "}
            <a
              href="https://console.groq.com/keys"
              target="_blank"
              rel="noopener noreferrer"
              className="underline underline-offset-2 hover:text-slate-700 dark:hover:text-slate-200"
            >
              console.groq.com/keys
            </a>
            . OpenAI and Anthropic keys work too, but they bill your account for each scan.
          </p>
          <p className="mt-2 text-xs leading-relaxed text-slate-500 dark:text-slate-400">
            A key you enter is used for this one scan and is never stored, never logged, and never
            written to disk. It is sent to this server only to make the request to your provider.
            Nothing else about the scan changes: the AI can add a caution or clear one, and can
            never downgrade a danger result or create one.
          </p>
        </div>
      )}

      <div className="mt-4 flex flex-wrap items-center justify-between gap-3 text-sm">
        <button
          type="button"
          onClick={() => {
            setUrl(EXAMPLE_URL);
            scan(EXAMPLE_URL);
          }}
          disabled={loading}
          className="inline-flex items-center gap-1 font-medium text-blue-600 hover:text-blue-500 disabled:opacity-50 dark:text-blue-400"
        >
          Try an example
          <ArrowRight className="h-4 w-4" />
        </button>
        <a
          href="#how-the-scam-works"
          className="inline-flex items-center gap-1.5 text-slate-500 hover:text-slate-700 dark:text-slate-400 dark:hover:text-slate-200"
        >
          <Briefcase className="h-4 w-4" />
          How this scam works
        </a>
      </div>

      {/* Loading state */}
      {loading && (
        <div
          role="status"
          aria-live="polite"
          className="mt-8 rounded-2xl border border-slate-200 bg-white p-6 text-center shadow-sm dark:border-slate-800 dark:bg-slate-900"
        >
          <div className="mx-auto h-7 w-7 animate-spin rounded-full border-[3px] border-blue-500 border-t-transparent" />
          <p className="mt-3 text-sm text-slate-500 dark:text-slate-400">
            Reading the repo&rsquo;s files (never running them) and checking for known malware
            patterns…{useAi && " Then asking the AI to double-check…"}
          </p>
        </div>
      )}

      {/* Error state */}
      {error && (
        <div
          role="alert"
          className="mt-8 rounded-2xl border border-red-300 bg-red-50 p-5 text-sm text-red-800 dark:border-red-900 dark:bg-red-950/50 dark:text-red-200"
        >
          <strong className="font-semibold">Couldn&rsquo;t scan that. </strong>
          {error}
        </div>
      )}

      {/* Result */}
      {result && <ResultCard result={result} />}

      {/* How the scam works */}
      <section id="how-the-scam-works" className="mt-16 scroll-mt-8">
        <h2 className="text-xl font-semibold tracking-tight">
          How the &ldquo;fake interview&rdquo; scam works
        </h2>
        <ol className="mt-4 space-y-4 text-slate-700 dark:text-slate-300">
          {[
            {
              title: "Someone reaches out",
              body: "Usually a recruiter, on LinkedIn or Telegram, for an attractive remote role at a crypto, Web3, AI, or fintech company you can't quite verify. It is not always hiring, though: the same approach arrives as a client, a collaborator, or someone asking you to look over their project.",
            },
            {
              title: "You are asked to look at a repo",
              body: "Sometimes it is a take-home task: clone it, run npm install, fix a small bug, report back. Sometimes there is no task at all, just “have a look, see how it works, and open it in an editor so you can read it properly.” That last instruction is not the setup for the attack. For a whole class of these, it is the attack.",
            },
            {
              title: "The trap springs on its own",
              body: "Hidden inside the project, typically in an install script or an innocent-looking config file, is code that runs automatically. Usually npm install or npm run dev fires it, but often nothing needs installing at all: a repo can ship a VS Code task, an MCP server, a dev container, or an editor hook that runs the moment you open the folder. You never even have to open the malicious file.",
            },
            {
              title: "It steals what's on your machine",
              body: "The payload hunts for browser passwords and cookies, crypto wallets and extensions like MetaMask, SSH keys, and API keys in your environment, and quietly uploads them. Some variants install a backdoor for later.",
            },
          ].map((step, i) => (
            <li key={i} className="flex gap-4">
              <span className="flex h-7 w-7 shrink-0 items-center justify-center rounded-full bg-blue-600/10 text-sm font-semibold text-blue-600 dark:bg-blue-500/15 dark:text-blue-400">
                {i + 1}
              </span>
              <div>
                <h3 className="font-semibold text-slate-900 dark:text-slate-100">{step.title}</h3>
                <p className="mt-1 text-sm leading-relaxed">{step.body}</p>
              </div>
            </li>
          ))}
        </ol>
        <p className="mt-6 rounded-xl border border-blue-200 bg-blue-50 p-4 text-sm leading-relaxed text-blue-900 dark:border-blue-900 dark:bg-blue-950/40 dark:text-blue-200">
          <strong>The golden rule:</strong> never run code from a stranger, and do not even open it,
          on the machine that holds your passwords and wallets. Opening a folder in an editor already
          runs whatever the repo told the editor to start. A legitimate interviewer will not mind if
          you review the code on GitHub first, ask questions, or use a throwaway virtual machine.
        </p>
      </section>

      {/* What RepoCanary checks */}
      <section className="mt-12">
        <h2 className="text-xl font-semibold tracking-tight">What RepoCanary checks</h2>
        <ul className="mt-4 grid gap-2.5 text-sm text-slate-600 sm:grid-cols-2 dark:text-slate-300">
          {[
            "Scripts that auto-run on npm install (preinstall / postinstall)",
            "Obfuscated or minified code hiding in normal-looking files",
            "Code that reads your passwords, keys, or environment secrets and sends them out",
            "References to crypto wallets, browser data, and keychains",
            "Code that downloads and executes more code from the internet",
            "Auto-run traps across ecosystems: npm, PyPI, composer, gems, Yarn, Docker, direnv, and CI",
            "Code that fires when you merely open the folder: VS Code tasks and tool paths, MCP servers, AI agent hooks, dev containers, and Emacs or Neovim project config",
            "Lockfiles that quietly install something other than what package.json declares",
            "Fishy account signals: brand-new orgs, empty “companies”, typosquatted packages",
          ].map((item, i) => (
            <li
              key={i}
              className="flex items-start gap-2.5 rounded-xl border border-slate-200 bg-white p-3.5 last:sm:col-span-2 dark:border-slate-800 dark:bg-slate-900"
            >
              <Check className="mt-0.5 h-4 w-4 shrink-0 text-blue-600 dark:text-blue-400" />
              <span>{item}</span>
            </li>
          ))}
        </ul>
        <p className="mt-4 text-sm text-slate-500 dark:text-slate-400">
          Every technique is catalogued and measured against a threat corpus, with the exact rules
          that fire on each.{" "}
          <a href="/coverage" className="font-medium text-blue-600 underline dark:text-blue-400">
            See the full coverage catalog
          </a>
          .
        </p>
      </section>

      {/* For developers: the same engine, where developers work */}
      <section className="mt-12">
        <h2 className="text-lg font-semibold tracking-tight">In your terminal or CI</h2>
        <p className="mt-2 text-sm leading-relaxed text-slate-500 dark:text-slate-400">
          The same engine runs as a CLI with no install and as a GitHub Action, with JSON and
          SARIF output and exit codes a pipeline can gate on. Open source, zero runtime
          dependencies.
        </p>
        <pre className="mt-3 overflow-x-auto rounded-xl border border-slate-200 bg-slate-50 p-3.5 font-mono text-sm text-slate-800 dark:border-slate-800 dark:bg-slate-900 dark:text-slate-200">
          <code>npx repocanary owner/repo</code>
        </pre>
        <p className="mt-3 text-sm">
          <a
            href="https://github.com/chriszemmel/repocanary"
            className="font-medium text-blue-600 underline dark:text-blue-400"
            target="_blank"
            rel="noopener noreferrer"
          >
            Source, docs and the GitHub Action on GitHub
          </a>
        </p>
      </section>

      {/* Footer */}
      <footer className="mt-16 border-t border-slate-200 pt-6 pb-8 text-center text-xs leading-relaxed text-slate-500 dark:border-slate-800 dark:text-slate-400">
        <p>
          RepoCanary is an automated heuristic, not a guarantee. A green result does not prove a
          repo is safe. Never run untrusted code. This tool never executes the repo; it only reads
          its files.
        </p>
        <p className="mt-2">
          Report malicious repos to{" "}
          <a
            href="https://github.com/contact/report-abuse"
            className="underline"
            target="_blank"
            rel="noopener noreferrer"
          >
            GitHub Report Abuse
          </a>{" "}
          · US victims:{" "}
          <a
            href="https://www.ic3.gov"
            className="underline"
            target="_blank"
            rel="noopener noreferrer"
          >
            FBI IC3
          </a>
        </p>
        <p className="mt-2">
          Free, no account, no tracking, no paid tier.{" "}
          <a
            href="https://github.com/chriszemmel/repocanary"
            className="underline"
            target="_blank"
            rel="noopener noreferrer"
          >
            Open source
          </a>
          .{" "}
          <a href="https://nimimo.com/@chris" className="underline" target="_blank" rel="noopener noreferrer">
            Say thanks
          </a>{" "}
          if it saved you a bad afternoon.
        </p>
        <LegalLinks />
      </footer>
    </main>
  );
}
