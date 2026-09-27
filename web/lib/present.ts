/**
 * Turning a scan into words for a worried visitor.
 *
 * The shared engine decides the verdict and produces the findings. This file
 * only chooses how to say it on the web, where the reader is likelier to be
 * non-technical than a CLI user and has not opted into anything.
 */

import type { Finding } from "@engine/scan.js";
import type { Verdict } from "@engine/verdict.js";

export const DISCLAIMER =
  "RepoCanary is an automated heuristic, not a guarantee. A green result means nothing known matched; it does not prove a repo is safe. Never run untrusted code. This tool never executes the repo; it only reads its files.";

const WHAT_TO_DO_DANGEROUS = [
  "Do NOT run this repo. Don't npm install, don't open it in an editor that auto-runs tasks, don't 'just take a quick look' by running it.",
  "If you already ran it: disconnect from the internet, then from another device move any crypto funds, revoke API tokens, and change your passwords starting with email.",
  // The three report steps are conditional, and the condition is the same one
  // the body text above them now states: a red is a signature match, not a
  // conviction, and three of the tool's own reds (rustdesk, yarnpkg/berry,
  // pm2) are red for doing the job they advertise. An unconditional "report
  // this to GitHub and the FBI" under a verdict that can be wrong about a
  // real project aims the tool at the people it misreads. WHAT_TO_DO_CAUTION
  // has always phrased it this way; the red list had not.
  "Read the findings below. If they describe malice rather than what the project openly does, report the repository to GitHub: https://github.com/contact/report-abuse",
  "If someone sent you this repository as a task or an opportunity, report them on the platform where they contacted you (LinkedIn, Telegram, etc.).",
  "If it was a scam aimed at you: in the US, report it to the FBI at https://www.ic3.gov. Elsewhere, report to your national cybercrime unit.",
];

const WHAT_TO_DO_CAUTION = [
  "Don't run this repo until someone experienced has reviewed the flagged files below.",
  "Ask the 'recruiter' why a take-home task requires running their code; a legitimate interview task rarely does.",
  "If anything feels off about how you got this repo (urgency, unsolicited contact, a company you can't verify), treat it as a scam.",
  "If you decide it's malicious, report it to GitHub (https://github.com/contact/report-abuse) and, in the US, to https://www.ic3.gov.",
];

const WHAT_TO_DO_CLEAN = [
  "Nothing known matched, but 'not caught' is not the same as 'safe'. Read the code yourself before running anything.",
  "Run unfamiliar projects inside a container or virtual machine, never on the machine that holds your passwords and wallets.",
  "Be suspicious of any interview task that requires npm install from a stranger's repo; ask if you can review it without running it.",
  "If the recruiter pressures you to run it quickly, that urgency is itself a red flag.",
];

/**
 * The first line of the clean list says nothing known matched, which is the
 * one thing that is not true of a green the AI pass cleared: there, signals
 * fired and a model judged them harmless. Same list, honest first line.
 */
const WHAT_TO_DO_AI_CLEARED = [
  "Signals fired here and a model judged them harmless. That is one model's opinion, not a signature, so read the findings and its reasoning yourself before relying on it.",
  ...WHAT_TO_DO_CLEAN.slice(1),
];

export function whatToDo(verdict: Verdict, aiCleared = false): string[] {
  if (verdict === "red") return WHAT_TO_DO_DANGEROUS;
  if (verdict === "yellow") return WHAT_TO_DO_CAUTION;
  return aiCleared ? WHAT_TO_DO_AI_CLEARED : WHAT_TO_DO_CLEAN;
}

export function headline(verdict: Verdict, owner: string, repo: string, aiCleared = false): string {
  const name = `${owner}/${repo}`;
  if (verdict === "red") return `Danger: ${name} matches known malware-trap signatures`;
  if (verdict === "yellow") return `Caution: ${name} has suspicious signals, don't run it yet`;
  if (aiCleared) return `${name} raised signals, and the AI second opinion judged them harmless`;
  return `Nothing known matched in ${name}, but stay careful`;
}

/**
 * A green that still lists findings is the ordinary case, not a corner: a
 * verdict turns yellow at three distinct low signals, so one or two are green
 * with those findings shown underneath. Kubernetes, React and Django all land
 * there. Until 2026-09-06 that case fell through to the caution text, so the
 * page told a visitor scanning `facebook/react` that it "has characteristics
 * that scam repos also have" and that they "should not run this code", under
 * a green headline. Alarming a reader about React is how a scanner teaches
 * people to ignore it.
 */
/**
 * A reason's opening sentence, continued mid-sentence. Only the leading
 * capital goes: lower-casing the whole sentence turned "VS Code (runOn:
 * folderOpen)" into "vs code (runon: folderopen)" in the paragraph a
 * visitor reads first.
 */
function lowerLead(sentence: string): string {
  return /^[A-Z][a-z]/.test(sentence) ? sentence[0].toLowerCase() + sentence.slice(1) : sentence;
}

export function whatItDoes(verdict: Verdict, findings: Finding[], aiCleared = false): string {
  if (findings.length === 0) {
    return "The scan didn't find install-time scripts, obfuscated code, credential access, poisoned dependencies, or download-and-run behavior in the files it checked. That lowers the risk, but an automated scan can't prove a repo is safe.";
  }
  if (verdict === "green") {
    if (aiCleared) {
      return "Signals did fire here, and the AI second opinion read the flagged files and found an innocent explanation for each. That is one model's judgement rather than the static rules', so read the findings and its reasoning below before you rely on it.";
    }
    return "The notes below are minor observations, not accusations: too few and too weak to add up to a caution, and ordinary projects trip them all the time. Nothing matched the install-time scripts, obfuscated code, credential access or download-and-run behavior the scan looks for. Read them if you're curious, but they are not a reason to distrust this repository.";
  }
  if (verdict === "red") {
    // A red always carries a high-severity finding today (the AI pass
    // cannot produce one), but the fallback stays in case that changes.
    const worst = findings.filter((f) => f.severity === "high");
    // Deduplicate before taking three, not after. Two findings of the same
    // rule share the opening sentence of their reason, so dotenvx read
    // "downloads something and runs it; downloads something and runs it",
    // which looks like a bug in the sentence a reader trusts most.
    const reasons = [
      ...new Set((worst.length > 0 ? worst : findings).map((f) => lowerLead(f.why.split(".")[0]))),
    ]
      .slice(0, 3)
      .join("; ");
    // The CLI's `verdictMeaning` was reworded on 2026-09-09 because "a pattern
    // that is essentially only ever present in malware" is measurably untrue:
    // rustdesk, yarnpkg/berry and pm2 are red for doing their advertised job.
    // The site never rendered `verdictMeaning` -- it builds its own words here
    // -- so the old universal survived on the surface a stranger hits first.
    // Same correction, said for a non-technical reader: name what fired, then
    // say what the tool cannot know, then keep the instruction.
    return `The scan matched patterns from the fake-interview malware playbook: ${reasons}. It reads files and nothing else, so it cannot tell software whose advertised job is the flagged behavior (a remote-desktop tool, an installer, a package manager) from malware doing the same thing. Read the findings below, and do not run this repository until you can explain what fired: even npm install can execute hidden code before you read anything.`;
  }
  return "This repository has characteristics that scam repos also have. None of them alone proves malice, but together they mean you should not run this code until someone has reviewed the findings below.";
}
