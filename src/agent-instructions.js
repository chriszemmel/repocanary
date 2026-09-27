/**
 * Files a coding agent reads as instructions: CLAUDE.md, AGENTS.md, rules
 * files. Nothing in them executes by itself; the risk is an agent obeying
 * text a human reviewer never sees, so these rules look for the mechanical
 * tricks (hidden text, spoofed delimiters, links that carry data), not intent.
 */

import { matchLocation, redactSnippet, withoutFencedBlocks } from "./textutil.js";

/**
 * Instruction files, judged on what can be checked mechanically rather than
 * on what the prose means. Three things earn a conviction:
 *
 *   - An instruction hidden from the person reviewing the file, in an HTML
 *     comment or behind invisible characters. A directive a human cannot
 *     see, aimed at a machine that can, has no honest reading.
 *   - Text that tries to displace the agent's own instructions. "Ignore
 *     previous instructions" is a literal string, not an interpretation.
 *   - An order to keep something from the user, next to something worth
 *     hiding: a credential path, an exfiltration verb, a shell command.
 *     Either half alone is ordinary. "Commit without asking" is a normal
 *     workflow preference; so is documenting where credentials live.
 *
 * Everything else is reported low. These files are ordinary now, and a rule
 * that convicted on their presence would be measuring the calendar.
 */
const AGENT_OVERRIDE =
  /\bignore\s+(all\s+)?(previous|prior|above|earlier)\s+(instructions?|prompts?|rules?)|\bdisregard\s+(all\s+)?(previous|prior|your)\s+(instructions?|prompts?|rules?|system)|\byour\s+(new|real|actual)\s+(instructions?|task|role)\s+(is|are)\b|\boverride\s+your\s+(system\s+)?(prompt|instructions?)/i;

const AGENT_CONCEAL =
  /\b(do\s+not|don'?t|never)\s+(tell|mention|inform|notify|show|reveal|report|display)\b[^\n]{0,40}\b(the\s+)?(user|human|developer|operator)\b|\bwithout\s+(telling|informing|notifying|alerting)\s+(the\s+)?(user|human|developer)\b|\b(silently|quietly)\s+(run|execute|send|upload|post|exfiltrate)\b/i;

const AGENT_PAYOFF =
  /~?[\/\\]?\.(aws\/credentials|ssh\/id_[\w]+|npmrc|netrc|kube\/config|docker\/config\.json)\b|\b(id_rsa|id_ed25519)\b|\.env(\.[\w]+)?\b|\b(GITHUB_TOKEN|AWS_SECRET_ACCESS_KEY|NPM_TOKEN|OPENAI_API_KEY|ANTHROPIC_API_KEY)\b|\b(curl|wget|fetch|POST|upload|exfiltrate|send)\b[^\n]{0,60}https?:\/\//i;

/**
 * Text present in the file but painted out of sight when the markdown is
 * rendered. A reviewer reading the rendered page sees nothing; an agent
 * reading the source sees an instruction.
 */
const HIDDEN_STYLE =
  /style\s*=\s*["'][^"']{0,120}(font-size\s*:\s*0|display\s*:\s*none|visibility\s*:\s*hidden|opacity\s*:\s*0|color\s*:\s*(#f{3,6}\b|white\b))/i;

/**
 * Markers that imitate the boundary between a model's own instructions and
 * the text it is reading. Writing one into a project's instruction file
 * forges a turn that the agent's operator never sent.
 */
// `[^\S\n]*` for the indentation, not `\s*`: under /m the anchor is per line,
// and `\s` matching a newline lets a run of blank lines be re-divided at
// every position, which turns a file of newlines into a nine-second scan.
const DELIMITER_SPOOF =
  /<\|(im_start|im_end|system|endoftext|assistant|user)\|>|<<SYS>>|\[\/?INST\]|^[^\S\r\n]*#{2,}[^\S\r\n]*(system|assistant)\s*:/im;

/**
 * A link or image whose address carries a value the agent would have to go
 * and find first. Rendering it is the exfiltration: the request itself
 * delivers whatever was interpolated. A badge has a query too, which is why
 * this needs a placeholder or a secret's name in it rather than any query.
 */
const RENDER_EXFIL =
  /!?\[[^\]]{0,80}\]\(\s*https?:\/\/[^\s)]{0,200}\?[^\s)]{0,200}(\{\{|\$\{|\$\(|%s|\b(env|secret|secrets|token|apikey|api_key|credential|password|key)\b)/i;

/**
 * HTML comments, which render as nothing. Being invisible is not itself the
 * problem: a doctoc marker, a prettier-ignore, a licence header and a note to
 * the next maintainer are all invisible and all ordinary. What convicts is an
 * invisible comment that also carries one of the things that convict
 * elsewhere, so the comment is judged by its contents rather than by the fact
 * that a verb appears in it. Airflow's "INSTEAD RE-RUN doctoc TO UPDATE" was
 * red under the looser reading.
 */
const HTML_COMMENT = /<!--((?:(?!-->)[\s\S]){0,2000})-->/g;

const escapeForRegExp = (text) => text.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");

export function checkAgentInstructions(path, content) {
  const base = path.split("/").pop();
  const what = `This repository ships ${base}, which an AI coding agent reads as instructions with close to the authority of its own system prompt. Nothing in it runs by itself; the risk is that the agent working in this folder does what it says.`;

  // Code spans and fences render verbatim, so nothing in them is hidden and
  // a marker in one is quoted rather than forged: openobserve's style guide
  // bans `style="color: #fff; padding: 10px"` in a table of code spans, and
  // MisakaNet's AGENTS.md tells the agent not to treat `<|im_start|>` as a
  // turn. Blanked to spaces, so every location below is unchanged.
  const prose = withoutFencedBlocks(content).replace(/`[^`\n]{1,400}`/g, (m) => " ".repeat(m.length));
  const damning = [...prose.matchAll(HTML_COMMENT)].find(
    (m) => AGENT_OVERRIDE.test(m[1]) || AGENT_CONCEAL.test(m[1]) || AGENT_PAYOFF.test(m[1]),
  );
  const hidden = damning ? matchLocation(content, new RegExp(escapeForRegExp(damning[0].slice(0, 80)))) : null;
  if (hidden) {
    return [
      {
        id: "agent-instruction-file",
        severity: "high",
        file: path,
        line: hidden.line,
        snippet: redactSnippet(hidden.snippet),
        why: `${what} This one carries a directive inside an HTML comment, which renders as nothing at all, so a person reviewing the file sees a blank where the agent sees an order.`,
        next: `Do not open this repository with an AI coding agent. Read ${base} as raw text, comments included, in the browser first.`,
      },
    ];
  }

  const styled = HIDDEN_STYLE.test(prose) ? matchLocation(content, HIDDEN_STYLE) : null;
  if (styled) {
    return [
      {
        id: "agent-instruction-file",
        severity: "high",
        file: path,
        line: styled.line,
        snippet: redactSnippet(styled.snippet),
        why: `${what} Part of it is styled so that it does not appear when the file is rendered, which means the version you would read and the version the agent reads are different documents.`,
        next: `Do not open this repository with an AI coding agent. Read ${base} as raw text, not rendered, in the browser first.`,
      },
    ];
  }

  const spoof = DELIMITER_SPOOF.test(prose) ? matchLocation(prose, DELIMITER_SPOOF) : null;
  if (spoof) {
    return [
      {
        id: "agent-instruction-file",
        severity: "high",
        file: path,
        line: spoof.line,
        snippet: redactSnippet(spoof.snippet),
        why: `${what} It contains markers that imitate the boundary between an agent's own instructions and the text it is reading, which forges a turn nobody sent. A project describing how to use a model would put those in a code sample, not in the file the agent obeys.`,
        next: `Do not open this repository with an AI coding agent. Read ${base} in the browser first.`,
      },
    ];
  }

  const exfil = RENDER_EXFIL.test(content) ? matchLocation(content, RENDER_EXFIL) : null;
  if (exfil) {
    return [
      {
        id: "agent-instruction-file",
        severity: "high",
        file: path,
        line: exfil.line,
        snippet: redactSnippet(exfil.snippet),
        why: `${what} It carries a link or image whose address has a value filled in from somewhere else, named for an environment variable, a token or a secret. Nothing has to run for that to leak: fetching the image to display it is the request that carries the data out.`,
        next: `Do not open this repository with an AI coding agent, and do not render ${base}. Read it as raw text first.`,
      },
    ];
  }

  const override = AGENT_OVERRIDE.test(content) ? matchLocation(content, AGENT_OVERRIDE) : null;
  if (override) {
    return [
      {
        id: "agent-instruction-file",
        severity: "high",
        file: path,
        line: override.line,
        snippet: redactSnippet(override.snippet),
        why: `${what} This one tries to displace the agent's own instructions, which no project has a reason to do to a tool its contributors are using.`,
        next: `Do not open this repository with an AI coding agent. Read ${base} in the browser first.`,
      },
    ];
  }

  const conceal = AGENT_CONCEAL.test(content) ? matchLocation(content, AGENT_CONCEAL) : null;
  if (conceal && AGENT_PAYOFF.test(content)) {
    return [
      {
        id: "agent-instruction-file",
        severity: "high",
        file: path,
        line: conceal.line,
        snippet: redactSnippet(conceal.snippet),
        why: `${what} This one tells the agent to keep something from you, and the same file names credentials, an address to send them to, or a command to run. Either on its own would be ordinary; together they are the shape of an instruction written for your machine rather than for you.`,
        next: `Do not open this repository with an AI coding agent. Read ${base} in the browser first, and rotate anything it names if you already did.`,
      },
    ];
  }

  return [
    {
      id: "agent-instruction-file",
      severity: "low",
      file: path,
      line: 1,
      snippet: base,
      why: `${what} Shipping one is ordinary, and RepoCanary reads it for hidden text and for orders that displace your agent's instructions, but it cannot judge what the prose asks for.`,
      next: `Read ${base} yourself before pointing a coding agent at this repository.`,
    },
  ];
}
