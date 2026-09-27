/**
 * Behavioral rules over source and config bodies: download-and-execute,
 * credential and wallet access, exfiltration, persistence, and code hidden
 * where a reviewer does not look.
 *
 * Every rule reads text. The helpers here exist to read it the way the
 * language would, so a pattern inside a string, a comment, a docstring or a
 * regex literal is not mistaken for code that runs.
 */

import {
  HIGH_SIGNATURES,
  MED_SIGNATURES,
  WALLET_EXTENSION_IDS,
  WALLET_EXTENSION_ID_RE,
  WALLET_FS_PATTERNS,
  checkShellPersistence,
} from "./signatures.js";
import { KNOWN_LOCAL_TOOL, downloadIntoShell } from "./ecosystems.js";
import { checkObfuscation } from "./obfuscation.js";
import {
  countMatches,
  everyMatchInContext,
  lineOfIndex,
  looksLikeEncodedAsset,
  looksLikeEncodedWordList,
  looksLikeWasm,
  matchLocation,
  redactSnippet,
  safeJsonParse,
  withoutCommentLines,
  withoutFencedBlocks,
  withoutImportLines,
} from "./textutil.js";
import { isVendoredArtifact } from "./vendored.js";

/**
 * Whether an offset falls inside a string literal that spans lines: a Go raw
 * string, a Python triple-quoted string, or a JavaScript template literal.
 *
 * Such a literal is where a program keeps a document -- CLI help, a usage
 * banner, a markdown table of environment variables -- and a document that
 * names a path is describing it, not opening it. This is deliberately a
 * cheap count of delimiters before the offset rather than a parse: an odd
 * count means the offset is inside one. Escapes and nesting can fool it, so
 * it is only ever used to weaken a finding, never to raise one.
 */
function insideMultiLineString(code, at) {
  const before = code.slice(0, at);
  for (const delim of ['"""', "'''", "`"]) {
    let n = 0;
    let i = before.indexOf(delim);
    while (i !== -1) {
      n += 1;
      i = before.indexOf(delim, i + delim.length);
    }
    if (n % 2 === 1) {
      // A one-line template literal is an ordinary string; the point of this
      // is the block that carries a document.
      const close = code.indexOf(delim, at);
      const open = before.lastIndexOf(delim);
      if (close !== -1 && code.slice(open, close).includes("\n")) return true;
    }
  }
  return false;
}

const FS_READ =
  /\b(readFileSync|readFile|readdirSync|readdir|createReadStream|copyFileSync|copyFile|existsSync|statSync|open\s*\(|os\.path|os\.listdir|os\.walk|glob\.|shutil\.|Path\s*\(|Get-Content|Copy-Item|Get-ChildItem|std::fs|fs::|ioutil\.ReadFile|os\.ReadFile|os\.Open|File\.read|IO\.read|file_get_contents|sqlite3?|leveldb|path\.(join|resolve)|homedir)\b/i;

/**
 * A directory that means "the project's own build, CI or provisioning" and
 * nothing else. A file here runs on a build agent, a release runner or a
 * container the project provisions -- never on the machine of the person who
 * cloned the repository to look at it, which is the only machine this tool is
 * asked about.
 *
 * Thirteen of the thirty-two entries in expected-red.txt were this one idea
 * missing: ponyc writing a generated key to a BSD build VM, calico fetching a
 * script into a CI epilogue, airflow generating a host key for its own test
 * container. The concept existed as CI_ONLY_DIR but was consulted in exactly
 * one place -- the high gate of download-and-execute -- so ssh-backdoor and
 * startup-persistence never asked, and its directory list matched exactly one
 * of the thirty-two paths.
 *
 * Five of those thirteen leave. The other eight sit in directory names that
 * guarantee nothing, and are listed below as what they are. (Two more
 * entries had looked like CI and were not, on re-reading: flink's script is
 * served from its docs site for users to run, and the aws-cdk sample is
 * infrastructure a user deploys. Both keep their reds on the merits.)
 *
 * This is the same trade as TEST_PATH directly below, made deliberately and
 * with the same two defenses: one step down and no more, so a payload here is
 * still reported, and `!executable`, so a file something starts is judged as
 * one wherever it sits. A name earns a place here only if it cannot mean
 * anything else. scripts/, tools/, misc/ and playground/ are
 * NOT here and must not be: a dropper a README tells you to run lives in
 * scripts/, and truffle, cal.com, cypress, grpc, materialize and beam
 * therefore keep their reds, because a scripts/ci.sh that pipes a stranger's
 * installer into bash is indistinguishable from a dropper by its path.
 *
 * Not .devcontainer: that one runs the moment the folder is opened, which is
 * the attack this tool exists for. Not hack/ either, though it is a strong
 * convention in the Kubernetes ecosystem: an existing regression test uses
 * hack/install_cleanup.sh to assert that installing an @reboot cron entry
 * stays a conviction, and that decision is older and better tested than this
 * one. minikube keeps its red.
 *
 * eng/ is .NET's Arcade convention for the engineering and build tree, and is
 * listed whole rather than as eng/common: dotnet/maui's red comes from
 * eng/devices/run-windows-devicetests.cmd, which downloads the Windows App
 * SDK runtime through aka.ms and installs it, and eng/devices is the same
 * claim about the same tree as eng/common.
 */
export const CI_PATH =
  /^(\.docker|docker|\.buildkite|\.github|\.circleci|\.gitlab|ci|\.ci|\.ci-scripts|\.argoci|\.semaphore|\.cirrus|\.travis|\.drone|\.jenkins|\.teamcity|\.azure-pipelines|build_tools)\/|^eng\//i;

// Files a shell, build tool or CI runner executes line by line, where a
// download piped into a shell IS the command. Everywhere else it is a string
// until something runs it, and the download rule asks for that something.
// An extensionless path counts: bare `configure`, `entrypoint`, `install`
// are shell scripts, and guessing the other way would exempt them.
const SCRIPT_FILE =
  /\.(sh|bash|zsh|ksh|fish|bat|cmd|ps1|psm1|mk|bazel|bzl)$|(^|\/)(Makefile|GNUmakefile|Dockerfile[\w.-]*|Containerfile|Justfile|Rakefile|Vagrantfile|Brewfile|Procfile)$|(^|\/)\.?(github|gitlab|circleci|buildkite|azure-pipelines|travis|drone|woodpecker)[\w.-]*\/|\.(yml|yaml)$/i;

/**
 * URLs that belong to the scanned repository's own owner. A script fetched
 * from a sibling repository of the same organisation (PostHog's Dockerfile
 * installs posthog-cli, sendgrid's Makefile fetches its own OpenAPI tooling)
 * is the same author's code, so it counts as known rather than as a dropper.
 */
export function ownUrls(repo) {
  if (!repo) return [];
  return [`https://raw.githubusercontent.com/${repo.owner}/`, `https://github.com/${repo.owner}/`];
}

/**
 * An eval or `new Function` call whose arguments are all string literals
 * (template literals only without interpolation). What it runs is written in
 * the file, so it cannot be running something a download returned.
 */
const CODE_LITERAL = String.raw`(?:'(?:[^'\
]|\.)*'|"(?:[^"\
]|\.)*"|` + "`(?:[^`\\$]|\\.)*`)";
const LITERAL_CODE_CALL = new RegExp(
  String.raw`(?:new\s+Function|(?<![.\w])eval)\s*\(\s*` + CODE_LITERAL + String.raw`(?:\s*,\s*` + CODE_LITERAL + String.raw`)*\s*,?\s*\)`,
  "g",
);

/**
 * Is the string bound to a name on this line kept away from every process
 * spawn in the file? Follows the name through plain reassignments (`cmd = X`,
 * `const full = X + args`) so an alias still counts, and reads each line that
 * uses one of the names for a spawn primitive. True also when the name is
 * never read, since a string nobody reads runs nothing. False whenever the
 * binding cannot be identified, so an unrecognised shape keeps the old,
 * stricter reading.
 *
 * browser-use keeps `TERMINAL_INSTALL_COMMAND = 'curl ... | sh'` for two
 * error messages; superagent-desktop hands its constant to spawn. The first
 * is an install hint and the second is a command, and only data flow tells
 * them apart: both files spawn processes.
 */
function bindingNeverSpawned(code, definitionLine, lineNumber) {
  const binding = /^\s*(?:export\s+)?(?:(?:const|let|var|final|static|readonly|private|public)\s+)*([A-Za-z_]\w*)\s*(?::\s*[\w<>[\], |.]+)?=\s*[fbrFBR]?["'`]/;
  const m = definitionLine.match(binding);
  if (!m) return false;
  const lines = code.split("\n");
  const names = new Set([m[1]]);
  const wordOf = (name) => new RegExp(`(?<![\\w$.])${name}(?![\\w$])`, "g");
  const assigns = /^\s*(?:(?:const|let|var|final|static|readonly)\s+)*([A-Za-z_]\w*)\s*(?::[^=]+)?=(?!=)/;
  // Aliases, to a fixed point; five rounds is more indirection than any
  // honest file uses, and a chain longer than that keeps the stricter reading
  // only in the sense that later links are not followed.
  for (let round = 0; round < 5; round++) {
    const before = names.size;
    for (let i = 0; i < lines.length; i++) {
      if (i + 1 === lineNumber) continue;
      const a = lines[i].match(assigns);
      if (a && !names.has(a[1]) && [...names].some((n) => wordOf(n).test(lines[i].slice(a[0].length)))) names.add(a[1]);
    }
    if (names.size === before) break;
  }
  const spawns = /exec|spawn|system|subprocess|popen|Command|Process|shell|run\s*\(|eval/i;
  for (let i = 0; i < lines.length; i++) {
    if (i + 1 === lineNumber) continue;
    let text = lines[i];
    let used = false;
    for (const n of names) {
      const re = wordOf(n);
      if (re.test(text)) {
        used = true;
        text = text.replace(wordOf(n), "");
      }
    }
    // Read without the names themselves, which may well be spelled COMMAND.
    if (used && spawns.test(text)) return false;
  }
  return true;
}

/**
 * The first line where something follows a run of at least 150 spaces or
 * tabs that itself follows something: text, then a gap wider than any
 * screen, then more text. Leading indentation is not this, however deep.
 * HZCX404/memecoin-trading-bots opens utils.cache.js with a one-line comment,
 * 382 spaces, and an obfuscated loader that `npm start` runs.
 *
 * Counted by hand rather than matched: a regex over a line of a megabyte of
 * spaces retries from every offset, and this is linear.
 */
function offscreenCode(content) {
  const GAP = 150;
  let line = 1;
  let seenText = false;
  let run = 0;
  // Spaces inside a string literal are the string's content: amux keeps a
  // captured terminal screen, padding and all, in a Rust constant. The quote
  // state is per line, which is all a hiding place on one line needs.
  let quote = 0;
  for (let i = 0; i < content.length; i++) {
    const c = content.charCodeAt(i);
    if (c === 10) {
      line += 1;
      seenText = false;
      run = 0;
      quote = 0;
    } else if (quote !== 0) {
      if (c === 92) i += 1;
      else if (c === quote) quote = 0;
    } else if (c === 32 || c === 9) {
      run += 1;
    } else if (c !== 13) {
      if (c === 34 || c === 39 || c === 96) {
        quote = c;
        seenText = true;
        run = 0;
        continue;
      }
      if (seenText && run >= GAP) {
        const end = content.indexOf("\n", i);
        const tail = content.slice(i, end === -1 ? content.length : end);
        // A trailing comment pushed right is alignment, not a hiding place.
        if (!/^(\/\/|#|\/\*|\*|<!--|--)/.test(tail) && tail.trim().length >= 10) {
          const code = /[;{}()=]|\b(require|import|eval|function|exec|atob|Buffer|_0x[0-9a-f]{3})/i.test(tail);
          return { line, gap: run, tail: tail.slice(0, 160), code };
        }
      }
      seenText = true;
      run = 0;
    }
  }
  return null;
}

/**
 * The source with the body of every regular expression blanked to spaces,
 * offsets intact: JavaScript regex literals in the positions an expression
 * can start, and the pattern string handed to RegExp, re.compile and their
 * relatives. A slash after an identifier or a closing bracket is division
 * and is left alone.
 */
const REGEX_LITERAL = /((?:^|[=(,:[!&|?{};]|\breturn)\s*)\/(?![*/])((?:\\.|\[(?:\\.|[^\]\\\n])*\]|[^/\\\n[])+)\/[a-z]*/g;
const REGEX_CALL = /((?:new\s+RegExp|\bre\.(?:compile|search|match|fullmatch|findall|sub)|\bregexp\.(?:MustCompile|Compile)|Regex::new|Pattern\.compile)\s*\(\s*[rRb]?)(["'`])((?:\\.|(?!\2)[^\\\n])*)\2/g;
function withoutRegexBodies(code) {
  return code
    .replace(REGEX_LITERAL, (m, lead, body) => `${lead} ${" ".repeat(body.length)} ${" ".repeat(m.length - lead.length - body.length - 2)}`)
    .replace(REGEX_CALL, (m, lead, q, body) => `${lead}${q}${" ".repeat(body.length)}${q}`);
}

/**
 * The text with every call of eval or of the Function constructor that sits
 * inside a string literal blanked, offsets intact. A string that mentions eval is a message
 * or a pattern name: oh-my-customcode's checker labels one of its rules
 * 'eval() usage' a few lines below one labelled 'curl pipe to shell', and the
 * two read as a download handed to eval. The call a dropper makes is code.
 * The scan is one pass over the text, tracking ' " and ` with escapes; a
 * quote opened and never closed on its line ends there, except a backtick,
 * which may span lines.
 */
function evalCallsOutsideStrings(text) {
  if (!/\beval\s*\(|new\s+Function\s*\(/.test(text)) return text;
  const inString = new Uint8Array(text.length);
  let quote = 0;
  for (let i = 0; i < text.length; i++) {
    const c = text.charCodeAt(i);
    if (quote !== 0) {
      inString[i] = 1;
      if (c === 92) {
        if (i + 1 < text.length) inString[i + 1] = 1;
        i += 1;
      } else if (c === quote || (c === 10 && quote !== 96)) quote = 0;
    } else if (c === 34 || c === 39 || c === 96) quote = c;
  }
  return text.replace(/\beval\s*\(|new\s+Function\s*\(/g, (m, at) => (inString[at] ? " ".repeat(m.length) : m));
}

/**
 * Does every URL on this line point at the machine the line runs on? A
 * request to localhost is a health check or a local API, and nothing it
 * returns comes from outside. m365-copilot-companion-mcp's quickstart polls
 * its own server at 127.0.0.1 through Invoke-WebRequest. A line with no URL
 * at all is not "only loopback": it may take its address from a variable.
 */
/**
 * Does every URL on this line belong to the repository being scanned? A
 * self-updater that fetches its own script from its own raw URL runs code
 * this scan can read: Cloverbandit1/fett-desk-win's batch files do that.
 */
function onlyOwnUrls(line, selfUrls) {
  const urls = line.match(/https?:\/\/[^\s"'`)]+/gi);
  if (!urls || !selfUrls || selfUrls.length === 0) return false;
  return urls.every((u) => selfUrls.some((own) => u.toLowerCase().startsWith(own.toLowerCase())));
}

function onlyLoopback(line) {
  const urls = line.match(/https?:\/\/[^\s"'`)]+/gi);
  if (!urls) return false;
  return urls.every((u) => /^https?:\/\/(localhost|127\.\d+\.\d+\.\d+|\[::1\]|0\.0\.0\.0)(:\d+)?(\/|$)/i.test(u));
}

/**
 * The source with every triple-quoted string that stands as a statement of
 * its own blanked, newlines kept so line numbers hold. One pass: each
 * opening is searched forward for its close, and the scan resumes after it.
 */
function withoutPythonDocstrings(code) {
  let out = "";
  let at = 0;
  const opener = /^[ \t]*[rRuUbB]{0,2}("""|\'\'\')/gm;
  for (let m = opener.exec(code); m !== null; m = opener.exec(code)) {
    if (m.index < at) continue;
    const start = m.index + m[0].length;
    const close = code.indexOf(m[1], start);
    const end = close === -1 ? code.length : close + 3;
    out += code.slice(at, m.index) + code.slice(m.index, end).replace(/[^\n]/g, " ");
    at = end;
    opener.lastIndex = end;
  }
  return out + code.slice(at);
}

/**
 * Is this line inside the arguments of a call that prints, logs or throws?
 * Scans forward from the nearest such opener within 1,500 characters,
 * tracking brackets and the three quote characters, and answers whether the
 * line is reached before the call closes. tjcoder-labs/cli prints its
 * fallback installer as one element of an array joined into console.error.
 */
function insidePrintCall(code, lineNumber) {
  let lineStart = 0;
  for (let n = 1; n < lineNumber && lineStart !== -1; n++) lineStart = code.indexOf("\n", lineStart) + 1;
  if (lineStart <= 0 && lineNumber > 1) return false;
  const from = Math.max(0, lineStart - 1500);
  const window = code.slice(from, lineStart);
  const openers = [...window.matchAll(/(?:console\.(?:log|error|warn|info|debug)|process\.std(?:err|out)\.write|\bprint(?:ln|f)?|\b(?:logger|log)\.\w+|\bwarn(?:ing)?|throw\s+new\s+\w*Error|\braise\s+\w+)\s*\(/g)];
  const last = openers.at(-1);
  if (!last) return false;
  let depth = 0;
  let quote = 0;
  for (let i = from + last.index + last[0].length - 1; i < lineStart; i++) {
    const c = code.charCodeAt(i);
    if (quote !== 0) {
      if (c === 92) i += 1;
      else if (c === quote) quote = 0;
      else if (c === 10 && quote !== 96) quote = 0;
      continue;
    }
    if (c === 34 || c === 39 || c === 96) quote = c;
    else if (c === 40 || c === 91 || c === 123) depth += 1;
    else if (c === 41 || c === 93 || c === 125) {
      depth -= 1;
      if (depth === 0) return false;
    }
  }
  return depth > 0;
}

/** An HTML page with everything but its scripts and event handlers blanked, offsets and lines intact. */
function htmlScriptsOnly(html) {
  const keep = new Uint8Array(html.length);
  for (const m of html.matchAll(/<script\b[^>]*>([\s\S]*?)<\/script\s*>/gi)) {
    const start = m.index + m[0].indexOf(">") + 1;
    keep.fill(1, start, start + m[1].length);
  }
  for (const m of html.matchAll(/\son\w+\s*=\s*("[^"]*"|'[^']*')/gi)) keep.fill(1, m.index, m.index + m[0].length);
  let out = "";
  for (let i = 0; i < html.length; i++) {
    const c = html[i];
    out += keep[i] || c === "\n" ? c : " ";
  }
  return out;
}

export function checkCodeContent(path, content, size, langOverride, repo = null, executable = false) {
  const findings = [];
  const selfUrls = ownUrls(repo);
  const isPy = langOverride ? langOverride === "python" : /\.py$/i.test(path);
  // The same bytes with comment-only lines blanked out, offsets intact. The
  // rules that convict a file for *doing* something read this instead of
  // `content`, because a sentence describing an action is not the action.
  // Used deliberately rather than everywhere: rules about what a file
  // *contains* (an obfuscator toolmark, a hardcoded extension ID) still want
  // the whole file, since a payload parked in a comment is still shipped.
  // In an HTML page, only scripts and event handlers run; the rest is
  // text a person reads. Riptide's landing page shows `sudo systemctl
  // enable --now riptide` in an install snippet, and a student's page quotes
  // Wikipedia with its zero-width spaces. Blanked to spaces, lines kept.
  // Only a document that is markup, and one nothing starts: node runs a
  // file called index.html as JavaScript if a script tells it to.
  // Kept for the one rule about how the file looks to a reader: the blanking
  // below writes runs of spaces of its own, and whitespace-hidden-code read
  // them as a hiding place in vllm's and openapi-generator's HTML.
  const asWritten = content;
  if (/\.html?$/i.test(path) && !executable && /<(!doctype|html|head|body|div|p|span|pre|section|main|script)\b/i.test(content)) {
    content = htmlScriptsOnly(content);
  }
  const code = withoutCommentLines(content, path);
  const vendored = isVendoredArtifact(path, content);

  // technique: obfuscator variable-name toolmarks
  // The toolmark is an identifier in use, not a hex number inside a word
  // (TypeScript's "between_0x0_and_0x10FFFF", jQuery's "_0x80040111_").
  const toolmarks = content.match(/_0x[a-f0-9]{4,6}\b/gi) ?? [];
  if (toolmarks.length >= 3 || /_0x[a-f0-9]{4,6}\s*[[(=]/i.test(content)) {
    const loc = matchLocation(content, /_0x[a-f0-9]{4,6}\b/i);
    findings.push({
      id: "hex-obfuscation",
      severity: "high",
      file: path,
      line: loc?.line ?? null,
      snippet: loc?.snippet ?? "",
      why: 'This file uses "_0x..." style variable names, the signature of a JavaScript obfuscator. Honest project code has no reason to hide what it does.',
      next: "Do not run this repository until someone explains why its source is machine-obfuscated.",
    });
  }

  // technique: code parked off-screen behind a run of spaces
  const pushed = offscreenCode(asWritten);
  if (pushed) {
    findings.push({
      id: "whitespace-hidden-code",
      severity: pushed.code ? "high" : "medium",
      file: path,
      line: pushed.line,
      snippet: redactSnippet(pushed.tail),
      why: `Line ${pushed.line} of this file continues after ${pushed.gap} blank characters, far past the right edge of any editor or of GitHub's file view, and what sits out there ${pushed.code ? "is code" : "is not blank"}. Pushing a payload off-screen this way is how it survives a reviewer reading the file top to bottom.`,
      next: pushed.code
        ? "Do not run this repository. Open the file with line wrapping on, or search it for the text above, to see what is hidden there."
        : "Turn on line wrapping and read what is at the end of that line before running anything.",
    });
  }

  // technique: code built and run from strings (eval, new Function)
  if (!isPy && (/\beval\s*\(/.test(content) || /new\s+Function\s*\(/.test(content))) {
    const loc = matchLocation(content, /\beval\s*\(|new\s+Function\s*\(/);
    findings.push({
      id: "dynamic-code-execution",
      // Low: bare eval and new Function appear throughout honest code
      // (bundlers, parsers, template engines, and their test suites), so on
      // their own they are informational. Running decoded or fetched text is
      // the malicious pattern, and eval-decoded-blob and remote-code-execution
      // cover that at high.
      severity: "low",
      file: path,
      line: loc?.line ?? null,
      snippet: loc?.snippet ?? "",
      why: "This file builds and runs code from strings (eval or new Function). Malware uses this to hide its real behavior from anyone reading the source.",
      next: "Find what string is being executed. If you cannot tell, do not run the repository.",
    });
  }

  // technique: base64-packed payload, high severity when the file also decodes it
  const bigBase64 = /["'][A-Za-z0-9+/=]{300,}["']/;
  if (bigBase64.test(content)) {
    // The blob is usually bound to a name first, so the decode call takes an
    // identifier or a literal.
    const decodes = /atob\s*\(|from\s*\(\s*[^,()]{1,80},\s*["']base64["']|b64decode/i.test(content);
    // Other decoders, a hex Buffer or a Go or .NET base64 call, also read
    // license public keys and contract bytecode, so they keep the blob a
    // caution rather than the conviction the two script-world idioms earn.
    const otherDecoder =
      /from\s*\(\s*[^,;]{1,80},\s*["']hex["']|unhexlify|fromhex\s*\(|DecodeString\s*\(|FromBase64String|base64\s+(-d|--decode)\b/i.test(content);
    const loc = matchLocation(content, bigBase64);
    // The blob's own first bytes say whether it is a payload or a sound
    // file. A demo that inlines an Ogg because its playground cannot serve
    // one decodes it with atob and hands it to the audio API, which is the
    // exact shape this rule looks for; taiga-family/ng-web-apis came out red
    // for doing it. An identified asset drops one severity step rather than
    // being exempted, because "it starts with a PNG header" is good evidence
    // and not proof.
    const blob = content.match(bigBase64)?.[0] ?? "";
    const asset = looksLikeEncodedAsset(blob);
    // A compiled WebAssembly module handed to the WebAssembly API is not a
    // smuggled script, and the API is the load-bearing half of that sentence.
    // WebAssembly stays out of the asset list on purpose -- it is executable,
    // and a blob that decodes to something runnable keeps its full weight --
    // so what earns the step down here is where the bytes go. ClickHouse
    // inlines its own SQL lexer, built to a 6,678-byte .wasm with the build
    // command in the comment above it, so the Play UI can highlight a query
    // offline; it decodes with atob and calls WebAssembly.instantiate, and
    // read as smuggling that made a database everyone has heard of red. A
    // module reached that way gets only the imports it is handed and cannot
    // reach eval, a socket or a process by itself. The same bytes passed to
    // eval, a shell, or nothing identifiable are still high.
    const wasmModule =
      looksLikeWasm(blob) && /WebAssembly\s*\.\s*(instantiate|compile)(Streaming)?\s*\(/.test(code);
    const wordList = !asset && !wasmModule && looksLikeEncodedWordList(blob);
    const identified = asset || wasmModule || wordList;
    // Encoded data nothing in the file decodes is data: a font exported as a
    // base64 module, a JWE test vector, an SVG data URI. The payload shape is
    // the blob together with its unscrambling, and that keeps its weight.
    const severity = decodes ? (identified ? "medium" : "high") : otherDecoder && !identified ? "medium" : "low";
    findings.push({
      id: "base64-blob",
      severity,
      file: path,
      line: loc?.line ?? null,
      snippet: loc?.snippet ?? "",
      why: wordList
        ? `This file contains a large scrambled (base64) blob that decodes to a plain list of short text entries, one per line, with no code in it, which is what an inlined vocabulary or lookup table looks like rather than a hidden script. It is still decoded${decodes ? " by the code beside it" : ""}, so it is worth a look.`
        : wasmModule
        ? `This file contains a large scrambled (base64) blob whose first bytes are those of a compiled WebAssembly module, and the code beside it hands those bytes to the WebAssembly API rather than to eval or a shell. Projects inline a .wasm build this way when a page has to work without fetching a separate file.`
        : asset
        ? `This file contains a large scrambled (base64) blob whose first bytes are those of an ordinary media or font file, so it is most likely an embedded asset${decodes ? " that the code beside it decodes and plays or displays" : ""} rather than hidden code. Projects inline images, sounds and fonts this way when a demo or playground cannot serve them as files.`
        : decodes
          ? "This file contains a large scrambled (base64) blob and the code that unscrambles and uses it, a classic way to smuggle a hidden payload past a quick code review."
          : "This file contains a large scrambled (base64) blob. That can be legitimate (embedded images or fonts), but it is also how payloads get hidden.",
      next: wordList
        ? "Decode the blob in a safe editor and check it is the list it appears to be all the way through."
        : identified
        ? "Decode the first bytes yourself if you want to confirm the blob is the format it announces."
        : decodes
          ? "Do not run this repository; decode the blob offline if you want to see what it hides."
          : "Check what the encoded data is used for before installing.",
    });
  }

  // technique: credential exfiltration, ships the environment to a server.
  //
  // Only a whole-object use of the environment counts (bare, spread, or
  // stringified process.env / os.environ). Reading one named variable to
  // configure a service connection is ordinary work, even when the code then
  // makes a request with it, so a named-property read never fires here. That
  // is the line between a stealer and an app connecting to its own Redis.
  // Whole-env dumps also fire high in env-dump-exfiltration.
  // A member access may sit on the next line, as a formatter leaves it:
  // `process.env\n  .DISCORD_WEBHOOK_URL` reads one named value.
  const ENV_OBJECT = /process\.env(?![\w.$[])(?!\s*[.[])|os\.environ(?![\w.[(])(?!\s*[.[])|os\.environ\.copy\s*\(/;
  // `const { AP_CLOUD_API_KEY } = process.env` is a named read wearing a
  // whole-object shape: the lookahead above only rules out `process.env.X`
  // and `process.env[X]`, so a destructuring bind slipped through as a dump
  // and activepieces was called a credential stealer for authenticating to
  // its own API with its own key. Destructuring names exactly which
  // variables it takes, which is the line this rule already says it draws.
  //
  // A rest element takes the whole object and must keep firing, so the
  // braces may not contain a dot -- that excludes `{ ...rest }` while still
  // allowing renames, defaults and `{ A: b = "x" }`, none of which have one.
  const NAMED_ENV_DESTRUCTURE = /\{[^{}.]*\}\s*=\s*process\.env(?![\w.$[])/g;
  // `if "GITHUB_TOKEN" in os.environ:` asks whether one named variable is
  // set. It reads nothing and takes nothing: it is the guard people write
  // before the named read on the next line, which this rule already exempts.
  // Selenium's Chrome DevTools updater does exactly that and then makes a
  // GET to raw.githubusercontent, and the two together were read as a
  // credential stealer -- one of the corpus's 1,170, found the day after
  // the file changed upstream.
  //
  // The name has to be a literal, so `for k in os.environ` and
  // `if user_supplied in os.environ` still count as reading the object.
  const ENV_MEMBERSHIP = /["'][\w.]+["']\s+(?:not\s+)?in\s+(?:os\.environ|process\.env)(?![\w.$[])/g;
  // Handing the environment to a child process is inheritance, not a read:
  // `env: { ...process.env, PORT: "8099" }` and `env={**os.environ}` are how
  // every test harness starts a server. denn-gubsky/loomcycle's smoke test
  // does exactly that and then posts to the server it started on 127.0.0.1.
  const ENV_INHERIT = /\benv\s*[:=]\s*(?:\{\s*\.\.\.process\.env|\{\s*\*\*os\.environ|dict\(\s*os\.environ|os\.environ\.copy\(\))/g;
  // Printing the environment to the console is a debugging habit, not a
  // send: richdacoder's form handler logs process.env beside the POST it
  // makes with the form data.
  const ENV_LOGGED = /\bconsole\.(?:log|debug|info|warn|error)\([^()\n]{0,120}(?:process\.env|os\.environ)[^()\n]{0,120}\)/g;
  const envUses = code
    .replace(ENV_LOGGED, (m) => " ".repeat(m.length))
    .replace(ENV_INHERIT, (m) => " ".repeat(m.length))
    .replace(NAMED_ENV_DESTRUCTURE, (m) => " ".repeat(m.length))
    .replace(ENV_MEMBERSHIP, (m) => " ".repeat(m.length));
  const readsEnvObject = ENV_OBJECT.test(envUses);
  const sendsOut =
    /axios\.post|\.post\s*\(\s*["'`]https?:/i.test(envUses) ||
    // Bounded, like every other run that sits ahead of a literal here: with
    // `[^)]*` a file of "fetch(" tokens is walked to its end from each one.
    /fetch\s*\([^)]{0,400}method\s*:\s*["'`]POST/is.test(envUses) ||
    /https?\.request\s*\(/.test(envUses) ||
    /requests\.post\s*\(/.test(envUses);
  // Both halves must appear close together. A whole-object env read at the top
  // and an unrelated post much later is not exfiltration.
  const envNearSend =
    /(?:process\.env(?![\w.$[])(?!\s*[.[])|os\.environ(?![\w.[(])(?!\s*[.[]))[\s\S]{0,300}?(axios\.post|\.post\s*\(|fetch\s*\(|https?\.request|requests\.post)/i.test(
      envUses,
    ) ||
    /(axios\.post|\.post\s*\(|fetch\s*\(|https?\.request|requests\.post)[\s\S]{0,300}?(?:process\.env(?![\w.$[])(?!\s*[.[])|os\.environ(?![\w.[(])(?!\s*[.[]))/i.test(
      envUses,
    );
  if (readsEnvObject && sendsOut && envNearSend) {
    const loc = matchLocation(envUses, ENV_OBJECT);
    findings.push({
      id: "env-exfiltration",
      severity: "high",
      file: path,
      line: loc?.line ?? null,
      snippet: loc?.snippet ?? "",
      why: "This file reads environment variables (where API keys and secrets live) AND sends data to a remote server. Together, that is the pattern of credential theft.",
      next: "Do not run this repository. If you already did, rotate every key in your environment; see https://github.com/chriszemmel/repocanary/blob/main/WHAT-TO-DO-NOW.md.",
    });
  }

  const patternFree = SCRIPT_FILE.test(path) ? code : withoutRegexBodies(code);
  // technique: reading wallet, browser, and keychain DATA on disk (theft),
  // as distinct from an app connecting to a wallet in the browser (normal UX).
  for (const { re, label } of WALLET_FS_PATTERNS) {
    // `code`, not `content`: a path named only in a comment is prose. The
    // doc line over VictoriaMetrics' AWS credential loader ("reads
    // credentials from ~/.aws/credentials for the given profile") was the
    // only literal occurrence of that path in the file -- the code builds it
    // with filepath.Join -- and it read as high, which is to say the tool
    // called an AWS client credential-stealing malware for describing
    // itself accurately. Apache Beam earned three of these for a comment
    // saying where KUBECONFIG defaults to.
    // A regex that lists secret paths is a redaction filter, not a read:
    // rhein1/agoragentic-integrations refuses to export any file matching
    // /(?:^|\/)(?:\.env|\.aws|\.ssh|...)/. Only in source files, where a
    // slash can open a pattern.
    if (re.test(patternFree)) {
      // Theft reads the file. Every occurrence is weighed, not just the
      // first: helm's CLI help names ~/.gnupg/secring.gpg in an example
      // command at the top of the file, and a rule that stopped there would
      // have judged the whole file on its documentation. The strongest
      // occurrence decides.
      let at = -1;
      const all = new RegExp(re.source, `${re.flags.replace(/[gy]/g, "")}g`);
      // A credential path joined onto a directory the code made up is not
      // the user's: silent-rs's sandbox test writes a fake id_ed25519 under
      // fake_home to check that it cannot be read back.
      const underFakeRoot = (i) => /\b(fake|tmp|temp|mock|test|fixture|sandbox|dummy|scratch)\w*\s*\.\s*join\s*\(\s*["'`][^"'`]*$/i.test(patternFree.slice(Math.max(0, i - 80), i));
      if ([...patternFree.matchAll(all)].every((m) => underFakeRoot(m.index))) continue;
      for (const m of patternFree.matchAll(all)) {
        if (at === -1) at = m.index;
        if (FS_READ.test(code.slice(Math.max(0, m.index - 400), m.index + 400))) {
          at = m.index;
          break;
        }
      }
      let reads = FS_READ.test(code.slice(Math.max(0, at - 400), at + 400));
      // Chrome's Local State lists the profiles and also holds the key that
      // decrypts saved passwords and cookies. Browser automation reads it for
      // the first; a stealer reads it for the second, and has to name the key
      // to do so. browser-use, floter and pi-kaush all list profiles.
      if (reads && label.startsWith("Chrome key store") && !/os_crypt|encrypted_key|CryptUnprotectData|DPAPI|app_bound_encrypted_key/i.test(code)) reads = false;
      // A private SSH key handed to an SSH client is the key doing its job:
      // a VPN bot logs in to its own server with paramiko and the key file
      // its config names. A stealer reads the key to send it somewhere, so
      // the client has to be there and no upload beside it.
      const sshClient =
        label === "private SSH key" &&
        /paramiko|from_private_key_file|key_filename|asyncssh|client_keys|\bprivateKey\s*:|NodeSSH|ssh2|ssh\s+-i\b|\bpkey\s*=/i.test(code) &&
        !/requests\.post|axios\.post|method\s*:\s*["'`]POST|https?\.request|urlopen|webhook|sendDocument|FormData/i.test(code);
      // Nothing filesystem-shaped anywhere near any occurrence, and the
      // occurrence sits inside a multi-line string: this is a document that
      // names a path, which is the same thing the comment carve-out above
      // says about a comment that names one. helm's package command prints
      // "$ helm package --sign ./mychart --keyring ~/.gnupg/secring.gpg" in
      // its help, and its root command prints a markdown table whose
      // KUBECONFIG row gives the default as "~/.kube/config". FS_READ is
      // broad enough -- os.path, path.join, Path(, fs::, homedir -- that
      // failing it within 800 characters of every mention means the file
      // does not go near the filesystem there at all.
      // A path named with nothing reading it nearby is information, unless
      // the file names several kinds of target: that is a stealer's list.
      // botocore's default credentials path, fastlane's default keychain
      // and an onboarding hint are each one name.
      const targets = WALLET_FS_PATTERNS.filter((p) => p.re.test(patternFree)).length;
      const mention = !reads && at >= 0 && (insideMultiLineString(code, at) || targets < 3);
      const loc = matchLocation(code.slice(at), re) ?? matchLocation(code, re);
      if (loc && at > 0) loc.line += lineOfIndex(code, at) - 1;
      findings.push({
        id: "wallet-file-access",
        severity: reads && !sshClient ? "high" : mention ? "low" : "medium",
        file: path,
        line: loc?.line ?? null,
        snippet: loc?.snippet ?? "",
        why: sshClient
          ? "This code loads a private SSH key from disk and hands it to an SSH client, which is how a tool logs in to a server it manages. Nothing in this file sends the key anywhere, but check which key it is and which server it connects to before running it."
          : `This code reaches for the ${label} on disk. A coding-interview project has no business reading it; this is what credential-stealing malware targets. (An app that merely connects to a wallet like MetaMask in the browser is normal and is not what this flags.)`,
        next: sshClient
          ? "Read where the key goes before running this; if it is not your own server, do not run it."
          : "Do not run this repository. If you already did, move funds and rotate credentials; see https://github.com/chriszemmel/repocanary/blob/main/WHAT-TO-DO-NOW.md.",
      });
      break; // one finding per file is enough
    }
  }

  // technique: download-and-execute, fetches remote content and runs it.
  //
  // Proximity is what separates a dropper from a build script. A dropper
  // reads a response and runs it a few lines later; a build script's exec of
  // a local binary sits far from any URL, or has no URL at all. The match
  // therefore requires a download primitive and an execution primitive
  // within 300 characters, newlines included.
  // A download piped, substituted or saved into a shell, from any host that
  // is not an allowlisted installer, judged by the same matcher the Makefile
  // and Dockerfile rules use.
  // Every test in this rule reads `code` rather than `content`. A comment is
  // not a download and not an exec. AutoGPT's Windows installer was called
  // malware for the REM line explaining why it shells out to curl instead of
  // Invoke-WebRequest: the words "PowerShell" and "Invoke-WebRequest" in one
  // sentence of prose, and nothing in the file that fetched or ran anything.
  // A file a shell runs line by line executes what it holds; anything else
  // has to be told to. So in a source file a command inside a markdown fence
  // is documentation being printed, and in a script it is not a fence at all
  // (a line of backticks there is a failing command), which is exactly the
  // gap an attacker would wrap a payload in. Only the first kind is blanked.
  const scriptLike = SCRIPT_FILE.test(path) || !/\.[A-Za-z0-9]+$/.test(path);
  // A regular expression is a pattern to match, not code to run. Security
  // tools list the shapes they refuse as regex literals, and
  // baekenough/oh-my-customcode's checker put /curl\s+.*\|\s*(bash|sh|eval)/
  // a few lines from a pattern for eval, which read as a download handed to
  // eval. Only in a source file: in a script a slash is a path.
  // A Python docstring, or any string standing alone as a statement, is
  // prose: nothing reads its value. Ikalus1988/MisakaNet's installer
  // explains that "the bootstrap route (`curl … bootstrap.sh | bash`)
  // downloads this file" in the docstring of a file that also spawns.
  const sourceCode = scriptLike ? code : withoutRegexBodies(isPy ? withoutPythonDocstrings(code) : code);
  const runnable = scriptLike ? code : withoutFencedBlocks(sourceCode);
  const shellDownload = downloadIntoShell(runnable, selfUrls);
  const POWERSHELL_DOWNLOAD =
    /powershell[^\n]{0,80}(-enc(?:odedcommand)?\b|downloadstring|iwr|invoke-webrequest)/i;
  const pipesToShell =
    shellDownload !== null ||
    // "-enc" is PowerShell's abbreviation of -EncodedCommand. "-Encoding" is
    // an unrelated cmdlet parameter that starts with the same four letters,
    // and matching its prefix convicted Chocolatey for the debug line
    // "Detected Powershell version < 6 ; Using -Encoding byte parameter" and
    // Scoop for a comment saying the same thing. Both are package managers
    // listed as expected reds, so both false positives sat behind an entry
    // that said the red was correct.
    runnable.split("\n").some((l) => POWERSHELL_DOWNLOAD.test(l) && !onlyLoopback(l) && !onlyOwnUrls(l, selfUrls));

  // A fetch primitive close to an execution primitive. The two orders cover
  // "fetch then run" and "run something built from a fetch".
  // A bare `fetch(` is a network call in JavaScript and an ordinary function
  // name everywhere else. Scrapy's interactive shell defines fetch() to load
  // a URL into the REPL and eval()s what the user types a few lines below,
  // and the two together read as a dropper running fetched code. Python's
  // download primitives are urllib and requests, both still listed.
  // urllib.parse is not a download: it is Python's string library for URLs,
  // and half the standard library's users import it beside subprocess for
  // reasons that have nothing to do with the network. pipenv names
  // urllib.parse.unquote in a docstring about not leaking credentials and
  // Red-DiscordBot imports it in a release helper. ecosystems.js already
  // listed the request half by name; this list did not.
  //
  // \b on curl and wget because without it the tokens matched inside longer
  // words: borg's `assert warning_type in ("percent", "curly")` supplied the
  // "fetch" half of fetch-near-spawn on the letters of "curly", and django's
  // release notes did the same. curl_exec and curl_init stay listed by name,
  // since those are PHP's download primitive and \b would drop them.
  const FETCH_TOKENS = [
    "\\bcurl(_(exec|init|setopt|multi_exec))?\\b", "\\bwget\\b",
    "axios\\.(get|post)", "https?\\.get", "http\\.get",
    "got\\s*\\(", "urllib\\.request|urllib2|urlretrieve|urlopen\\s*\\(",
    "requests\\.(get|post)", "\\.download\\s*\\(",
  ];
  // Compiled languages have no global fetch and no spawn by that name: jj's
  // `fn fetch(` asks git for refs, and `.spawn(` in Rust starts a thread or
  // an async task (zed, gitui); a child process is `.spawn()` with no
  // closure, and the other languages' process primitives are named below.
  const COMPILED = /\.(rs|go|java|kt|kts|cs|swift|c|cc|cpp|h|hpp|scala|dart|zig)$/i.test(path);
  if (!isPy && !COMPILED) FETCH_TOKENS.push("(?<!\\w)fetch\\s*\\(");
  const FETCH = `(${FETCH_TOKENS.join("|")})`;
  // (?<!\\.) excludes method calls like a regexp's .exec() or a string's, which
  // are not process spawns. execSync/execFile and child_process cover the
  // real shell-exec forms that do use a dot.
  // `->exec(` is a PHP method (PDO runs SQL with it) and `::spawn(` starts
  // a Rust thread or task; neither starts a process.
  // subprocess counts where it starts something: subprocess.STDOUT and
  // subprocess.PIPE are constants, and bitcoin's verify script passing them
  // to its wget call read as a second spawn beside the download.
  const SPAWN = COMPILED
    ? "(\\.spawn\\(\\s*\\)|std::process|\\bexec\\.Command\\b|ProcessBuilder|Runtime\\.getRuntime\\(\\)\\.exec|Process\\.Start|(?<![.>\\w])system\\s*\\(|\\bpopen\\s*\\(|\\bexecv\\w*\\s*\\()"
    : "(execSync|execFile|spawnSync|(?<!::)spawn\\s*\\(|child_process|subprocess\\.(?:run|call|check_call|check_output|Popen|getoutput|getstatusoutput)\\b|\\bPopen\\s*\\(|os\\.system|os\\.popen|(?<![.>])\\bexec\\s*\\(|(?<![.>])\\bsystem\\s*\\()";
  // Import declarations do not supply either primitive: they state that the
  // file may use one, and two of them sit next to each other by
  // construction, which is the tightest adjacency there is. The tokens
  // reappear at the point of use, so a file that imports the process
  // module and later calls execSync still matches on execSync.
  // A curl whose body goes to /dev/null fetches a status code, not a
  // program: nikolai-vysotskyi/trace-mcp's postinstall polls its own control
  // plane with `curl -s -o /dev/null -w %{http_code}`.
  // A request to the machine itself fetches nothing from outside:
  // MMUCraft's deploy script posts to its API container at 127.0.0.1, and a
  // stress test curls a local server. The token is blanked where the URL
  // beside it is loopback.
  // Starting a named toolchain program runs that tool, not what was
  // downloaded: viem asks git for a commit, a Firebase sample hands an image
  // to ImageMagick, ruff's scripts use curl itself to fetch data. The call is
  // blanked so it is not counted as the spawn beside a fetch.
  const TOOL_SPAWN = new RegExp(
    // Argument-list forms run no shell, so the named program is all that
    // starts. A shell string counts only when it is one plain command:
    // `execSync("git status && curl ... | sh")` is still a pipeline.
    `\\b(?:execFileSync|execFile|spawnSync|spawn)\\s*\\(\\s*["'\`](?:${KNOWN_LOCAL_TOOL}|curl|wget)["'\`]\\s*[,)]|` +
      `\\b(?:execSync|execa|exec)\\s*\\(\\s*(["'\`])${KNOWN_LOCAL_TOOL}\\b[^"'\`|;&$<>]*\\1|` +
      `\\b(?:execFileSync|execFile|spawnSync|spawn)\\s*\\(\\s*["'](?:node|python3?|bun|deno|tsx)["']\\s*,\\s*\\[\\s*["']\\.{0,2}\\/?[\\w./-]+\\.(?:m?js|cjs|ts|py)["']|` +
      `\\bsubprocess\\.\\w+\\s*\\(\\s*\\[\\s*["'](?:${KNOWN_LOCAL_TOOL}|curl|wget)["']|` +
      `\\bos\\.system\\s*\\(\\s*(["'])${KNOWN_LOCAL_TOOL}\\b[^"'|;&$<>]*\\2|` +
      `\\bCommand::new\\s*\\(\\s*"(?:${KNOWN_LOCAL_TOOL}|curl|wget)"|\\bexec\\.Command\\s*\\(\\s*"(?:${KNOWN_LOCAL_TOOL}|curl|wget)"`,
    "g",
  );
  // A file whose every URL is the machine itself, with nothing that could
  // assemble another one, talks only to local services: LichtFeld-Studio's
  // MCP bridge posts to its own app on 127.0.0.1 and starts that app's
  // binary. The fetch tokens stand for nothing downloaded there.
  const urls = sourceCode.match(/\bhttps?:\/\/[^\s"'`)]+/gi) ?? [];
  const localOnly =
    urls.length > 0 &&
    urls.every((u) => /^https?:\/\/(?:localhost|127\.\d+\.\d+\.\d+|\[::1\]|0\.0\.0\.0)(?:[:/]|$)/i.test(u)) &&
    !/atob|b64decode|base64|fromCharCode|\\x[0-9a-f]{2}|codecs\.decode|fromhex|unhexlify|join\s*\(\s*\[/i.test(sourceCode);
  // Process primitives outside the scripting languages' names.
  const OTHER_SPAWN = /\bexec\.Command\b|ProcessBuilder|Runtime\.getRuntime\(\)\.exec|Process\.Start|proc_open|shell_exec|passthru|\bpopen\s*\(|Command::new|std::process/;
  const used = withoutImportLines(sourceCode)
    // Only the call goes: a curl or wget it names is still the download, and
    // a later spawn of what it saved is still judged against it.
    .replace(TOOL_SPAWN, (m) => m.replace(/(curl|wget)|[^\n]/g, (x, keep) => keep ?? " "))
    .replace(/\b(?:fetch|curl|wget)\b(?=[^\n]{0,120}?["'`\s(]https?:\/\/(?:localhost|127\.\d+\.\d+\.\d+|\[::1\]|0\.0\.0\.0)[:/"'`\s])/g, (m) => " ".repeat(m.length))
    // A relative URL is the page's own server: bpm-manager's smoke test
    // reads its app's `fetch('/api/documents/...')` calls as source text.
    .replace(/\bfetch(?=\s*\(\s*["'`]\.{0,2}\/(?!\/))/g, "     ")
    .replace(
    /\bcurl\b(?=[\s\S]{0,200}?['"]?(?:-o|--output)['"]?\s*,?\s*['"]?\/dev\/null\b)/g,
    "    ",
  )
    .replace(localOnly ? new RegExp(FETCH, "gi") : /(?!)/g, (m) => " ".repeat(m.length))
    // In a compiled language a process starts through a call, never through
    // text: xalgorix lists "system(", "popen(" and "curl " as markers to look
    // for in a payload it is testing. Inside a string literal there the
    // spawn names are data.
    .replace(COMPILED ? /"(?:[^"\\\n]|\\.){0,400}"|`[^`]{0,4000}`/g : /(?!)/g, (lit) => lit.replace(new RegExp(SPAWN, "gi"), (m) => " ".repeat(m.length)).replace(new RegExp(OTHER_SPAWN.source, "gi"), (m) => " ".repeat(m.length)));
  const near = (a, b) => new RegExp(`${a}[\\s\\S]{0,300}?${b}`, "i").test(used);
  // Adjacency means something only where a line break means something. A
  // minified bundle is one line of megabytes, so three hundred characters
  // spans unrelated functions and everything looks adjacent to everything:
  // Yarn's own release bundle in .yarn/releases earned a caution in prettier
  // and jest for spawning processes, which is what a package manager does.
  // The rule still reports; it just stops calling the distance evidence.
  const fetchNearSpawn = !vendored && (near(FETCH, SPAWN) || near(SPAWN, FETCH));

  // Executing fetched CODE, not a downloaded binary, is what separates a
  // dropper from an ordinary native-module installer. sharp and node-gyp
  // legitimately download a binary and run it (medium, worth a look); a
  // dropper runs the bytes it fetched through an inline interpreter or eval
  // (high). The tell is an inline-code runner near the fetch.
  // eval and Function handed over as a callback run whatever they are
  // given just the same: passing eval itself to .then() was green where an
  // arrow calling it on the text was red.
  const EVAL_BY_REFERENCE = "\\.(?:then|map|forEach)\\s*\\(\\s*(?:eval|Function)\\s*[),]|\\b(?:setTimeout|setInterval)\\s*\\(\\s*(?:eval|Function)\\b";
  const INLINE_CODE = `((node|python3?|deno|bun|ruby|php)\\s+-(e|c)\\b|(?<!\\.)\\beval\\s*\\(|new\\s+Function\\s*\\(|${EVAL_BY_REFERENCE})`;
  // An eval or Function whose every argument is a string literal runs code
  // written in the file, which is what a reader can already see; nothing
  // fetched can reach it. A Function constructor whose body is the literal
  // `return import(s)` is the standard way to keep a bundler from rewriting
  // a dynamic import, and dhanushgopi2456/interview-prep-kit turned red for
  // one beside a fetch() fallback. Blanked with spaces so offsets stay put.
  // A download piped into `python3 -c '...'` or `node -e '...'` is that
  // program's input, not its code: the program is the literal after the
  // flag. mixpeek/amux prints a recheck command that pretty-prints its own
  // log API that way, and the interpreter flag beside the curl read as
  // fetched code being run.
  // eval and the Function constructor are primitives of the dynamic
  // languages. In Rust, Go or Java a method that happens to be called eval
  // evaluates something else: lablup/mlxcel forces a lazy MLX array with
  // mlxcel_core's eval function on an array.
  const NO_EVAL_LANGUAGE = /\.(rs|go|java|kt|kts|cs|swift|c|cc|cpp|h|hpp|scala|dart|zig)$/i.test(path);
  const literalCode = (NO_EVAL_LANGUAGE ? used.replace(/\beval\s*\(|new\s+Function\s*\(/g, (m) => " ".repeat(m.length)) : evalCallsOutsideStrings(used))
    .replace(LITERAL_CODE_CALL, (m) => " ".repeat(m.length))
    .replace(/\|\s*(?:node|python3?|deno|bun|ruby|php)\s+-(?:e|c)\b/gi, (m) => " ".repeat(m.length));
  const nearCode = (a, b) => new RegExp(`${a}[\\s\\S]{0,300}?${b}`, "i").test(literalCode);
  const runsFetchedCode = nearCode(FETCH, INLINE_CODE) || nearCode(INLINE_CODE, FETCH);

  // The forms that take a VALUE and run it as code, which is what a fetched
  // response becomes in a dropper. Kept apart from the -e and -c interpreter
  // flags on purpose: `curl ... | python3 -c "json.load(sys.stdin)"` runs a
  // program written in the file and merely parses what it fetched, which is
  // an everyday shell idiom. The dangerous shapes of -e and -c take the
  // download through a pipe or a command substitution, and downloadIntoShell
  // already reads those.
  const EVAL_OF_VALUE = `((?<!\\.)\\beval\\s*\\(|new\\s+Function\\s*\\(|${EVAL_BY_REFERENCE})`;
  const evalsFetched = nearCode(FETCH, EVAL_OF_VALUE) || nearCode(EVAL_OF_VALUE, FETCH);

  // Proximity grades this rule; it no longer gates it. Three hundred
  // characters is a threshold an attacker can simply step over, and the same
  // dropper with ordinary logging between its halves used to produce nothing
  // at all. Both primitives anywhere in a file is worth reporting; how close
  // they sit, and whether this is a file something runs by itself, is what
  // decides how loudly.
  const hasFetch = new RegExp(FETCH, "i").test(used);
  const hasSpawn = new RegExp(SPAWN, "i").test(used);

  // A download written somewhere that will be executed later needs no spawn
  // in this file at all: the second stage runs from PATH or from the manifest
  // that names it. That shape had no rule.
  const persistsPayload =
    /createWriteStream|writeFileSync|copyFileSync|\.pipe\s*\(/i.test(code) &&
    /node_modules\/\.bin|chmod|0o?7[0-7][0-7]|["']\+x["']/i.test(code);

  // evalsFetched belongs in the entry condition, not only in the severity: a
  // fetch whose response goes straight into eval never spawns anything, so
  // the strongest dropper shape of all used to miss the gate it graded.
  if (pipesToShell || fetchNearSpawn || evalsFetched || (hasFetch && hasSpawn) || (hasFetch && persistsPayload)) {
    // Adjacency still carries the conviction, and so does a file an install
    // script or an editor hook actually runs. The two far apart in a large
    // build script is a caution, which is what it was worth all along.
    // A download piped into a shell is a command in a script and a string in
    // a source file. sst's CLI carries "curl -fsSL https://sst.dev/install |
    // bash" inside a Go string literal, because it prints its own install
    // instructions as markdown, and that made the tool that prints the
    // instructions indistinguishable from a dropper. In a shell script,
    // Makefile or CI step the file itself is what runs the line, so nothing
    // more is needed; in a .go, .js or .py file something has to execute it,
    // and sst's main.go has no process-spawning primitive anywhere in it.
    // The CI-path step-down now lives in one place, beside the test-path one,
    // and applies to every rule rather than to this one alone.
    // A download piped into a shell is a command in a script and a string in
    // a source file, and the comment above already says so; the code did not.
    // GkhanKINAY/postqueen-app turned red for a catalog of install
    // instructions in a .ts file, each one a `code:` field the page shows in
    // a copy-to-clipboard box. In a file a shell runs line by line, or one
    // an install script or editor hook starts, the line is the command. In
    // any other source file something in that file has to hand the string to
    // a shell, so a spawn primitive is required for the conviction; without
    // one it is a caution to read.
    const runsCommands =
      hasSpawn ||
      OTHER_SPAWN.test(used);
    // A directive is the one comment a tool runs: `//go:generate curl | sh`
    // is the command, whatever file it sits in.
    const pipeLine = shellDownload ? (code.split("\n")[shellDownload.line - 1] ?? "") : "";
    const directive = /^\s*\/\/\s*go:generate\b/.test(pipeLine);
    // A pipe bound to a name that never reaches a spawn is an install hint,
    // however many processes the file starts for other reasons; see
    // bindingNeverSpawned. A string handed to a spawn, directly or through
    // an alias, is still a command.
    const shownOnly = shellDownload ? bindingNeverSpawned(code, pipeLine, shellDownload.line) : false;
    // In a program, as opposed to a script a shell reads line by line, text
    // becomes a command only by being handed to a shell, and that happens
    // where the program spawns. A file something starts is still a program:
    // tjcoder-labs/cli's postinstall prints the Go installer's one-liner in an
    // error message, and a docs page renders one inside <code>. When the
    // string's binding is unknown, a spawn within forty lines of it is what
    // stands in for the flow.
    const psLine = runnable.split("\n").findIndex((l) => POWERSHELL_DOWNLOAD.test(l) && !onlyLoopback(l) && !onlyOwnUrls(l, selfUrls));
    const pipeAt = shellDownload ? shellDownload.line : psLine + 1;
    // The string handed straight to a method that runs commands is a command,
    // whatever object carries the method: oh-my-customcode installs rtk with
    // deps.exec('curl ... | sh'). A regex's .exec reads no such string.
    const lines = used.split("\n");
    const pipeText = lines[pipeAt - 1] ?? "";
    const curlAt = pipeText.search(/\b(curl|wget)\b/);
    const leadIn = [...lines.slice(Math.max(0, pipeAt - 3), pipeAt - 1), curlAt === -1 ? pipeText : pipeText.slice(0, curlAt)].join("\n");
    const handedToRunner = pipeAt > 0 && /\.(?:exec|execSync|execa|execaCommand|run|spawn|system|shell)\s*\(\s*["'`]?$/.test(leadIn.trimEnd());
    const spawnNear =
      pipeAt > 0 &&
      used
        .split("\n")
        .slice(Math.max(0, pipeAt - 41), pipeAt + 40)
        .some((l) => new RegExp(SPAWN).test(l) || OTHER_SPAWN.test(l));
    const printed = shellDownload ? insidePrintCall(used, shellDownload.line) : false;
    const pipeIsCommand = scriptLike || handedToRunner || (runsCommands && !shownOnly && spawnNear && !printed) || directive;
    const high = (pipesToShell && pipeIsCommand) || runsFetchedCode || (fetchNearSpawn && executable);
    // Two capabilities present somewhere in one file, with nothing bringing
    // them together and nothing running the file, is informational rather
    // than a caution. The severity used to be medium for that, while the
    // sentence printed beside it said "close together", which the condition
    // did not require: prettier and tailwind each earned one for an import
    // line naming the process module beside a fetch elsewhere in the file,
    // and vue for a release script. It fired on 28 of the 71 repositories in
    // the benign standing set, which is what a rule looks like just before
    // people learn to page past it.
    //
    // `executable` is the other half and has to stay: a dropper whose fetch
    // and exec are separated by forty lines of padding is still a dropper
    // when a lifecycle script or an editor config is what starts the file,
    // and scan.js escalates a medium there. Dropping that to a low took a
    // real one from red to yellow, and test/scan.test.js caught it.
    //
    // Adjacency, a shell pipe, an eval of a response, or a payload written
    // to disk all still carry a medium wherever they are. Three lows are
    // still a yellow, so a file doing several odd things is not silenced.
    const worthACaution =
      pipesToShell || fetchNearSpawn || evalsFetched || (hasFetch && persistsPayload) || executable;
    // Point at the line that actually fired, not at the first token that
    // looks like one. AutoGPT's report named line 110, a comment mentioning
    // curl, while the match that convicted it was the PowerShell one on 112.
    // A reader who opens the named line and finds nothing wrong there learns
    // to distrust the finding, which is the whole of its value.
    const loc =
      shellDownload ??
      (POWERSHELL_DOWNLOAD.test(runnable) ? matchLocation(runnable, POWERSHELL_DOWNLOAD) : null) ??
      (fetchNearSpawn ? matchLocation(code, new RegExp(`${FETCH}[\\s\\S]{0,300}?${SPAWN}|${SPAWN}[\\s\\S]{0,300}?${FETCH}`, "i")) : null) ??
      // Every token the gate above can fire on, so a finding never goes out
      // with no line and an empty snippet: alldoneapp's helper earned one for
      // a storage client's .download() beside an exec(), and the report
      // printed a caution pointing at nothing.
      matchLocation(
        code,
        /(\bcurl\b|\bwget\b|powershell|child_process|execSync|execFile|spawn|axios\.(get|post)|https?\.get|\.download\s*\(|got\s*\(|urlopen|urlretrieve|requests\.(get|post)|subprocess|os\.system|(?<!\.)\bexec\s*\(|(?<!\.)\bsystem\s*\(|(?<!\.)\beval\s*\(|new\s+Function\s*\(|\bfetch\s*\()/i,
      );
    findings.push({
      id: "download-and-execute",
      severity: high ? "high" : worthACaution ? "medium" : "low",
      file: path,
      line: loc?.line ?? null,
      snippet: loc?.snippet ?? "",
      why: high
        ? "This code downloads something from the internet and runs it as a program. That means the visible source is only stage one; the real payload arrives at run time."
        : worthACaution
          ? "This code both downloads from the internet and runs external programs, close together. That can be a legitimate native-module installer fetching a prebuilt binary, but it is also how a dropper stages a payload, so check what is fetched and what is run."
          : "This file can both download from the internet and run external programs, but the two are far apart in it and nothing here connects them. Build and release scripts routinely do both for unrelated reasons. Reported so it is on the record, not because it looks wrong.",
      next: high
        ? "Do not run this repository. The fetched code can differ per victim, so no review of the repo alone clears it."
        : worthACaution
          ? "Check whether the downloaded file is a known binary or fetched code before installing."
          : "Nothing to do unless something else in this repository looks wrong.",
    });
  }

  // technique: crypto-stealer reaching a specific wallet extension by its ID
  const extMatch = content.match(WALLET_EXTENSION_ID_RE);
  if (extMatch) {
    const wallet = WALLET_EXTENSION_IDS.find((w) => w.id.toLowerCase() === extMatch[0].toLowerCase());
    const loc = matchLocation(content, WALLET_EXTENSION_ID_RE);
    findings.push({
      id: "wallet-extension-id",
      severity: "high",
      file: path,
      line: loc?.line ?? null,
      snippet: loc?.snippet ?? "",
      why: `This file hardcodes the browser-extension ID of the ${wallet?.label ?? "a crypto"} wallet. Code that reaches for a specific wallet extension's stored data by its ID is doing what a crypto-stealer does, not what a coding task does.`,
      next: "Do not run this repository. If you already did, move funds out of that wallet from a clean device.",
    });
  }

  // The signature tables read `code`, the file with comment-only lines
  // blanked. These rules all convict a file for DOING something, and a
  // sentence describing it is not the deed: ripgrep earned sandbox-evasion
  // for a /// doc comment about qemu, and stripe-node earned
  // stealer-file-globbing for prose describing a digital wallet.
  for (const sig of HIGH_SIGNATURES) {
    if (sig.pythonOnly && !isPy) continue;
    if (sig.dynamicOnly && /\.(rs|go|java|kt|kts|cs|swift|c|cc|cpp|h|hpp|scala|dart|zig)$/i.test(path)) continue;
    if (sig.minDistinct) {
      // The rule's own flags plus g, not a hardcoded "gi": a signature
      // declared case-sensitive was counted case-insensitively here and
      // case-sensitively by countMatches, so the two disagreed.
      const flags = sig.re.flags.includes("g") ? sig.re.flags : `${sig.re.flags}g`;
      const names = new Set((code.match(new RegExp(sig.re.source, flags)) ?? []).map((s) => s.toLowerCase()));
      if (names.size < sig.minDistinct) continue;
    }
    if (countMatches(code, sig.re) >= (sig.minMatches ?? 1)) {
      const loc = matchLocation(code, sig.re);
      // A signature can name a context that changes what the match means
      // rather than whether it fired. It only applies when every match sits
      // in that context: one line aimed at the reader's own machine is
      // enough to keep the finding at full weight.
      // A path under a directory the code made up is a fixture, not the
      // user's file: NaLanBoO0/Gdou-agent's policy test asks whether an agent
      // may write C:/fakehome/.ssh/authorized_keys and expects "deny".
      const allFake =
        sig.fakeRootSoftens &&
        [...code.matchAll(new RegExp(sig.re.source, sig.re.flags.includes("g") ? sig.re.flags : `${sig.re.flags}g`))].every((m) =>
          /(fake|tmp|temp|mock|test|fixture|dummy|sandbox)[\w-]*[\\/][^\s"'`]*$/i.test(code.slice(Math.max(0, m.index - 60), m.index + m[0].indexOf(".ssh") + 1)),
        );
      if (allFake) continue;
      if (sig.needsProbe && !sig.needsProbe.test(code)) {
        findings.push({ id: sig.id, severity: "low", file: path, line: loc?.line ?? null, snippet: loc?.snippet ?? "", why: `${sig.why} Here the names appear with nothing that asks the machine what it is, which is how build scripts, enums and map projections name them.`, next: "Nothing to do unless something else in this repository looks wrong." });
        continue;
      }
      const softened =
        (sig.elsewhere && everyMatchInContext(code, sig.re, sig.elsewhere.re)) ||
        (sig.mentionOnly && everyMatchInContext(code, sig.re, sig.mentionOnly.when) && !sig.mentionOnly.needs.test(code));
      const soft = softened && sig.mentionOnly && !(sig.elsewhere && everyMatchInContext(code, sig.re, sig.elsewhere.re)) ? sig.mentionOnly : sig.elsewhere;
      findings.push({
        id: sig.id,
        severity: softened ? "medium" : "high",
        file: path,
        line: loc?.line ?? null,
        snippet: loc?.snippet ?? "",
        why: softened ? `${sig.why} ${soft.why}` : sig.why,
        next: softened ? soft.next : sig.next,
      });
    }
  }
  for (const sig of MED_SIGNATURES) {
    if (countMatches(code, sig.re) >= (sig.minMatches ?? 1)) {
      const loc = matchLocation(code, sig.re);
      const every = [...code.matchAll(new RegExp(sig.re.source, sig.re.flags.includes("g") ? sig.re.flags : `${sig.re.flags}g`))];
      const soft =
        (sig.lowWhen && every.every((m) => sig.lowWhen.test(code.slice(m.index, m.index + m[0].length + 12)))) ||
        (sig.needsProbe && !sig.needsProbe.test(code));
      findings.push({
        id: sig.id,
        severity: soft ? "low" : "medium",
        file: path,
        line: loc?.line ?? null,
        snippet: loc?.snippet ?? "",
        why: sig.why,
        next: sig.next,
      });
    }
  }

  const persistence = checkShellPersistence(path, content);
  if (persistence) findings.push(persistence);

  findings.push(...checkObfuscation(path, content, size));
  return findings;
}

/**
 * Jupyter notebooks (.ipynb) are JSON, so the same code checks would never
 * see the code hidden in their cells. Many "ML take-home" lures ship a
 * malicious notebook. This extracts the source of every code cell and runs
 * the ordinary code checks over it, in the notebook's own language, so a
 * dropper in a cell is caught exactly as it would be in a .py or .js file.
 */
export function checkNotebook(path, content, size) {
  const parsed = safeJsonParse(content);
  if (!parsed.ok || !parsed.value || !Array.isArray(parsed.value.cells)) return [];
  const language =
    parsed.value.metadata?.kernelspec?.language ||
    parsed.value.metadata?.language_info?.name ||
    "python";
  const sources = [];
  for (const cell of parsed.value.cells) {
    if (!cell || cell.cell_type !== "code") continue;
    const src = Array.isArray(cell.source) ? cell.source.join("") : typeof cell.source === "string" ? cell.source : "";
    if (src) sources.push(src);
  }
  if (sources.length === 0) return [];
  const code = sources.join("\n");
  const langOverride = /python/i.test(language) ? "python" : /javascript|typescript|node/i.test(language) ? "js" : "python";
  // Size from the extracted code, not the notebook's JSON wrapper: the
  // blob and density rules measure lines and bytes, and the wrapper's
  // are not the cells'.
  return checkCodeContent(path, code, { bytes: code.length, lines: code.split("\n").length }, langOverride);
}
