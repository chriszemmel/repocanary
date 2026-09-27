/**
 * Small text helpers shared by every rule module.
 *
 * Snippets shown to the user are always redacted here: whitespace collapsed,
 * long encoded blobs shortened, control characters stripped, length capped.
 * A scanner for malware must never re-print a working payload at the user.
 */

// C1 as well as C0: U+009B is CSI and U+009D is OSC in a terminal that
// honours 8-bit controls in UTF-8, so a snippet carrying them can clear the
// screen and print a green headline without a single ESC byte.
const CONTROL_CHARS = new RegExp("[\\u0000-\\u0008\\u000b-\\u001f\\u007f-\\u009f]", "g");

/**
 * A copy of a JSON document with `\uXXXX` escapes resolved, for matching.
 *
 * An editor parses these files, so `{"\u0068ooks": ...}` is the key `hooks`
 * to it and has to be to us as well. Rules that match the raw text would
 * otherwise be evaded by a document the editor honours identically, which is
 * a mechanical bypass rather than a clever one.
 *
 * Two kinds of escape are left alone. A quote or a backslash would invent
 * string boundaries that are not there, and a control character would change
 * how many lines the document has, which would move every finding's line
 * number. So this shifts columns and never lines: use it to decide, and
 * either text to locate.
 */
export function decodeJsonEscapes(content) {
  if (!content.includes("\\u")) return content;
  return content.replace(/\\u([0-9a-fA-F]{4})/g, (whole, hex) => {
    const code = parseInt(hex, 16);
    if (code < 0x20 || code === 0x22 || code === 0x5c) return whole;
    return String.fromCharCode(code);
  });
}

/**
 * The same idea for YAML, and narrower, because YAML resolves escapes only
 * inside a double-quoted scalar. In `'\u0063url'` or in a plain scalar those
 * six characters are literally themselves, so decoding everywhere would
 * convict a workflow that merely writes the sequence down.
 */
export function decodeYamlEscapes(content) {
  if (!content.includes("\\u") && !content.includes("\\x")) return content;
  // A hand-written scan, not /"(?:[^"\\\n]|\\.)*"/g: a line of `"\` repeated
  // made that regex retry from every quote to the end of the line, and a
  // 160 KB workflow took fourteen seconds. When a scalar is not closed on
  // its line, every quote inside it is escaped, and a match starting from an
  // escaped quote fails at the same place, so skipping to the line end finds
  // exactly the scalars the regex found.
  let out = "";
  let from = 0;
  let i = content.indexOf('"');
  while (i !== -1) {
    let j = i + 1;
    let open = true;
    while (open && j < content.length && content[j] !== '"' && content[j] !== "\n") {
      if (content[j] !== "\\") j += 1;
      // An escape takes any one character except a line terminator, as `.`
      // does; a backslash before one ends the attempt right there.
      else if (j + 1 < content.length && !LINE_TERMINATOR.test(content[j + 1])) j += 2;
      else open = false;
    }
    if (open && content[j] === '"') {
      out += content.slice(from, i) + decodeYamlScalar(content.slice(i, j + 1));
      from = j + 1;
      i = content.indexOf('"', j + 1);
    } else {
      i = j >= content.length ? -1 : content.indexOf('"', j + 1);
    }
  }
  return out + content.slice(from);
}

const LINE_TERMINATOR = /[\n\r\u2028\u2029]/;

function decodeYamlScalar(scalar) {
  return scalar.replace(/\\(?:u([0-9a-fA-F]{4})|x([0-9a-fA-F]{2}))/g, (whole, u, x) => {
    const code = parseInt(u ?? x, 16);
    // Same exclusions as the JSON decoder: nothing that could invent a
    // string boundary, and nothing that could change the line count.
    if (code < 0x20 || code === 0x22 || code === 0x5c) return whole;
    return String.fromCharCode(code);
  });
}

/** Return a non-global clone of a regex, so .match() reports the match index. */
function nonGlobal(re) {
  return re.global ? new RegExp(re.source, re.flags.replace("g", "")) : re;
}

/**
 * The newline offsets of the file most recently asked about, so repeated
 * lookups into one file cost a binary search instead of a walk from its
 * start. Rules call this once per match and once per dependency, which on a
 * manifest with twenty thousand dependencies made a 0.4 MB file take nine
 * seconds. One entry is the right size: a scan reads one file at a time, and
 * every rule sees that file before the next one is fetched.
 *
 * This is a memo, not state: the answer for a given (content, index) is the
 * same whether or not the cache is warm.
 */
let indexedContent = null;
let newlineOffsets = null;

function offsetsFor(content) {
  if (content === indexedContent) return newlineOffsets;
  const offsets = [];
  for (let i = 0; i < content.length; i++) if (content.charCodeAt(i) === 10) offsets.push(i);
  indexedContent = content;
  newlineOffsets = offsets;
  return offsets;
}

/** 1-based line number of a character index in content. */
export function lineOfIndex(content, index) {
  const offsets = offsetsFor(content);
  // How many newlines start before this index; the line number is one more.
  let low = 0;
  let high = offsets.length;
  while (low < high) {
    const mid = (low + high) >> 1;
    if (offsets[mid] < index) low = mid + 1;
    else high = mid;
  }
  return low + 1;
}

/**
 * Redact a raw excerpt for display: collapse whitespace, strip control
 * characters, shorten anything that looks like an encoded payload, and cap
 * the length so a snippet can never smuggle the payload back to the user.
 */
/**
 * Characters that change how the text around them is displayed, or that
 * display as nothing at all: bidirectional overrides, zero-width joiners and
 * spaces, the byte-order mark, and the Unicode tag block.
 *
 * These are what several rules exist to find, which is exactly why a snippet
 * must not reproduce them. A report that quotes "safe\u202egnp.txt.exe"
 * renders in the reader's terminal as the filename the attacker wanted them
 * to see, so the warning performs the trick instead of revealing it. Written
 * out as their code points, the finding becomes readable and inert.
 */
const DECEPTIVE_CHARS = /[\u061c\u200b-\u200f\u202a-\u202e\u2060-\u2064\u2066-\u2069\ufeff\u180e]|[\u{e0000}-\u{e007f}]/gu;

const codePoint = (ch) => `<U+${ch.codePointAt(0).toString(16).toUpperCase().padStart(4, "0")}>`;

export function redactSnippet(raw, maxLength = 200) {
  let s = String(raw).replace(CONTROL_CHARS, " ").replace(DECEPTIVE_CHARS, codePoint).replace(/\s+/g, " ").trim();
  // Shorten base64 / hex runs so no working payload survives in the report.
  s = s.replace(/[A-Za-z0-9+/=]{48,}/g, (m) => `${m.slice(0, 24)}...[${m.length} chars redacted]`);
  s = s.replace(/(?:\\x[0-9a-fA-F]{2}){12,}/g, (m) => `${m.slice(0, 16)}...[hex redacted]`);
  if (s.length > maxLength) s = `${s.slice(0, maxLength - 3)}...`;
  return s;
}

/**
 * The same protection for an excerpt meant to be read as code.
 *
 * redactSnippet collapses all whitespace, which is right for a one-line
 * snippet and wrong for a script body: the report prints those over several
 * lines and a reader is meant to follow them. So newlines and tabs survive
 * here and everything else that could repaint a terminal does not.
 */
export function redactBlock(raw, maxLength = 600) {
  // CONTROL_CHARS already spares the tab and the newline, which is exactly
  // what a block needs to keep and a one-line snippet does not.
  let s = String(raw)
    .replace(CONTROL_CHARS, " ")
    .replace(DECEPTIVE_CHARS, codePoint)
    .replace(/[^\S\n]+/g, " ")
    .replace(/[ \t]+$/gm, "");
  s = s.replace(/[A-Za-z0-9+/=]{48,}/g, (m) => `${m.slice(0, 24)}...[${m.length} chars redacted]`);
  s = s.replace(/(?:\\x[0-9a-fA-F]{2}){12,}/g, (m) => `${m.slice(0, 16)}...[hex redacted]`);
  if (s.length > maxLength) s = `${s.slice(0, maxLength - 3)}...`;
  return s;
}

/**
 * Locate the first match of a regex and return the line number plus a
 * redacted snippet of the surrounding text. Returns null when no match.
 */
export function matchLocation(content, re, span = 140) {
  const m = content.match(nonGlobal(re));
  if (!m || m.index === undefined) return null;
  // The excerpt starts where a reader would: at the start of the match's
  // line when that is close, otherwise after the first space in the 40
  // characters of lead-in. A fixed offset began excerpts mid-token, as in
  // `base.js", "runOptions"`, in the first thing every report shows.
  const lineStart = content.lastIndexOf("\n", m.index - 1) + 1;
  let start = Math.max(0, m.index - 40);
  if (lineStart >= start) start = lineStart;
  else {
    const gap = content.slice(start, m.index).search(/\s\S/);
    if (gap !== -1) start += gap + 1;
  }
  // And ends after a whole word where the cap allows it.
  const matchEnd = m.index + m[0].length;
  let end = m.index + Math.min(m[0].length + span, 300);
  if (end < content.length) {
    const lastSpace = content.slice(matchEnd, end).search(/\s\S*$/);
    if (lastSpace > 0) end = matchEnd + lastSpace;
  }
  return {
    line: lineOfIndex(content, m.index),
    snippet: redactSnippet(content.slice(start, end)),
  };
}

/** How many times a pattern matches; 0/1 for non-global, full count for global. */
export function countMatches(content, re) {
  if (!re.global) return re.test(content) ? 1 : 0;
  return (content.match(re) ?? []).length;
}

/**
 * How deep a walk over parsed manifest JSON may go.
 *
 * V8 parses arbitrarily nested JSON happily; it is the recursive walk over the
 * result that overflows the stack, so safeJsonParse cannot protect these. A
 * 29 KB package.json of nothing but nesting aborted a whole scan. Real
 * manifests are a handful of levels deep, so anything past this is a
 * structure built to crash a reader rather than to describe dependencies.
 */
export const MAX_MANIFEST_DEPTH = 100;

/**
 * Guarded JSON parse: never blind-parse text you did not produce. Returns
 * { ok: true, value } or { ok: false, error } and never throws.
 */
export function safeJsonParse(text) {
  try {
    return { ok: true, value: JSON.parse(text) };
  } catch (err) {
    return { ok: false, error: err instanceof Error ? err.message : String(err) };
  }
}

/**
 * JSON as the editors that read these files actually parse it.
 *
 * devcontainer.json is JSONC by specification, and VS Code reads tasks.json,
 * settings.json and mcp.json with the same parser: comments and trailing
 * commas are legal in all of them. JSON.parse rejects both, and every rule
 * that reached for a parsed object returned nothing at all when it did, so
 * one trailing comma turned a dev container whose postCreateCommand pipes a
 * download into a shell from red into green, with no finding and no note.
 *
 * Strings are walked rather than stripped with a pattern, because "//" inside
 * a URL is not a comment and a comma inside a string is not a trailing one.
 */
export function parseJsonc(text) {
  let out = "";
  let i = 0;
  while (i < text.length) {
    const c = text[i];
    if (c === '"') {
      const start = i++;
      while (i < text.length && text[i] !== '"') i += text[i] === "\\" ? 2 : 1;
      out += text.slice(start, Math.min(i + 1, text.length));
      i += 1;
    } else if (c === "/" && text[i + 1] === "/") {
      // Kept as a newline, not dropped: line numbers reported from the
      // original text have to keep matching the document the user opens.
      while (i < text.length && text[i] !== "\n") i += 1;
    } else if (c === "/" && text[i + 1] === "*") {
      const end = text.indexOf("*/", i + 2);
      const skipped = text.slice(i, end === -1 ? text.length : end + 2);
      out += skipped.replace(/[^\n]/g, "");
      i = end === -1 ? text.length : end + 2;
    } else {
      out += c;
      i += 1;
    }
  }
  return safeJsonParse(out.replace(/,(\s*[}\]])/g, "$1"));
}

/**
 * File signatures that identify an embedded asset rather than a payload.
 *
 * A base64 blob beside the code that decodes it is the shape of a smuggled
 * payload, and it is equally the shape of a demo that inlines a sound file
 * because its playground cannot serve one. The blob's own first bytes tell
 * the two apart: audio, images and fonts are data a browser renders, and
 * none of them is something a machine can be made to execute.
 *
 * Deliberately absent: zip and gzip (an archive of anything, code included),
 * WebAssembly, ELF, Mach-O and PE, and a shebang. Those decode to something
 * that runs, which is the whole question, so they stay convicted.
 */
const ASSET_SIGNATURES = [
  [0, [0x4f, 0x67, 0x67, 0x53]], // OggS: Ogg audio or video
  [0, [0x89, 0x50, 0x4e, 0x47]], // PNG
  [0, [0xff, 0xd8, 0xff]], // JPEG
  [0, [0x47, 0x49, 0x46, 0x38]], // GIF8
  [0, [0x52, 0x49, 0x46, 0x46]], // RIFF: WAV, WebP, AVI
  [0, [0x49, 0x44, 0x33]], // ID3: MP3 with a tag
  [0, [0xff, 0xfb]], // MP3 frame
  [0, [0x77, 0x4f, 0x46, 0x46]], // wOFF font
  [0, [0x77, 0x4f, 0x46, 0x32]], // wOF2 font
  [0, [0x4f, 0x54, 0x54, 0x4f]], // OTTO: OpenType font
  [0, [0x00, 0x01, 0x00, 0x00]], // TrueType font
  [0, [0x25, 0x50, 0x44, 0x46]], // %PDF
  [4, [0x66, 0x74, 0x79, 0x70]], // ftyp at offset 4: MP4, M4A, HEIC
];

/** WebAssembly's magic bytes: "\0asm", then a version word. */
const WASM_SIGNATURE = [0x00, 0x61, 0x73, 0x6d];

/**
 * Does this base64 text decode to a known media or font file?
 *
 * Only the first bytes are decoded, so the cost does not depend on the size
 * of the blob, and a blob that merely starts with an image header while
 * carrying something else after it is not what this claims: it says the
 * bytes a decoder would hand a media API begin as that media, which is the
 * question a reviewer is actually asking.
 */
export function looksLikeEncodedAsset(base64) {
  const head = String(base64).replace(/[^A-Za-z0-9+/=]/g, "").slice(0, 16);
  if (head.length < 8) return false;
  let bytes;
  try {
    bytes = Buffer.from(head, "base64");
  } catch {
    return false;
  }
  if (bytes.length < 4) return false;
  return ASSET_SIGNATURES.some(
    ([at, sig]) => bytes.length >= at + sig.length && sig.every((b, i) => bytes[at + i] === b),
  );
}

/**
 * Does this base64 text decode to a plain word list: printable text, one
 * short entry per line, and almost no line carrying the punctuation code is
 * written in?
 *
 * continuedev/continue inlines LLaMA's tokenizer vocabulary this way, one
 * token per line, and decodes it with atob beside the tokenizer that reads
 * it; that turned the most widely used open coding assistant red. A script
 * encoded to hide it decodes to calls, braces and semicolons, and a single
 * long line of minified code fails the line count, so the step this earns
 * is taken by data and not by a payload. Only the first few kilobytes are
 * decoded, so the cost does not depend on the blob.
 */
export function looksLikeEncodedWordList(base64) {
  const head = String(base64).replace(/[^A-Za-z0-9+/]/g, "").slice(0, 4096);
  if (head.length < 1024) return false;
  let text;
  try {
    text = Buffer.from(head.slice(0, head.length - (head.length % 4)), "base64").toString("utf8");
  } catch {
    return false;
  }
  // UTF-8, since a vocabulary is not ASCII: a control character or a byte
  // that does not decode is what binary looks like.
  let printable = 0;
  for (let i = 0; i < text.length; i++) {
    const c = text.charCodeAt(i);
    if (c === 10 || c === 9 || (c >= 32 && c !== 127 && c !== 0xfffd)) printable += 1;
  }
  if (printable / text.length < 0.97) return false;
  // The last line was cut wherever the sample ended.
  const lines = text.split("\n").slice(0, -1);
  if (lines.length < 50) return false;
  const lengths = lines.map((l) => l.length).sort((a, b) => a - b);
  if (lengths[Math.floor(lengths.length / 2)] > 24) return false;
  const codeLike = lines.filter((l) => /[;{}()]|=>|\b(function|require|import|eval|exec)\b/.test(l)).length;
  return codeLike / lines.length < 0.05;
}

/**
 * Does this base64 text decode to a WebAssembly module?
 *
 * Deliberately NOT one of the asset signatures above: WebAssembly is
 * executable, and a blob that decodes to something runnable keeps its full
 * weight. This only reports the format; the caller decides what it means,
 * and the base64-blob rule only steps the severity down when the bytes also
 * go to the WebAssembly API rather than to eval or a shell.
 */
export function looksLikeWasm(base64) {
  const head = String(base64).replace(/[^A-Za-z0-9+/=]/g, "").slice(0, 16);
  if (head.length < 8) return false;
  let bytes;
  try {
    bytes = Buffer.from(head, "base64");
  } catch {
    return false;
  }
  return (
    bytes.length >= WASM_SIGNATURE.length &&
    WASM_SIGNATURE.every((b, i) => bytes[i] === b)
  );
}

/**
 * Wrap a paragraph at a column width, preserving an indent prefix.
 *
 * A word longer than the width is broken rather than allowed to overhang.
 * Prose has no such words, but a snippet is a line lifted out of the
 * repository under scan, and a URL, a hex run or a line of minified code
 * carries no space to break at. Those overhung by up to the snippet cap, so
 * the report announced 78 columns and then printed 90 whenever the scanned
 * file happened to contain a long token. The content that decides the width
 * is the scanned repository's, which is the wrong party to let decide it.
 */
export function wrapText(text, width = 78, indent = "") {
  const words = String(text).split(/\s+/).filter(Boolean);
  // A width that leaves no room for the indent would loop forever below.
  const room = Math.max(1, width - indent.length);
  const lines = [];
  let line = indent;
  for (const word of words) {
    let rest = word;
    while (rest.length > room) {
      if (line.length > indent.length) {
        lines.push(line);
        line = indent;
      }
      lines.push(indent + rest.slice(0, room));
      rest = rest.slice(room);
    }
    if (rest.length === 0) continue;
    if (line.length > indent.length && line.length + 1 + rest.length > width) {
      lines.push(line);
      line = indent + rest;
    } else {
      line += (line.length > indent.length ? " " : "") + rest;
    }
  }
  if (line.length > indent.length) lines.push(line);
  return lines.join("\n");
}

/**
 * Does every line a signature matched also sit in the given context? Used
 * where the same command means something different depending on what it is
 * aimed at, and a single match outside that context has to keep the finding
 * at full weight.
 */
/**
 * How many matches this will read before giving up. A file with more than
 * this is not something a context guard can honestly judge, so it stops
 * relaxing rather than stopping counting.
 */
const MAX_CONTEXT_MATCHES = 200;

export function everyMatchInContext(content, re, contextRe, scope = "line") {
  const global = new RegExp(re.source, re.flags.includes("g") ? re.flags : `${re.flags}g`);
  const lines = content.split("\n");
  let m;
  let seen = 0;
  while ((m = global.exec(content)) !== null) {
    if (m[0].length === 0) global.lastIndex += 1;
    const at = lineOfIndex(content, m.index) - 1;
    let text = lines[at] ?? "";
    if (scope === "statement") {
      // Walk back to the start of the enclosing top-level statement, which
      // in the languages this is used for begins unindented. A callback
      // body is indented under the call that installs it, so the call comes
      // with it and the guard can see what the code is attached to.
      let start = at;
      while (start > 0 && /^\s/.test(lines[start] ?? "")) start -= 1;
      text = lines.slice(start, at + 1).join("\n");
    }
    if (!contextRe.test(text)) return false;
    seen += 1;
    // Running out of budget is not evidence that every match sat in context.
    // Falling out of the loop returned "all of them did", so padding a file
    // with decoys ahead of the real line downgraded the finding.
    if (seen > MAX_CONTEXT_MATCHES) return false;
  }
  return seen > 0;
}

/**
 * Comment markers that begin a line, by the language the path implies.
 *
 * Only line-leading markers, on purpose. Deciding whether a "//" in the
 * middle of a line opens a comment or sits inside a string or a URL needs a
 * lexer per language, and a wrong answer there blinds a rule to real code.
 * A line whose first non-space characters are a comment marker is prose in
 * every one of these languages, with no such ambiguity to get wrong.
 */
const C_LIKE = /\.(js|mjs|cjs|jsx|ts|tsx|mts|cts|go|java|c|h|cc|cpp|cxx|hpp|cs|rs|swift|kt|kts|scala|php|dart|groovy|proto|sol)$/i;
const HASH_LIKE = /\.(sh|bash|zsh|ksh|py|rb|pl|pm|yml|yaml|toml|ini|cfg|conf|tf|tfvars|gradle|nix|ps1|psm1|psd1|dockerfile|mk)$/i;
const HASH_LIKE_NAME = /^(Dockerfile|Makefile|GNUmakefile|Gemfile|Rakefile|Vagrantfile|Procfile|\.env[\w.-]*|\.gitignore|\.dockerignore)$/i;
const BATCH = /\.(bat|cmd)$/i;
const DASH_LIKE = /\.(sql|lua|hs|elm|adb|ads)$/i;
const MARKUP = /\.(html|htm|xml|xhtml|svg|vue|svelte|md|markdown)$/i;

/**
 * How many characters of comment marker this line opens with, or 0.
 *
 * The C-family star case wants care: a block-comment continuation line
 * starts with a star and a space, while a C pointer store starts with a star
 * and a name, so the star alone is not enough to decide.
 */
function commentMarkerLength(trimmed, kind) {
  if (kind === "c") {
    // Rust and C# write documentation as "///" and Rust inner docs as "//!",
    // which are prose by definition. Without these the space test below sees
    // "/" and "!" after the marker and reads the line as code: ripgrep's
    // "/// will have setup qemu to run it" earned a sandbox-evasion finding.
    if (trimmed.startsWith("///") || trimmed.startsWith("//!")) return 3;
    if (trimmed.startsWith("//") || trimmed.startsWith("/*") || trimmed.startsWith("*/")) return 2;
    return trimmed.startsWith("*") ? 1 : 0;
  }
  if (kind === "hash") return trimmed.startsWith("#") ? 1 : 0;
  if (kind === "batch") {
    const m = /^(@?rem|::)/i.exec(trimmed);
    return m ? m[0].length : 0;
  }
  if (kind === "dash") return trimmed.startsWith("--") ? 2 : 0;
  if (kind === "markup") {
    if (trimmed.startsWith("<!--")) return 4;
    return trimmed.startsWith("-->") ? 3 : 0;
  }
  // Unknown extension, which in this corpus is usually a shell script with no
  // suffix. "#" and "//" are the two markers that never begin a statement in
  // anything that would land here.
  if (trimmed.startsWith("//")) return 2;
  return trimmed.startsWith("#") ? 1 : 0;
}

/**
 * Is this line a comment a human wrote to be read, rather than one a tool
 * reads to be obeyed?
 *
 * The marker must be followed by whitespace or nothing. That one character
 * is the whole difference between prose and a directive, and the difference
 * matters because some directives execute: Go runs "//go:generate sh -c
 * ..." when someone types go generate, and treating that line as prose lost
 * a real high-severity download-and-execute on a benchmark sample that
 * exists to carry it. A shebang is the same shape ("#!" and not "# "), and
 * so are "//# sourceMappingURL", "# syntax=docker/dockerfile:1" and
 * "//go:build". Prose has the space; a directive does not.
 */
function isProseComment(trimmed, kind) {
  const n = commentMarkerLength(trimmed, kind);
  if (n === 0) return false;
  const rest = trimmed.slice(n);
  return rest.length === 0 || /^\s/.test(rest);
}

function commentKind(path) {
  const base = String(path).split("/").pop() ?? "";
  if (C_LIKE.test(base)) return "c";
  if (BATCH.test(base)) return "batch";
  if (DASH_LIKE.test(base)) return "dash";
  if (MARKUP.test(base)) return "markup";
  if (HASH_LIKE.test(base) || HASH_LIKE_NAME.test(base)) return "hash";
  return "unknown";
}

/**
 * Blank out the lines that are nothing but a comment, keeping every byte
 * offset and line number exactly where it was.
 *
 * A rule that says "this code reads your AWS credentials" must not fire on a
 * sentence saying so. VictoriaMetrics was called malware for the doc comment
 * over its AWS credential loader ("reads credentials from ~/.aws/credentials
 * for the given profile"), which was the only place in the file where that
 * path appeared literally at all -- the code builds it with filepath.Join.
 * AutoGPT was called malware for a REM comment explaining why its installer
 * uses curl rather than Invoke-WebRequest. Neither line executes.
 *
 * Blanking rather than deleting is what makes this safe to drop in: callers
 * index into the result with matchLocation and slice windows around a match,
 * and every one of those offsets still points at the same place in the
 * original. A comment-only line is the whole of the loss, so a marker part
 * way along a line of real code hides nothing: that line is left intact.
 */
export function withoutCommentLines(content, path) {
  const kind = commentKind(path);
  const lines = String(content).split("\n");
  let touched = false;
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    const trimmed = line.trimStart();
    if (trimmed.length > 0 && isProseComment(trimmed, kind)) {
      lines[i] = " ".repeat(line.length);
      touched = true;
    }
  }
  return touched ? lines.join("\n") : content;
}

/**
 * Blank out lines inside a fenced markdown code block, offsets intact.
 *
 * A command inside a fence is being shown, not run. sst's CLI carries its own
 * install instructions as an array of markdown lines, and the one reading
 * "curl -fsSL https://sst.dev/install | bash" sits between a line holding
 * "```bash" and a line holding "```", which made the tool that prints the
 * instructions look like the dropper they warn about.
 *
 * The fence marker is recognised with surrounding quotes, commas and
 * backslashes stripped, because in a source file these lines are string
 * literals in a list rather than markdown proper.
 *
 * Callers must not use this on a file a shell executes. A line of backticks
 * in a shell script is a command that fails, not a fence, so honouring one
 * there would let an attacker wrap a real payload in two inert lines and
 * disappear. The download rule applies it only to files nothing runs
 * line-by-line.
 */
export function withoutFencedBlocks(content) {
  const lines = String(content).split("\n");
  let inFence = false;
  let touched = false;
  for (let i = 0; i < lines.length; i++) {
    // Strip the string-literal wrapping a source file puts around the line.
    // Two index walks rather than `["',\s]+$`: anchored at the end, that
    // class re-tried from every position of a long run of spaces, and a
    // line of `import` and ten thousand spaces cost this function four
    // hundred milliseconds it spent nowhere else.
    const line = lines[i];
    let a = 0;
    let b = line.length;
    const wrap = (c) => c === '"' || c === "'" || c === "," || c === " " || c === "\t" || c === "\r";
    while (a < b && wrap(line[a]) && line[a] !== ",") a++;
    while (b > a && wrap(line[b - 1])) b--;
    // A fence line is short; anything longer than a marker and a language
    // tag cannot be one, and skipping the test keeps the walk above the
    // only cost on a long line.
    const isFence = b - a <= 40 && /^(`{3,}|~{3,})[A-Za-z0-9_+-]*$/.test(line.slice(a, b));
    if (isFence) inFence = !inFence;
    if (isFence || (inFence && lines[i].length > 0)) {
      lines[i] = " ".repeat(lines[i].length);
      touched = true;
    }
  }
  return touched ? lines.join("\n") : content;
}

/**
 * Blank out lines that only declare an import, offsets intact.
 *
 * An import states that a file may use something; it is not the use. Two
 * import lines sit next to each other by construction, so any rule grading on
 * how close a download primitive is to an execution primitive reads an import
 * block as the tightest possible adjacency. esbuild, puppeteer and node-gyp
 * each earned a caution for exactly that: an import of spawn from the
 * process module on one line and a fetch or urllib import on the next.
 *
 * Nothing is lost by blanking them, because the tokens the rules look for
 * appear again at the point of use: a file that imports the process module
 * and later calls execSync still matches on execSync, and one that imports urllib
 * still matches where it calls urllib.request.urlopen. Only the declaration
 * disappears.
 *
 * A line is a declaration only if it ends after the module specifier, so
 * a require of the process module followed by .execSync(out) is left
 * alone: that one is a use.
 */
// Every run is bounded and none of them overlaps the next: `import` followed
// by two thousand spaces and a stray character took seconds under the
// previous shape, because `[\w.,\s*]+` and the closing `\s*$` re-divided the
// same spaces at every position. A declaration fits in three hundred
// characters.
const IMPORT_LINE =
  /^[ \t]*(?:import[ \t][^;\n]{0,300}?from[ \t]*["'][^"'\n]{1,300}["'][ \t]*;?|import[ \t]*["'][^"'\n]{1,300}["'][ \t]*;?|import[ \t]+[\w$]+[ \t]*=[ \t]*require[ \t]*\([ \t]*["'][^"'\n]{1,300}["'][ \t]*\)[ \t]*;?|(?:const|let|var)[ \t]+[\w${},:* \t]{1,300}?=[ \t]*require[ \t]*\([ \t]*["'][^"'\n]{1,300}["'][ \t]*\)[ \t]*;?|import[ \t]+[\w.*]+(?:[ \t]*,[ \t]*[\w.*]+)*(?:[ \t]+as[ \t]+\w+)?|from[ \t]+[\w.]+[ \t]+import[ \t]+[\w.*(),]+(?:[ \t]+[\w.*(),]+)*|use[ \t]+[\w:{},*]+(?:[ \t]+[\w:{},*]+)*;)[ \t]*$/;

export function withoutImportLines(content) {
  const lines = String(content).split("\n");
  let touched = false;
  for (let i = 0; i < lines.length; i++) {
    if (lines[i].length > 0 && IMPORT_LINE.test(lines[i])) {
      lines[i] = " ".repeat(lines[i].length);
      touched = true;
    }
  }
  return touched ? lines.join("\n") : content;
}
