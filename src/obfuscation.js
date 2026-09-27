/**
 * Obfuscation, measured rather than guessed.
 *
 * These rules quantify how unreadable a file is: entropy of string literals,
 * density of encoded blobs, invisible characters, mixed-script identifiers,
 * and enormous single-line files. Vendored and minified library bundles
 * legitimately look like this, so the caller downgrades these findings
 * inside vendored artifacts; in hand-authored code they stay loud.
 */

import { lineOfIndex, looksLikeEncodedAsset, looksLikeEncodedWordList, looksLikeWasm, matchLocation, redactSnippet, withoutCommentLines } from "./textutil.js";

/** Shannon entropy of a string in bits per character. */
/** Is the line holding this offset a comment and nothing else? */
function commentOnlyLine(content, index) {
  const start = content.lastIndexOf("\n", index - 1) + 1;
  const endAt = content.indexOf("\n", index);
  const line = content.slice(start, endAt === -1 ? content.length : endAt);
  if (/^\s*(\/\/|#(?!!)|--\s)/.test(line)) return true;
  return /^\s*\*/.test(line) && !line.includes("*/");
}

export function shannonEntropy(s) {
  if (!s) return 0;
  const counts = new Map();
  for (const ch of s) counts.set(ch, (counts.get(ch) ?? 0) + 1);
  let entropy = 0;
  for (const n of counts.values()) {
    const p = n / s.length;
    entropy -= p * Math.log2(p);
  }
  return entropy;
}

/**
 * Extract quoted string literals (single, double, backtick) of 40 to 4,000
 * characters, on one line, with backslash escapes honoured.
 *
 * A hand-written scanner rather than a regex. The regex form spent 98% of a
 * scan inside itself on a megabyte of `"\` pairs: every quote opened an
 * attempt, every attempt consumed the rest of the line through the escape
 * branch and failed at the end, and a file of half a million quotes did that
 * half a million times. Here a quote that never closes on its line is
 * remembered, and no later quote of the same kind on that line starts the
 * same doomed walk, so the cost is one pass per line.
 */
function stringLiterals(content) {
  const literals = [];
  const n = content.length;
  const failedUntil = { '"': -1, "'": -1, "`": -1 };
  let i = 0;
  while (i < n) {
    const q = content[i];
    if (q === "\n") {
      failedUntil['"'] = failedUntil["'"] = failedUntil["`"] = -1;
      i += 1;
      continue;
    }
    if ((q !== '"' && q !== "'" && q !== "`") || i < failedUntil[q]) {
      i += 1;
      continue;
    }
    let j = i + 1;
    let closed = false;
    while (j < n) {
      const c = content[j];
      if (c === "\\") {
        if (content[j + 1] === "\n") break;
        j += 2;
        continue;
      }
      if (c === "\n") break;
      if (c === q) {
        closed = true;
        break;
      }
      j += 1;
    }
    if (!closed) {
      failedUntil[q] = j;
      i += 1;
      continue;
    }
    const len = j - i - 1;
    if (len >= 40 && len <= 4000) literals.push({ value: content.slice(i + 1, j), index: i });
    // Past the closing quote either way. The regex retried from inside a
    // short literal and could pair its closing quote with the opening quote
    // of the next one, reading the code between them as a string.
    i = j + 1;
  }
  return literals;
}

const BASE64_CHARS = /^[A-Za-z0-9+/=\s]+$/;
const HEX_CHARS = /^[0-9a-fA-F\s]+$/;

// Zero-width and invisible characters: zero-width space, non-joiner, joiner,
// word joiner, soft hyphen, and the BOM. Position is judged by the caller.
const INVISIBLE_RE = /[\u200B\u200C\u200D\u2060\u00AD\uFEFF]/;

// A Latin letter directly touching a Cyrillic or Greek letter inside one
// token. Whole words in another script (comments, docs) never match;
// a spoofed identifier or domain with a Cyrillic lookalike letter does.
const MIXED_SCRIPT_RE = /[A-Za-z][\u0370-\u03FF\u0400-\u04FF]|[\u0370-\u03FF\u0400-\u04FF][A-Za-z]/;

// Bounded either side of the non-ASCII character rather than `*`. Two
// unbounded runs around one character re-divide the same text at every
// position, which is quadratic on a long line with no whitespace in it: a
// megabyte of "http://a?" took 228 seconds, and every code file reaches this.
// A homoglyph hostname and the address around it fit in a few hundred
// characters; past that the match would be on a different URL anyway.
const URL_WITH_NON_ASCII_RE = /https?:\/\/[^\s"'`<>]{0,200}[\u0080-\uFFFF][^\s"'`<>]{0,200}/;

/**
 * The first mixed-script token that is not sitting inside a string literal
 * of prose. A product description in Uzbek with one Cyrillic letter typed
 * into a Latin word is text somebody wrote, not an identifier somebody
 * spoofed; husanswe/texmart-laravel-ecommerce carried one in a seeder and
 * it counted towards a caution. A literal counts as prose when it holds a
 * space: an identifier or a hostname never does. Returns the index, or null.
 */
function mixedScriptOutsideProse(content) {
  const re = new RegExp(MIXED_SCRIPT_RE.source, "g");
  let prose = null;
  let m;
  while ((m = re.exec(content)) !== null) {
    if (prose === null) {
      prose = stringLiterals(content)
        .filter((l) => l.value.includes(" "))
        .map((l) => [l.index, l.index + l.value.length + 2]);
    }
    const at = m.index;
    if (prose.some(([a, b]) => at >= a && at < b)) continue;
    // A multi-line literal (a PHP string or a heredoc across lines) has no
    // single-line literal to find, so the line itself is read: six words
    // and none of the punctuation an assignment, a call or a block carries
    // is a sentence, whatever quotes it sits between.
    const lineStart = content.lastIndexOf("\n", at) + 1;
    const lineEnd = content.indexOf("\n", at);
    const line = content.slice(lineStart, lineEnd === -1 ? content.length : lineEnd);
    if (line.trim().split(/\s+/).length >= 6 && !/[=(){};[\]<>]/.test(line)) continue;
    return at;
  }
  return null;
}

const ASCII_WORD = /[A-Za-z0-9_$]/;
const isAsciiWord = (c) => c !== undefined && c !== "" && ASCII_WORD.test(c);
const ASCII_LETTER = /[A-Za-z]/;
const isAsciiLetter = (c) => c !== undefined && c !== "" && ASCII_LETTER.test(c);
const isNonAscii = (c) => c !== undefined && c !== "" && c.charCodeAt(0) > 0x7f;

// Bidirectional override and isolate controls. These reorder how text is
// DISPLAYED without changing what runs, so reviewed source and executed
// source differ (the Trojan Source attack, CVE-2021-42574). They have no
// legitimate use in program source; a right-to-left language uses letters,
// not overrides, to render correctly.
const BIDI_OVERRIDE_RE = /[\u202A-\u202E\u2066-\u2069]/;

// Unicode Private Use Area. These code points render as nothing or as a
// missing-glyph box in every editor, and mean nothing to any language, so a
// run of them in source is a steganographic payload, not text. Seen in 2025
// npm attacks hiding executable code in "blank" space. A stray one can be a
// custom-font icon, so this fires on a RUN, not a single character.
const PUA_RUN_RE = /[\uE000-\uF8FF]{4,}/;

/**
 * First index of an invisible character used to hide something, or -1.
 *
 * A zero-width character only hides anything inside an ASCII identifier,
 * where it splits one name into two that look identical (isAdmin and
 * isAdmin<ZWSP>). Elsewhere the same code points are ordinary typography:
 * ZWJ joins emoji, and ZWNJ is required by Arabic, Persian and Devanagari.
 * The character must therefore touch an ASCII word character on at least one
 * side and non-ASCII text on neither. A leading byte-order mark is a normal
 * encoding artifact and is skipped.
 */
export function findInvisibleCharacter(content, code = content) {
  const start = content.charCodeAt(0) === 0xfeff ? 1 : 0;
  // Invisible characters before each index, built on the first candidate.
  // Counting a 61-character window with a fresh regex per candidate made a
  // megabyte of zero-width spaces cost seconds.
  let prefix = null;
  const invisibleIn = (from, to) => {
    if (!prefix) {
      prefix = new Uint32Array(content.length + 1);
      for (let k = 0; k < content.length; k++) prefix[k + 1] = prefix[k] + (INVISIBLE_RE.test(content[k]) ? 1 : 0);
    }
    return prefix[Math.min(to, content.length)] - prefix[Math.max(0, from)];
  };
  for (let i = start; i < content.length; i++) {
    if (!INVISIBLE_RE.test(content[i])) continue;
    // Nothing on a comment-only line runs, so a zero-width character there
    // splits no identifier. assertj carries one inside a Javadoc sample
    // ("completedFuture<ZWSP>(1)") to stop the doc renderer gluing tokens
    // together, and slate carries a word joiner in a "// This issue occurs
    // when the ..." line; both read as hidden code. A run of three or more
    // is already skipped above as display padding, so this loses no
    // steganography the rule was catching.
    if (code[i] !== content[i]) continue;
    // Several zero-width characters close together are padding in a display
    // string (Discord bots space menu entries with them), not one hidden
    // split in an identifier.
    if (invisibleIn(i - 30, i + 31) >= 3) continue;
    const before = content[i - 1];
    const after = content[i + 1];
    if (isNonAscii(before) || isNonAscii(after)) continue;
    // Khmer, Thai, Lao and Myanmar use the zero-width space as a word
    // separator, often right after a placeholder like %1, so non-ASCII text
    // anywhere nearby marks typography too.
    if (/[^\x00-\x7F]/.test(content.slice(Math.max(0, i - 8), i + 9).replace(content[i], ""))) continue;
    // A soft hyphen is a hyphenation point: its whole job is to sit at the end
    // of a word fragment and stay invisible until a line has to break there.
    // So it follows an ASCII letter, and what comes next is the rest of the
    // word or, at an actual soft wrap, the newline itself. It cannot hide an
    // identifier split, because no language accepts it in an identifier, so in
    // code it lives only in comments and strings where it is typography.
    // linebender/parley wrote "not in\u00AD\nteresting" across a wrap, the
    // soft hyphen sitting right before the newline, and turned red for it.
    if (content[i] === "\u00AD" && isAsciiLetter(before)) continue;
    // ZWNJ and ZWJ are typography (Persian, Arabic, emoji sequences) and
    // turn up next to punctuation in ordinary UI strings; they only hide
    // something when they sit inside an ASCII word. The zero-width space,
    // word joiner, soft hyphen and mid-file BOM have no such use.
    // Against a string delimiter the character is at the edge of a literal,
    // where it is data rather than a name being split in two: there is no
    // second identifier for it to be confused with. langflow's
    // rehypeWbrUnderscore replaces "_" with "_<ZWSP>" so long snake_case
    // names can wrap in the docs, and the whole string is those two
    // characters. The trade is that a zero-width character at the very edge
    // of a literal is no longer reported; one anywhere inside it, which is
    // what a lookalike name needs, still is.
    const quote = (c) => c === '"' || c === "'" || c === "`";
    if (quote(before) || quote(after)) continue;
    // At the very start of a line the character is where two files were
    // joined: KlaraStellaa's editor carries a byte-order mark before a
    // function declaration. Right before a full stop or comma it ends a
    // sentence in prose: a zero-width space after "strategy" in JSX text
    // (elshadayz21/dx-product-list). Neither splits a name in two.
    if (before === "\n" || before === undefined) continue;
    if (isAsciiLetter(before) && /[.,!?]/.test(after ?? "") && /[\s<]/.test(content[i + 2] ?? " ")) continue;
    const joiner = content[i] === "\u200C" || content[i] === "\u200D";
    if (joiner ? isAsciiWord(before) && isAsciiWord(after) : isAsciiWord(before) || isAsciiWord(after)) return i;
  }
  return -1;
}

/** Does this encoded run say what it is, and is that something inert? */
function looksLikeNamedData(run) {
  if (new Set(run).size < 12) return true;
  if (looksLikeEncodedAsset(run) || looksLikeWasm(run) || looksLikeEncodedWordList(run)) return true;
  let head = "";
  try {
    head = Buffer.from(run.slice(0, 16), "base64").toString("latin1");
  } catch {
    return false;
  }
  return /^(\{"|\[\{"|-----BEGIN )/.test(head);
}

/**
 * Obfuscation findings for one code file. Severities here assume
 * hand-authored code; the caller downgrades inside vendored artifacts.
 */
export function checkObfuscation(path, content, { bytes, lines }) {
  const findings = [];

  const invisibleIndex = findInvisibleCharacter(content, withoutCommentLines(content, path));
  if (invisibleIndex !== -1) {
    findings.push({
      id: "invisible-characters",
      severity: "high",
      file: path,
      line: lineOfIndex(content, invisibleIndex),
      snippet: redactSnippet(content.slice(Math.max(0, invisibleIndex - 40), invisibleIndex + 60)),
      why: "This file contains invisible characters (zero-width spaces or joiners) inside its source. You cannot see them, but the computer executes them. Their only use in code is to hide something from a human reader.",
      next: "Do not run this repository. Open the file in a hex viewer if you want to see what is hidden.",
    });
  }

  // Unicode tag characters (U+E0000..U+E007F) mirror ASCII into a block that
  // renders as nothing at all, so they carry text past a human reader
  // entirely. Their one honest use is a subdivision flag emoji, where the
  // sequence follows U+1F3F4, and those are skipped.
  const tagRun = /(?<!\u{1F3F4}[\u{E0020}-\u{E007F}]{0,8})[\u{E0020}-\u{E007E}]{4,}/u;
  const tagMatch = content.match(tagRun);
  if (tagMatch) {
    const decoded = [...tagMatch[0]].map((c) => String.fromCodePoint(c.codePointAt(0) - 0xe0000)).join("");
    findings.push({
      id: "unicode-tag-smuggling",
      severity: "high",
      file: path,
      line: lineOfIndex(content, tagMatch.index),
      snippet: redactSnippet(`${tagMatch[0].length} tag characters, which read as: ${decoded.slice(0, 80)}`),
      why: "This file carries text written in Unicode tag characters, a block that renders as nothing at all. Anyone reviewing the file sees blank space where a machine reads a full sentence. Outside a subdivision flag emoji there is no honest use for it, and it is a standard way to smuggle instructions past a human into an AI coding agent.",
      next: "Do not run this repository or open it with a coding agent. The hidden text is shown above, decoded.",
    });
  }

  // Bidirectional override controls (Trojan Source): the code you read and the
  // code that runs are different.
  // A run of several different control characters together is a list of
  // them (a terminal emulator's sanitizer regex, a Unicode table), not a
  // trojan, which uses one override and one pop.
  const CONTROL_LIST = /[\u200B-\u200F\u202A-\u202E\u2060-\u2069\uFEFF]/g;
  // A control character alone inside its own quotes is an entry in a table,
  // not an attack: one such character on its own reorders nothing. That is
  // what a denylist looks like when it is written out one line at a time,
  // which the window test above cannot see, because a comment naming each
  // character pushes the next one well past twelve columns.
  // Cranot/roam-code lists all nine with a comment on each and turned red.
  const quotedAlone = (i) => {
    const before = content[i - 1];
    const after = content[i + 1];
    return (before === '"' || before === "'" || before === "`") && after === before;
  };
  // Scripts written right-to-left. These controls exist to lay this text out
  // beside left-to-right text, and a translation file is where that happens.
  // Bitcoin's Arabic locale wraps a string in RLE and PDF so the "%1"
  // placeholder sits correctly inside the Arabic sentence, and the tool
  // called Bitcoin Core malware for shipping a translation. Trojan Source
  // needs the surrounding code to be ASCII, so a control doing its declared
  // job next to real RTL script is not that attack. The same reasoning, and
  // the same trade, as the non-ASCII window in findInvisibleCharacter above.
  const RTL_SCRIPT =
    /[\u0590-\u05FF\u0600-\u06FF\u0700-\u074F\u0750-\u077F\u0780-\u07BF\u07C0-\u08FF\uFB1D-\uFDFF\uFE70-\uFEFF]/;
  let bidiIndex = -1;
  let commentBidi = -1;
  for (const m of content.matchAll(new RegExp(BIDI_OVERRIDE_RE.source, "g"))) {
    const window = content.slice(Math.max(0, m.index - 12), m.index + 12);
    if (new Set(window.match(CONTROL_LIST) ?? []).size >= 3) continue;
    if (quotedAlone(m.index)) continue;
    if (RTL_SCRIPT.test(content.slice(Math.max(0, m.index - 24), m.index + 25))) continue;
    // A line that is nothing but a comment holds no code for a control to
    // reorder: bidi reordering stays within its line. z0r0z/tacit and
    // vaipakam both show "Trust\u202ekellaW" in the comment above the code
    // that strips it. The Trojan Source comment attack puts the control in
    // a comment that shares its line with code, which this does not skip.
    if (commentOnlyLine(content, m.index)) {
      if (commentBidi === -1) commentBidi = m.index;
      continue;
    }
    bidiIndex = m.index;
    break;
  }
  if (bidiIndex !== -1) {
    findings.push({
      id: "bidi-override",
      severity: "high",
      file: path,
      line: lineOfIndex(content, bidiIndex),
      snippet: redactSnippet(content.slice(Math.max(0, bidiIndex - 40), bidiIndex + 60)),
      why: "This file contains bidirectional text-override characters, which reorder how the code appears without changing what runs. A reviewer reads one thing and the computer executes another. This is the Trojan Source attack, and there is no legitimate reason for these controls in source code.",
      next: "Do not run this repository. The visible source is not what will execute.",
    });
  }

  if (bidiIndex === -1 && commentBidi !== -1) {
    findings.push({
      id: "bidi-override",
      severity: "low",
      file: path,
      line: lineOfIndex(content, commentBidi),
      snippet: redactSnippet(content.slice(Math.max(0, commentBidi - 40), commentBidi + 60)),
      why: "This file has a bidirectional text-override character on a line that is only a comment, where it can change how the comment reads but not how any code runs. Code that defends against Trojan Source often shows the attack this way.",
      next: "Nothing to do unless the same character appears on a line with code.",
    });
  }

  // Private Use Area steganography: a run of code points that render as blank.
  const puaMatch = content.match(PUA_RUN_RE);
  if (puaMatch) {
    findings.push({
      id: "private-use-steganography",
      severity: "high",
      file: path,
      line: lineOfIndex(content, puaMatch.index),
      snippet: `${puaMatch[0].length} private-use characters that render as blank space`,
      why: "This file hides a run of Unicode Private Use Area characters, which display as nothing in every editor and terminal. They mean nothing to any language; a block of them is a payload smuggled inside apparently empty space, a technique seen in 2025 npm attacks.",
      next: "Do not run this repository. Open the file in a hex viewer to see what is concealed.",
    });
  }

  // Homoglyph URL: a link whose text mixes in lookalike non-ASCII letters.
  const urlMatch = content.match(URL_WITH_NON_ASCII_RE);
  let mixedAt = null;
  if (urlMatch && MIXED_SCRIPT_RE.test(urlMatch[0])) {
    findings.push({
      id: "homoglyph-url",
      severity: "high",
      file: path,
      line: lineOfIndex(content, urlMatch.index),
      snippet: redactSnippet(urlMatch[0]),
      why: "This file contains a web address using lookalike letters from another alphabet (for example a Cyrillic 'a' inside a Latin word). It displays as a familiar site but points somewhere else entirely.",
      next: "Do not visit or trust that address, and do not run this repository.",
    });
  } else if ((mixedAt = mixedScriptOutsideProse(content)) !== null) {
    const loc = matchLocation(content.slice(mixedAt), MIXED_SCRIPT_RE);
    if (loc) loc.line += lineOfIndex(content, mixedAt) - 1;
    findings.push({
      id: "homoglyph-identifier",
      // Low: mixed-script identifiers turn up in unicode test fixtures and
      // internationalized code. The homoglyph URL case (a lookalike of a
      // real domain) stays high; a bare mixed-script name only accumulates.
      severity: "low",
      file: path,
      line: loc?.line ?? null,
      snippet: loc?.snippet ?? "",
      why: "This file mixes lookalike letters from different alphabets inside a single word. Two identifiers can then look identical while being different, a trick used to hide a malicious variable next to a harmless-looking one.",
      next: "Have someone review this file character by character before trusting it, or simply do not run it.",
    });
  }

  // High-entropy string literals that are not plain base64 or hex (those are
  // caught by their own, more specific rules). Random base64 sits near 6 bits
  // per character, so 5.0 is the line; under 120 characters the measure is
  // too noisy to act on.
  //
  // Measured on the packed run rather than on the whole literal. The comment
  // here used to say English prose sits near 4 bits per character, and that
  // is true of lowercase letters and spaces alone: a sentence with mixed
  // case, digits, punctuation and markup in it spreads over seventy-odd
  // distinct characters and lands at 5.0 to 5.1. Three of the standing
  // benign set earned this finding on ordinary English -- prisma's roadmap
  // page, a Prisma error message built from a template literal, and the
  // comment in borg's paperkey page that says where the QR code goes.
  //
  // Packed data is one unbroken run; prose has a space every few characters
  // and cannot make a 120-character run without one. So the run is what the
  // rule reads, and a sentence no longer supplies the length that the
  // entropy measure needs. This is not a hiding place: whitespace-separated
  // chunks short enough to pass are short enough that base64-blob and
  // encoded-blob-density read them as what they are.
  for (const lit of stringLiterals(content)) {
    if (lit.value.length < 120) continue;
    let packed = "";
    for (const run of lit.value.split(/\s+/)) if (run.length > packed.length) packed = run;
    if (packed.length < 120) continue;
    if (BASE64_CHARS.test(packed) || HEX_CHARS.test(packed)) continue;
    const entropy = shannonEntropy(packed);
    if (entropy >= 5.0) {
      findings.push({
        id: "high-entropy-literal",
        // Low: a long random-looking string alone (a hash, a test vector, a
        // source map, embedded binary data) is common in honest code. It
        // accumulates toward a caution rather than raising one by itself.
        severity: "low",
        file: path,
        line: lineOfIndex(content, lit.index),
        snippet: redactSnippet(packed, 120),
        why: `This file embeds a long, random-looking string (measured entropy ${entropy.toFixed(1)} bits per character). Strings like this are usually encrypted or packed data waiting to be decoded and run.`,
        next: "Ask what this data is for. If nobody can say, treat the repository as unsafe to run.",
      });
      break; // one finding per file is enough
    }
  }

  // Density of encoded blobs: how much of the file is base64 or hex runs.
  // Data that names itself is left out: a data URI that is not a script, a
  // base64 run that decodes to a media file, a font, a WebAssembly module,
  // a word list, JSON or a PEM block, 0x-prefixed contract bytecode, and a
  // run of a handful of repeated characters. Icon components, inlined fonts,
  // tokenizer vocabularies, test fixtures and ABI files are made of these; a
  // payload is not. String literals joined with + are read as one.
  const namedData = content
    .replace(/(["'`])\s*\+\s*\1/g, "")
    .replace(/data:(?!(?:text|application)\/(?:javascript|ecmascript|x-sh|x-python))[\w.+-]+\/[\w.+-]+(?:;[\w=.-]+)*,[A-Za-z0-9+/=%]+|\b0x[0-9a-fA-F]{100,}/g, "");
  const blobRuns = (namedData.match(/[A-Za-z0-9+/=]{100,}|(?:[0-9a-fA-F]{2}){50,}/g) ?? []).filter(
    (run) => !looksLikeNamedData(run),
  );
  const blobBytes = blobRuns.reduce((n, r) => n + r.length, 0);
  if (bytes > 4000 && blobBytes / bytes > 0.4) {
    findings.push({
      id: "encoded-blob-density",
      severity: "medium",
      file: path,
      line: null,
      snippet: `${Math.round((blobBytes / bytes) * 100)}% of the file is base64 or hex data`,
      why: "Most of this file is encoded data rather than readable code. Legitimate code sometimes embeds an icon or font this way; malware uses the same trick to carry a hidden payload.",
      next: "Check whether anything in the repository decodes this data and runs it. If unsure, do not install.",
    });
  }

  // A huge file on almost no lines that claims to be source, not a bundle.
  // Low: generated validators, checked-in minified assets, an emoji regex and
  // an Emscripten loader all look like this, and a payload hidden in such a
  // blob still trips the decode, eval or theft rules, which is where the
  // caution belongs. It still counts toward three weak signals.
  if (bytes > 8_000 && bytes / Math.max(lines, 1) > 2_000) {
    findings.push({
      id: "single-line-blob",
      severity: "low",
      file: path,
      line: 1,
      snippet: `${bytes.toLocaleString("en-US")} bytes across only ${lines} line${lines === 1 ? "" : "s"}`,
      why: "This file packs a huge amount of code into almost no lines. Machine-generated bundles look like this; a file presented as hand-written source should not. Deliberately unreadable code is where payloads hide.",
      next: "Ask why this file is not readable source. Do not run the repository until someone explains it.",
    });
  }

  return findings;
}
