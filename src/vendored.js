/**
 * Telling the code a person wrote from the code a tool generated or copied in.
 *
 * The same raw patterns (eval, minification, packed data) sit in malware and
 * in every bundled library. Malware hides where a human is meant to write or
 * run code, so the low-specificity checks step down inside vendored,
 * generated and test artifacts, while theft signatures stay high everywhere.
 */

import { ENCODED_CONTENT_SIGNALS } from "./verdict.js";
import { HIGH_SIGNATURES, MED_SIGNATURES } from "./signatures.js";

/**
 * A camelCase test file: httpServerTests.ts, ParserSpec.js. Case-sensitive,
 * and therefore separate from TEST_PATH, which is case-insensitive so that
 * Test/ and TESTS/ are directories like any other. Folding case here made
 * "protest.js" a test file, which an existing test says it is not.
 */
export const TEST_PATH_CAMEL = /[a-z](Tests?|Specs?)\.[a-z]+$/;

/**
 * Paths whose contents do not run when someone installs or opens a project.
 * A test suite legitimately contains what this tool looks for: parsers test
 * eval, http clients test proxy environment variables, bundlers test their
 * own output. Findings here are downgraded, never dropped, so a payload
 * placed in a test directory is still reported; it just cannot be the sole
 * evidence of danger. Exempting the path outright would be a hiding place.
 */
export const TEST_PATH =
  /(^|\/)(_?tests?|__tests__|__mocks__|__fixtures__|fixtures?|spec|specs|e2e|testdata|benchmarks?|examples?)\/|(^|\/)(?:[\w.-]*[-_.])?tests?(?:-?suite|ing)?\/|[-_.](test|tests|spec)\.[a-z]+$|(^|\/)(tests?|specs?)\.[a-z]+$|(^|\/)test_[^/]*\.py$|_test\.go$|(^|\/)test[-_][^/]*\.(sh|bash|zsh|bats)$|\.bats$/i;

/**
 * Checks whose findings are low-specificity: normal in libraries, damning
 * only in authored code. Imported rather than restated: verdict.js collapses
 * these four into one signal when scoring, and the two lists have to agree
 * for that to mean anything.
 */
export const BLOB_SIGNALS = ENCODED_CONTENT_SIGNALS;

/**
 * The line here is what a signal is about, not how strong it is.
 *
 * These describe the SHAPE of a file: how it was encoded, packed and padded.
 * A minifier really does emit hex escapes, giant string literals and
 * zero-width padding inside display strings, so in something that is actually
 * a bundle they say nothing at all and relax to informational.
 *
 * Everything else in LOW_SPECIFICITY describes what the code DOES: read a
 * wallet, run a fetched response, dump the environment. A library doing that
 * is still doing it, so those step down one level at most and never reach
 * informational. Being a bundle is not a defence against behaviour.
 */
const VENDOR_NOISE = new Set([
  "hex-obfuscation",
  "dynamic-code-execution",
  "base64-blob",
  "single-line-blob",
  "encoded-blob-density",
  "high-entropy-literal",
  // Character-level padding and direction marks: i18n and minifier output
  // carry these routinely, which is the whole reason the downgrade exists.
  "invisible-characters",
  "private-use-steganography",
  "bidi-override",
  // A mime-type table in a bundled webpack lists application/x-virtualbox-ova
  // and every other format anyone registered, which is not a virtual machine
  // being detected. next.js carries one under packages/next/src/compiled.
  "sandbox-evasion",
  // A bundled package manager downloads and writes executable files for a
  // living. Yarn's own release bundle in .yarn/releases earned a caution in
  // prettier and jest for exactly that. Co-occurrence of a fetch and a write
  // says nothing inside a megabyte of minified library code; a high finding
  // here is still stepped down to a caution rather than to nothing, by
  // LOW_SPECIFICITY below.
  "download-and-execute",
]);

const LOW_SPECIFICITY = new Set([
  "hex-obfuscation",
  "invisible-characters",
  "private-use-steganography",
  "bidi-override",
  "dynamic-code-execution",
  "download-and-execute",
  "base64-blob",
  "single-line-blob",
  "encoded-blob-density",
  "high-entropy-literal",
  "wallet-extension-id",
  ...[...HIGH_SIGNATURES, ...MED_SIGNATURES].filter((s) => s.downgradeInVendored).map((s) => s.id),
]);

/**
 * Is this file a vendored or minified library artifact rather than code the
 * author hand-wrote? Such files legitimately contain eval, obfuscation, and
 * huge minified blobs, so those checks are downgraded there.
 */
/**
 * Whether a file is shaped like something a tool emitted rather than
 * something a person typed. Used to corroborate a licence banner, which is
 * otherwise trivial to forge.
 *
 * Bundles are either enormous or packed onto very long lines, and usually
 * both: the vendored copies this rule exists for run to megabytes. Line
 * length alone cannot tell a bundle from a payload (the single-line-blob
 * fixture is one 14 KB line and is malicious), which is why this only ever
 * corroborates a banner and never establishes anything by itself.
 */
const GENERATED_MIN_BYTES = 50_000;
const GENERATED_MIN_LINE = 500;

function looksGenerated(content) {
  if (content.length >= GENERATED_MIN_BYTES) return true;
  let longest = 0;
  let start = 0;
  for (;;) {
    const nl = content.indexOf("\n", start);
    const end = nl === -1 ? content.length : nl;
    if (end - start > longest) longest = end - start;
    if (longest >= GENERATED_MIN_LINE) return true;
    if (nl === -1) return false;
    start = nl + 1;
  }
}

/**
 * An HTML page a documentation generator produced, rather than a page someone
 * wrote. Pandoc, Sphinx, Doxygen, Hugo and the rest all stamp what they
 * emitted into a meta tag or a body class, and a project's built manual is
 * the one HTML file that is full of the commands the project runs.
 *
 * The stamp alone proves nothing, so it counts only where the file is also
 * shaped like machine output, exactly as a licence banner does above. This
 * does not exempt anything: the caller uses it to step a conviction down to a
 * caution.
 */
const DOC_GENERATOR =
  /<meta[^>]{0,120}name=["']generator["'][^>]{0,120}content=["'](pandoc|sphinx|docutils|doxygen|hugo|jekyll|mkdocs|asciidoctor|hexo|gitbook|docusaurus|rustdoc|javadoc|pdoc|typedoc|mdbook)/i;

/**
 * A Qt translation catalogue. Qt names these `.ts`, which collides with
 * TypeScript, so `bitcoin_fil.ts` was read as source and a Left-to-Right
 * Override inside a Filipino UI string fired the Trojan Source rule, while
 * "wallet.dat" inside a Basque translation of a warning fired the wallet
 * rule. The file is XML holding <source>/<translation> string pairs and Qt
 * compiles it to a .qm resource; nothing in it executes, and every match is
 * in human-readable interface text. The root element is <TS>, which a real
 * TypeScript file never opens with.
 */
export function isQtTranslationCatalogue(path, content) {
  if (!/\.ts$/i.test(path)) return false;
  const head = content.slice(0, 500);
  return /<!DOCTYPE\s+TS\b/i.test(head) || /^\s*(?:<\?xml[^>]*\?>\s*)?<TS[\s>]/i.test(head);
}

export function isGeneratedDocument(path, content) {
  if (!/\.html?$/i.test(path)) return false;
  // The stamp sits in the head, so a mention of the word further down in a
  // page's own body text cannot pass for one.
  return DOC_GENERATOR.test(content.slice(0, 4000)) && looksGenerated(content);
}

export function isVendoredArtifact(path, content) {
  // external-libs, externals and external sit beside vendor and third_party
  // in the same role, and CMake projects use external/ by convention.
  // helixml/helix ships Redoc at frontend/assets/external-libs/redoc/.
  // generated/ and __generated__/ are what Prisma, GraphQL codegen and
  // Relay name their output directories. MikroTik3/enkod_api was yellow for
  // a 4.9 MB base64 WebAssembly module Prisma wrote to prisma/generated/.
  if (/(^|\/)(node_modules|vendor|vendored|third_party|third-party|external|externals|external[-_]libs|dist|build|out|\.next|coverage|compiled|generated|__generated__|__snapshots__|\.yarn)\//i.test(path)) {
    return true;
  }
  // A library dropped into lib/ or libs/ that is shaped like machine output:
  // a Maven web resource tree keeps pixi.js at resources/view/lib/, half a
  // megabyte on ten lines. Hand-written code under lib/ is neither that
  // large nor that flat, and the shape test is the same one a licence
  // banner needs.
  if (/(^|\/)libs?\/[^/]+\.(js|mjs|cjs|css)$/i.test(path) && looksGenerated(content)) return true;
  // A JVM project's src/main/resources/ is served like public/, and what it
  // serves is built elsewhere: a game engine's player page and its demo
  // bundle sit there at half a megabyte on two lines. Laravel keeps
  // hand-written code under resources/js/, which is why this asks for the
  // shape of machine output as well as the path.
  if (/(^|\/)resources\/.*\.(js|mjs|cjs|css|html?)$/i.test(path) && looksGenerated(content)) return true;
  // A hyphen separates the suffix as often as a dot does (rapidoc-min.js),
  // and pi-hole/FTL turned red for a bundled API-docs viewer named that way.
  if (/[.-](min|bundle|chunk)\.(js|mjs|cjs|css)$/i.test(path)) return true;
  // A webpack or rspack chunk says so in its first bytes: it registers its
  // modules on a global chunk array. MadiroGlobalHealth/UVL-EMR ships an
  // OpenMRS frontend's numbered chunks (2544.js) under distro/binaries/.
  if (/^\s*(?:"use strict";\s*)?\(\s*(?:globalThis|self|window|this)\.webpackChunk[\w$]*\s*=/.test(content.slice(0, 300))) return true;
  // A bundler's hashed vendor chunk (vendor-BS4xPthR.js) checked into a
  // static folder.
  if (/(^|\/)vendor[-_.][\w-]*\.(js|mjs|cjs|css)$/i.test(path)) return true;
  // Any bundler output named for its content hash (main.29be736305584ec78ade
  // .js). Chainlink checks its built web assets in, and one of them carries
  // a syntax highlighter whose shell-keyword list names wget and curl.
  if (/[.-][0-9a-f]{8,}\.(js|mjs|cjs|css)$/i.test(path)) return true;
  // The same thing from a modern bundler, whose content hash is base62
  // rather than hex (assets/main-C27Rsro-.mjs). The hex rule above misses
  // every Vite and Rollup build for that reason alone, and jtydhr88/ComfyTV
  // came out red for an invisible character inside one. Anchored on the
  // assets/ directory those bundlers emit into, so it cannot catch an
  // ordinary hand-written name that happens to hold digits.
  if (/(^|\/)assets\/[^/]*[.-][A-Za-z0-9_-]{8,}\.(js|mjs|cjs|css)$/i.test(path)) return true;
  // Third-party libraries shipped under an examples tree (three.js keeps
  // emscripten decoders in examples/jsm/libs), and built site assets.
  if (/(^|\/)(examples?|samples?|demos?)\/.*(^|\/)libs?\//i.test(path)) return true;
  // Under a served-assets directory, src/ is the project's own code and lib/
  // is where third-party libraries are dropped, which is the opposite of what
  // this exception assumed. yona-projects/yona turned red for an invisible
  // character inside the Ace editor at static/javascripts/lib/ace/.
  // docs/ joins them: a documentation tree is generated and served like any
  // other, and formkit/auto-animate turned red for the minified Prism.js in
  // docs/assets/, whose shell-keyword list names curl and wget. That is the
  // same syntax highlighter already noted above for Chainlink; the rule that
  // caught it there wanted a content hash in the filename, and this copy has
  // none.
  if (/(^|\/)(public|static|_site|site|www|docs)\/.*\.(js|mjs|css)$/i.test(path) && !/(^|\/)(public|static|_site|site|www|docs)\/(.*\/)?src\//i.test(path)) return true;
  // A plotting or notebook tool exporting a self-contained page: the whole
  // library is inlined beside the data, and the data is a base64 blob of
  // packed numbers. vllm keeps a Plotly benchmark timeline at
  // docs/assets/contributing/, one file carrying the Plotly bundle and a
  // 20 KB array, and it read as a smuggled payload. The rule above already
  // treats a served docs tree as generated for .js and .css; HTML is the
  // format these tools actually emit, and it is required to look like
  // machine output rather than a page somebody wrote.
  if (
    /(^|\/)(public|static|_site|site|www|docs|assets)\/.*\.html?$/i.test(path) &&
    looksGenerated(content)
  ) {
    return true;
  }
  // The line Go's toolchain specifies for machine-written source
  // (golang.org/s/generatedcode). stringer, protoc, mockgen and sqlc all
  // stamp it, and it has to be the file's first line, which is why it is
  // read from the first few hundred bytes and not from anywhere in the file.
  // fzf ships two stringer tables -- one 300-character constant holding
  // every action name run together, another holding every key name -- and
  // both read as encoded blobs, because a name table with no separators is
  // exactly what one looks like.
  //
  // Downgraded, not exempted, like everything else here: stamping the line
  // onto a payload costs one line, so the high-specificity signatures still
  // fire at full weight on a file carrying it.
  if (/^(\/\/|#)\s*Code generated .{0,120}? DO NOT EDIT\.$/m.test(content.slice(0, 400))) return true;
  // A declaration file states types and executes nothing: webpack ships a
  // 15,000-line types.d.ts and earned a caution from it. Downgraded rather
  // than exempted, like everything else here, so a payload parked in one is
  // still reported.
  if (/\.d\.[cm]?ts$|\.pyi$/i.test(path)) return true;
  // A library checked in under its own version (jsonwebtoken@8.5.1.js) or
  // a libraries folder.
  if (/[@-]\d+\.\d+\.\d+(\.min)?\.(js|mjs|cjs|css)$/i.test(path) || /(^|\/)libraries\//i.test(path)) return true;
  // A Yarn release bundle, wherever a project keeps it. ".yarn/" above
  // catches the default location; Yarn 1 and vendored copies sit elsewhere.
  if (/(^|\/)yarn\/releases\//i.test(path)) return true;
  const head = content.slice(0, 600);
  // A licence header is twenty bytes and anyone can write one, so on its own
  // it says nothing: it used to be enough to mark any file at any path as a
  // library. It counts only where the file is also shaped like machine
  // output, which every genuine case here is. A hand-written file that opens
  // with a copyright line is authored code and is judged as authored code.
  if (/@license|@preserve|copyright\s+\(c\)|\(c\)\s*\d{4}|\bMozilla\b|pdf\.?js/i.test(head) && looksGenerated(content)) {
    return true;
  }
  // A minifier stamps what it produced, and a CDN stamps what it repackaged.
  // Line length cannot tell a bundle from a payload (the single-line-blob
  // fixture is one 14 KB line and is malicious), but a build tool's own
  // banner can: FalconChristmas/fpp turned red for a 3.7 MB file whose first
  // line reads "Minified by jsDelivr using Terser". This does not exempt
  // anything on its own, it downgrades the low-specificity signals, so a
  // forged banner still leaves every real signature at full weight.
  if (/minified by|\boriginal file:\s*\/npm\/|\bterser\b|\buglify(js)?\b|\bcdn\.jsdelivr\.net|\bunpkg\.com|generated by (rollup|esbuild|webpack|parcel|vite)/i.test(head)) {
    return true;
  }
  // A file that opens with a bundler's own generated banner is bundler
  // output, whatever it is named or wherever it sits. Insomnia ships Yarn's
  // 4 MB standalone build as packages/insomnia/bin/yarn-standalone.js, which
  // no path or version rule catches. This matches the banner webpack emits,
  // not the identifier it defines: authored code can mention
  // __webpack_require__ in a comment, and that is not a bundle.
  if (/webpackBootstrap|\/\*{4,}\/[\s\S]{0,80}\/\*{4,}\//.test(head)) return true;
  // Emscripten writes its own section markers into the JavaScript it compiles
  // from C or C++. galacean/engine ships PhysX built that way under
  // packages/physics-physx/libs/, and the asm.js body reads as one huge
  // encoded blob because that is exactly what it is.
  if (/EMSCRIPTEN_START_(ASM|FUNCS)|\bemscripten_bind_|\bModule\[["']asm["']\]/.test(content.slice(0, 65536))) return true;
  return false;
}

/**
 * In vendored artifacts, drop low-specificity findings to informational.
 * High-specificity theft behavior stays loud everywhere: libraries do not
 * legitimately read wallets or ship your environment to a server.
 */
export function maybeDowngrade(findings, vendored) {
  if (!vendored) return findings;
  // Everything from a vendored artifact is marked, not only what this
  // function steps down. Eight informational findings about one checked-in
  // bundle are one observation -- "this project vendors a minified library"
  // -- and verdict.js collapses them into a single weak signal for the same
  // reason it collapses four names for encoded content. Prettier and jest
  // were yellow on nothing but Yarn's own release bundle.
  return findings.map((f) => ({ ...f, vendored: true })).map((f) => {
    if (VENDOR_NOISE.has(f.id)) {
      return {
        ...f,
        severity: "low",
        why: `${f.why} (This appears inside what looks like a vendored or minified library file, where such patterns are normal, so it is treated as informational.)`,
      };
    }
    // Theft and loader behaviour is not what a bundle looks like. A banner is
    // cheap to write, so it buys one step down and no more: a caution still
    // reads as "someone should look", which is the least this deserves.
    if (LOW_SPECIFICITY.has(f.id) && f.severity === "high") {
      return {
        ...f,
        severity: "medium",
        why: `${f.why} (This file looks vendored or minified, so it is reported as a caution rather than as danger. A library that does this is still doing it.)`,
      };
    }
    return f;
  });
}
