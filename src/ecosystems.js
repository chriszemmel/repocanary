/**
 * Rules for the places the attack hides outside npm code: Python, Rust, Go,
 * Gradle and Maven build steps, editor and container auto-run hooks, CI
 * workflows, and Makefiles. The social attack is language-agnostic; the
 * mechanism is always the same: a step that executes before the victim has
 * read anything.
 */

import {
  decodeJsonEscapes,
  withoutCommentLines,
  decodeYamlEscapes,
  everyMatchInContext,
  lineOfIndex,
  matchLocation,
  parseJsonc,
  redactSnippet,
  safeJsonParse,
} from "./textutil.js";

/**
 * Script bodies that make an automatically-run hook genuinely dangerous,
 * not just present: a download piped, substituted or saved into a shell,
 * inline eval, decoding blobs, or fetching a URL and running it.
 *
 * A loopback host is not a remote source: nothing arrives from the machine
 * the command already runs on, and a server the repository starts is code
 * this scan reads on its own terms. remix-run/indie-stack runs
 * `start-server-and-test dev http://localhost:3000 "npx cypress open"`,
 * where the URL is the address the harness waits for and npx runs a
 * devDependency, and the two together read as fetching an interpreter from
 * the network.
 *
 * A curl with nothing after it downloads nothing: whiteknightonhorse/APIbase
 * ships an agent hook that refuses any command matching *'curl | bash'*, and
 * the name of the shape it refuses read as an instance of it.
 *
 * Every run here is bounded. `\S+` before another bounded run is the shape a
 * fuzzer found: on a long line with no spaces the greedy run and the run
 * after it re-divide the same text at every position, and a 30 KB file took
 * four seconds. A URL long enough to exceed 300 characters is not the case
 * this is trying to read.
 */
export const DANGEROUS_SCRIPT =
  /(curl|wget)\s+[^\s|][^\n]{0,120}\|\s*(sh|bash|node|python)|(^|[\s;&])(node\s+-e|python3?\s+-c)\b|\beval\b|base64\s+(-d|--decode)|atob\(|(https?:\/\/(?!localhost[:/\s"']|127\.0\.0\.1|0\.0\.0\.0|\[::1\])[^\n]{1,300}?(?:\|\|?|&&|;|["'])\s*(?:sudo\s+)?(node|npx|sh|bash|python3?)\b)|(^|[\s;&|(])(node|sh|bash|python3?)\s+(?:-\S{1,60}\s+)*https?:\/\/(?!localhost[:/\s"']|127\.0\.0\.1|0\.0\.0\.0|\[::1\])|(start\s+\/b\s+node)|(nohup\s+(node|bash|sh|python)[^\n]{0,80}&)|\b(npx|tsx)\s+https?:\/\/|powershell[^\n]{0,80}(-enc|downloadstring|iwr|invoke-webrequest)|(sh|bash|zsh|source|\.)\s+(-[a-zA-Z]+\s+)*<\(\s*(curl|wget)\b|(sh|bash|zsh)\s+(-[a-zA-Z]+\s+)*["']?(\$\(|`)\s*(curl|wget)\b/i;

/**
 * An inline interpreter call whose code is a short, self-contained
 * expression: no module loading, no network, no decoding, no process
 * spawning, no escapes. MetaMask's postinstall gate,
 * node -e "process.exit(process.env.CI ? 0 : 1)", is the shape. Such a call
 * cannot stage a payload, so it is removed before the danger test; anything
 * else in the same script string is still judged.
 */
// Escapes are allowed inside the quotes, since a regex or a newline in the
// code needs them; whether an escape hides anything is judged below.
const TRIVIAL_INLINE_RE = /\b(node\s+-e|python3?\s+-c)\s+(?:"((?:[^"\\]|\\.){0,2000})"|'((?:[^'\\]|\\.){0,2000})')/g;

/**
 * What an inline program needs to do anything a trap wants: reach the
 * network, start a process, run code it was handed, decode something, load
 * native code, or spell an identifier through escapes so a reader does not
 * see it. `\b` and `\d` in a regex are none of those; `\x72equire` is.
 */
const INLINE_DANGER =
  /\b(fetch|https?|net|dgram|tls|socket|urllib\d?|requests|httpx|aiohttp|child_process|spawn\w*|exec\w*|popen|subprocess|system|eval|Function|compile|__import__|importlib|base64|b64decode|atob|btoa|Buffer|fromCharCode|codecs|marshal|pickle|ctypes|dlopen|vm|worker_threads|shutil|process\.binding)\b|\\x[0-9a-f]{2}|\\u\{?[0-9a-f]{4}|\\[0-7]{3}/i;

/** Modules an inline program may load and stay inert: data, text, time, and the project's own files. */
const INERT_MODULES = /^(?:node:)?(?:fs|path|os\.path|json|sys|re|datetime|time|math|random|string|collections|itertools|functools|textwrap|pathlib|typing|enum|dataclasses|uuid|hashlib)$/;

/**
 * Can this inline program only compute and touch files inside the project?
 * Then it cannot fetch or run anything, whatever it is for: MetaMask's
 * `process.exit(process.env.CI ? 0 : 1)`, marm-memory's lockfile cleanup,
 * and a Claude Code hook in Justdvp/claude-code-templates that adds the year
 * to a search query with json, re and datetime. A path that leaves the
 * project, the home directory, or any module outside the inert set keeps it
 * dangerous.
 */
function inlineCodeIsInert(code) {
  const modules = [
    ...[...code.matchAll(/require\(\s*['"]([^'"]+)['"]\s*\)/g)].map((m) => m[1]),
    ...[...code.matchAll(/(?:^|[;\s])import\s+([\w.]+(?:\s*,\s*[\w.]+)*)/g)].flatMap((m) => m[1].split(/\s*,\s*/)),
    ...[...code.matchAll(/(?:^|[;\s])from\s+([\w.]+)\s+import\b/g)].map((m) => m[1]),
  ];
  // The project's own modules, by relative path, are code this scan reads
  // on its own: web3.js checks its build with node -e "require('./lib')".
  if (modules.some((name) => !INERT_MODULES.test(name) && !/^\.{1,2}\//.test(name))) return false;
  if (/\brequire\s*\(\s*[^'"\s]/.test(code)) return false;
  if (INLINE_DANGER.test(code)) return false;
  return !LEAVES_PROJECT.test(code);
}

/** A path or lookup that reaches outside the project: the home directory, the environment, the root. */
const LEAVES_PROJECT = /['"`](\/|~)|\.\.|homedir|expanduser|\.home\s*\(|getenv|tmpdir|gettempdir|process\.env\.(HOME|USERPROFILE|APPDATA|TMP)|environ/;

/**
 * A literal program in a Makefile recipe is code the reader sees where it
 * sits, so what it imports is not the question: numpy asks sys for the
 * interpreter version, scipy's docs open a browser tab, wagtail's writes its
 * OpenAPI schema through Django. It is a caution when it reaches the network,
 * starts or evaluates something, decodes, or leaves the project.
 */
function literalProgramIsInert(code) {
  return !INLINE_DANGER.test(code) && !LEAVES_PROJECT.test(code);
}

/**
 * DANGEROUS_SCRIPT with trivial inline expressions blanked out first, for
 * manifest lifecycle hooks where "node -e" is a common benign idiom.
 */
export function isDangerousScript(cmd) {
  // The one spawn an inline prepare script commonly makes is husky's hook
  // installer, guarded by an environment check; it runs a package the
  // lockfile already pins, not fetched code.
  // The same guard runs any one installed tool the same way: carmazium's
  // postinstall runs `npx prisma generate` inside it. One plain command
  // through the package runner, with no shell syntax, no URL and no
  // interpreter, names a package the lockfile pins; a bare `id` or
  // anything more keeps the conviction.
  const HUSKY_IDIOM =
    /require\(\s*['"](?:node:)?child_process['"]\s*\)\s*\.execSync\(\s*['"](?:husky(?:\s+install)?|(?:npx|bunx|pnpm\s+exec|yarn)\s+(?!(?:curl|wget|sh|bash|zsh|node|python3?|deno|bun|ruby|perl|powershell|pwsh|cmd|eval|sudo)\b)[\w@][\w@/.-]*(?:\s+[\w@/.:=-]+)*)['"][^)]*\)/g;
  // Running a script this repository ships, named by a literal path, is the
  // plain local hook the severity split already calls low: scan.js follows
  // that path and the file is judged on its own, so a dropper is caught
  // there rather than by the wrapper around it. windmill guards its UI
  // builder with exactly this shape. A path built from a variable, a URL, or
  // anything decoded is not a literal and keeps the conviction.
  const LOCAL_SCRIPT_IDIOM =
    /require\(\s*['"](?:node:)?child_process['"]\s*\)\s*\.(?:execSync|execFileSync|spawnSync)\(\s*['"](?:node|sh|bash|python3?)\s+\.{0,2}\/?[\w./-]+\.(?:js|cjs|mjs|sh|py)(?:\s+[\w./=-]+)*['"][^)]{0,120}\)/g;
  // Housekeeping on a path the repository owns: asking whether a build
  // directory is there, making it, and removing it again. Airflow's clean
  // script is
  //   node -e "require('node:fs').rmSync('dist', { recursive: true, force: true })"
  // which deletes its own build output, and it was read as a loader because
  // the inline check counted any require() as a tell. That was always wrong; it
  // only became reachable once a hook was judged on the script it delegates
  // to, and it convicted Apache Airflow. The path has to be a literal that
  // stays inside the project, so anything built from a variable, reaching
  // upwards, or decoded keeps the conviction.
  const LOCAL_FS_IDIOM =
    /require\(\s*['"](?:node:)?fs['"]\s*\)\s*\.(?:existsSync|statSync|mkdirSync|rmSync|rmdirSync|unlinkSync)\(\s*['"](?![^'"]*\.\.)\.?\/?[\w./-]+['"]\s*(?:,\s*\{[^{}]{0,160}\}\s*)?\)/g;
  // The two local idioms are neutralised across the whole command, not just
  // inside a short inline expression: windmill's guard is longer than the
  // inline matcher's limit, and the reason they are safe does not depend on
  // how much else is written around them.
  // Printing a literal is not running it. @openhands/agent-canvas greets a
  // global install with
  //   node -e "if (process.env.npm_config_global === 'true') { console.log('...') }"
  // and the escapes in the colour codes read as an obfuscated loader. Only a
  // call whose one argument is a string literal is blanked, so a value built
  // from anything else still reaches the tells below.
  const CONSOLE_PRINT_IDIOM =
    /console\.(?:log|error|warn|info)\(\s*(?:'(?:[^'\\\n]|\\.)*'|"(?:[^"\\\n]|\\.)*"|`(?:[^`\\$]|\\.)*`)\s*\)/g;
  // An allowlisted installer piped into a shell is the documented way to
  // install that tool, here as in a Dockerfile or a Makefile, where
  // downloadIntoShell already reads it so. MSKazemi/yazses installs uv
  // from astral.sh in a dev container's postCreateCommand.
  const KNOWN_INSTALLER_PIPE = /\b(?:curl|wget)\b[^|;&\n]{0,300}\|\s*(?:ba|z|da)?sh\b/g;
  // eval "$(mise activate bash)" is a local tool's shell integration, the
  // same as in an .envrc; a substitution that downloads keeps the finding.
  const LOCAL_TOOL_EVAL = /\beval\s+\\?"\\?\$\(\s*(?!curl|wget|base64)[\w.-]+(?:\s+[\w.=-]+){0,4}\s*\)\\?"/g;
  const stripped = String(cmd)
    .replace(LOCAL_TOOL_EVAL, "true")
    .replace(KNOWN_INSTALLER_PIPE, (m) => (allUrlsAreKnownInstallers(m) ? "true" : m))
    .replace(CONSOLE_PRINT_IDIOM, "0")
    .replace(LOCAL_SCRIPT_IDIOM, "true")
    .replace(LOCAL_FS_IDIOM, "true")
    .replace(TRIVIAL_INLINE_RE, (m, _kw, dq, sq) => {
    // A literal git command is the repository's own version control:
    // agentmux points core.hooksPath at its .githooks, as husky does.
    const code = (dq ?? sq ?? "")
      .replace(HUSKY_IDIOM, "true")
      .replace(/\b(?:cp|require\(\s*['"](?:node:)?child_process['"]\s*\))\s*\.\s*(?:execSync|execFileSync|spawnSync)\(\s*(['"])git\s[^'"]{1,120}\1\s*(?:,\s*\{[^{}]{0,120}\}\s*)?\)/g, "0")
      .replace(/(?:(?:const|let|var)\s+)?\bcp\s*=\s*require\(\s*['"](?:node:)?child_process['"]\s*\)\s*,?/g, "");
    return inlineCodeIsInert(code) ? "true" : m;
  });
  return DANGEROUS_SCRIPT.test(stripped);
}

/**
 * Installers whose curl-pipe-sh is an established convention. Each entry is a
 * hostname, optionally narrowed to a path prefix where the host also serves
 * user-published content.
 */
const KNOWN_INSTALLERS = [
  "sh.rustup.rs",
  // Paradigm's Foundry and rclone, each installer served from its project's
  // own domain and documented as the way to install it.
  "foundry.paradigm.xyz",
  // Haskell's toolchain installer, from the Haskell organisation's domain.
  "get-ghcup.haskell.org",
  "rclone.org/install.sh",
  "dot.net/v1/dotnet-install.sh",
  "apt.llvm.org/llvm.sh",
  "release.anza.xyz",
  "release.solana.com",
  "get.pnpm.io",
  "get.docker.com",
  "deb.nodesource.com",
  // The same publisher's RPM host. Listing only the Debian one made pm2's
  // own RPM packaging script a dropper for installing Node the documented
  // way, which is the shape this allowlist exists to recognise.
  "rpm.nodesource.com",
  "install.python-poetry.org",
  "astral.sh",
  "bun.sh",
  "bun.com",
  "get.wasmer.io",
  "fly.io/install.sh",
  "ollama.com/install.sh",
  "raw.githubusercontent.com/travis-ci/gimme/",
  "raw.githubusercontent.com/golangci/golangci-lint/",
  // The same installer, which moved to the project's own domain.
  "golangci-lint.run/install.sh",
  "raw.githubusercontent.com/cargo-bins/cargo-binstall/",
  "deno.land/install.sh",
  "deno.land/x/install/",
  "get.helm.sh",
  "getcomposer.org",
  "install.goreleaser.com",
  "install-node.vercel.app",
  "bootstrap.pypa.io",
  "repo.anaconda.com",
  "repo.continuum.io",
  "raw.githubusercontent.com/nvm-sh/nvm/",
  // nvm's previous home; pinned older versions still install from there.
  "raw.githubusercontent.com/creationix/nvm/",
  "rustwasm.github.io/wasm-pack/installer/",
  "raw.githubusercontent.com/Homebrew/install/",
  "raw.githubusercontent.com/ohmyzsh/ohmyzsh/",
  "raw.githubusercontent.com/pyenv/pyenv-installer/",
  "pyenv.run",
  "get.rvm.io",
  "get.sdkman.io",
  "sdk.cloud.google.com",
  "nixos.org/nix/install",
  "install.determinate.systems",
  "yarnpkg.com/install.sh",
  "get.volta.sh",
  "fnm.vercel.app",
  "starship.rs/install.sh",
  "tailscale.com/install.sh",
  "get.acme.sh",
  "get.pulumi.com",
  // Coding-agent CLIs, each from its vendor's own domain, and the security
  // scanners a pentest image installs from their own repositories.
  "antigravity.google/cli/install.sh",
  "claude.ai/install.sh",
  "opencode.ai/install",
  "cursor.com/install",
  "mise.run",
  "raw.githubusercontent.com/trufflesecurity/trufflehog/",
  "raw.githubusercontent.com/anchore/syft/",
  "raw.githubusercontent.com/anchore/grype/",
  "raw.githubusercontent.com/aquasecurity/trivy/",
];

/** True when the command has URLs and every one of them is an allowlisted installer. */
function allUrlsAreKnownInstallers(command, extra = []) {
  const all = command.match(/https?:\/\/[^\s'"`|;)]+/gi) ?? [];
  if (all.length === 0) return false;
  // `extra` holds prefixes that count as known for this scan: the scanned
  // repository's own raw and web URLs, whose content the reader already has.
  const urls = all.filter((u) => !extra.some((prefix) => u.toLowerCase().startsWith(prefix.toLowerCase())));
  if (urls.length === 0) return true;
  return urls.every((raw) => {
    let url;
    try {
      url = new URL(raw);
    } catch {
      return false;
    }
    const host = url.hostname.toLowerCase();
    return KNOWN_INSTALLERS.some((entry) => {
      const slash = entry.indexOf("/");
      if (slash === -1) return entry === host;
      return entry.slice(0, slash) === host && url.pathname.startsWith(entry.slice(slash));
    });
  });
}

/**
 * The download being piped: the command from its last curl or wget onward.
 * Splitting on shell separators instead would let a `;` inside a quoted URL
 * move the boundary.
 */
function lastDownloadCommand(command) {
  const starts = [...command.matchAll(/\b(?:curl|wget)\b/gi)];
  const last = starts[starts.length - 1];
  return last ? command.slice(last.index) : command;
}

/** Longest logical line this rule will assemble, in characters. */
const MAX_LOGICAL_LINE = 8_000;

/**
 * The file as logical lines, joining backslash continuations onto the line
 * they start on. A continuation removes the backslash and the newline and
 * nothing else, so surrounding whitespace is preserved exactly: joining with
 * a space would break a URL split across the join, and trimming would glue
 * two words together.
 */
function logicalLines(content) {
  const out = [];
  let current = null;
  content.split("\n").forEach((rawLine, i) => {
    const raw = rawLine.replace(/\r$/, "");
    // Counted backwards rather than matched: a greedy `\\+$` retries from
    // every offset on a line that is nothing but backslashes, which is
    // quadratic and stalled the scan on a crafted Makefile. This is linear.
    let backslashes = 0;
    while (backslashes < raw.length && raw[raw.length - 1 - backslashes] === "\\") backslashes += 1;
    // An even run of backslashes is an escaped backslash, not a continuation.
    const continues = backslashes % 2 === 1;
    // A full-line comment (shell, YAML, Dockerfile, Makefile, Python) that
    // mentions curl|bash is documentation, not a command: act's installer
    // warns about it, nocodb's compose file shows the one-liner alternative.
    const text = /^[^\S\n]*#/.test(raw) ? "" : continues ? raw.slice(0, -1) : raw;
    if (current === null) current = { line: i + 1, text: "" };
    if (current.text.length < MAX_LOGICAL_LINE) current.text += text;
    if (!continues) {
      out.push(current);
      current = null;
    }
  });
  if (current !== null) out.push(current);
  return out;
}

/** Interpreters a fetched script is handed to. `.` and `source` read it into the current shell. */
const INTERPRETER = "(sh|bash|zsh|ksh|dash|source|\\.|node|python3?|perl|ruby|php)";

// The span between the download and the shell may contain further pipes,
// so an intermediate filter (`| tee f | bash`) cannot hide the pipe.
// "| python3 -c '...'" hands the download to an inline program as data
// (vllm parses GitHub labels that way); only a bare interpreter, or one
// reading stdin with "-", runs the download as code.
// The horizontal space after the command name is load-bearing. A real
// download names something to download, so curl and wget are always followed
// by an argument; "curl|wget|bash" with no space anywhere is a regex
// alternation listing command names, which is what a tool that detects these
// commands writes down. 0xMarcio/pocindex indexes CVE proof-of-concepts and
// turned red for its own detector: re.compile(r"(?:curl|wget|python\d*|bash|sh)").
// A bare "curl|sh" is not a loss: curl with no URL prints its usage and exits.
// The -c and -e exclusion belongs to the interpreters that take their
// program as an argument and ignore stdin: `curl URL | node -e "..."` runs
// the quoted text, not the download. A shell is the opposite: `sh -e` sets
// errexit and still reads the script from the pipe, so the exclusion applied
// to every interpreter made `| bash -e` a bypass of this whole rule.
// "| python3 -m json.tool" is the same: -m runs a module named on the
// command line and the download is its input. mixpeek/amux's Makefile
// pretty-prints its own health endpoint that way and turned red for it.
// A curl with nothing after it downloads nothing: "(curl | bash)" in a
// warning a guard prints is the name of the shape, not an instance of it.
const CURL_PIPE =
  /\b(curl|wget)[^\S\n]+[^\s|][^\n]{0,200}?\|\s*(?:(?:sh|bash|zsh|ksh|dash)\b|(?:node|perl|ruby|php)\b(?!\s+-(?:c|e|r)\b)|python3?\b(?!\s+-(?:c|e|r|m)\b))/i;

// bash <(curl URL): the download is handed to the shell as a file that never
// touches the disk.
const PROCESS_SUBSTITUTION = new RegExp(`(^|[\\s;&|(])${INTERPRETER}\\s+(-[a-zA-Z]+\\s+)*<\\(\\s*(curl|wget)\\b`, "i");

// eval "$(curl URL)", sh -c "$(wget -qO- URL)", bash "`curl URL`": the
// download becomes the command text itself. A Makefile writes the same
// substitution as $$(curl URL). A plain VERSION=$(curl ...) assignment is not
// this: the substitution has to be consumed by eval or an interpreter.
const COMMAND_SUBSTITUTION = new RegExp(
  `(^|[\\s;&|(])(eval|${INTERPRETER})\\s+(-[a-zA-Z]+\\s+)*["']?(\\$\\$?\\(|\`)\\s*(curl|wget)\\b`,
  "i",
);

/**
 * A single shell command is not four kilobytes long. The cap is here because
 * without it a file of ten thousand `curl` tokens makes this walk to the end
 * of the file ten thousand times, which is quadratic and measurably stalls a
 * scan. What the callers read out of a segment (the URL, an -o flag, the
 * interpreter it pipes into) sits within a line of the download.
 */
const MAX_COMMAND_SEGMENT = 4_000;

/**
 * The command a download belongs to: from its curl or wget up to the next
 * unquoted `;`, `&&`, `||` or `|`, so a separator inside a quoted URL cannot
 * end it early.
 */
function commandSegment(text, start) {
  let quote = null;
  const stop = Math.min(text.length, start + MAX_COMMAND_SEGMENT);
  for (let i = start; i < stop; i++) {
    const c = text[i];
    if (quote) {
      if (c === quote) quote = null;
      continue;
    }
    if (c === '"' || c === "'") quote = c;
    else if (c === ";" || c === "|" || (c === "&" && text[i + 1] === "&")) return text.slice(start, i);
  }
  return text.slice(start, stop);
}

const unquote = (token) => token.replace(/^["']|["']$/g, "");
const basename = (path) => unquote(path).split(/[\\/]/).pop();

/**
 * The file a download command writes, or null when it writes to stdout.
 * curl needs -o or -O to write a file; wget writes one unless -O - says
 * otherwise. Either can name the file after the URL.
 */
function downloadedFile(segment) {
  const tool = segment.match(/^(curl|wget)\b/i)[1].toLowerCase();
  const urlName = (segment.match(/https?:\/\/[^\s'"`|;)]+/i) ?? [""])[0].split(/[?#]/)[0].split("/").pop();
  const explicit = segment.match(/(?:^|\s)(?:-[a-zA-Z]*o|--output(?:-document)?)(?:=|\s+)("[^"]*"|'[^']*'|\S+)/);
  const remoteName = segment.match(/(?:^|\s)(?:-[a-zA-Z]*O\b|--remote-name)/);
  let file = null;
  if (tool === "curl") {
    if (explicit) file = unquote(explicit[1]);
    else if (remoteName) file = urlName;
  } else {
    const wgetOut = segment.match(/(?:^|\s)(?:-[a-zA-Z]*O|--output-document)(?:=|\s+)?("[^"]*"|'[^']*'|\S+)/);
    file = wgetOut ? unquote(wgetOut[1]) : urlName;
  }
  if (!file || file === "-" || file.startsWith("/dev/")) return null;
  return file;
}

const escapeRegExp = (s) => s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");

/**
 * Does the text hand the named file to an interpreter? `sh f`, `bash ./f`,
 * `python /tmp/f`, `source f`. A file with a script extension also counts
 * when it is made executable or run as ./f. A downloaded binary that is only
 * ever executed directly is not matched: Dockerfiles do that for every CLI
 * they install, and the dropper shape is fetched code run as code.
 */
function runsFile(text, file) {
  const name = escapeRegExp(basename(file));
  if (name.length === 0) return false;
  const viaInterpreter = new RegExp(
    `(^|[\\s;&|(])${INTERPRETER}\\s+(-[a-zA-Z]+\\s+)*["']?(\\S*[\\\\/])?${name}["']?(?=$|[\\s;&|)])`,
    "im",
  );
  if (viaInterpreter.test(text)) return true;
  if (/\.(sh|bash|zsh|py|js|mjs|cjs|rb|pl|php|ps1)$/i.test(file)) {
    return new RegExp(`(\\./|chmod\\s+[+a-z0-7]+\\s+)(\\S*[\\\\/])?${name}(?=$|[\\s;&|)])`, "im").test(text);
  }
  return false;
}

/**
 * Every position in the file where some file is handed to an interpreter,
 * made executable, or run as `./f`, as basename -> the last such offset.
 *
 * runsFile above reads the whole rest of the file, and it was asked once per
 * download on the line. On an ordinary file that is nothing; on a file of
 * twenty thousand `curl -o a.sh URL` lines it reads a megabyte twenty
 * thousand times, and one such Makefile took 240 seconds inside a scan with a
 * sixty second ceiling. This is the same question asked once for the whole
 * file, so the loop below can skip a download whose file is never run without
 * reading anything.
 *
 * The pattern is deliberately the two in runsFile with the filename left
 * open, so anything runsFile could match appears here: a name absent from
 * this map cannot match there, and a name present is still decided by
 * runsFile itself.
 */
// Named, because INTERPRETER is itself a capturing group: a positional read
// here picks up the interpreter rather than the file it is handed.
const RUN_TARGET = new RegExp(
  `(?:(?:^|[\\s;&|(])${INTERPRETER}\\s+(?:-[a-zA-Z]+\\s+)*["']?|\\.\\/|chmod\\s+[+a-z0-7]+\\s+)(?<target>(?:\\S*[\\\\/])?[^\\s;&|)]*)`,
  "gim",
);

function runTargets(text) {
  const out = new Map();
  for (const m of text.matchAll(RUN_TARGET)) {
    const name = basename(m.groups.target);
    if (name.length > 0) out.set(name.toLowerCase(), m.index);
  }
  return out;
}

/**
 * The first download that is run as a shell script and does not come from
 * an allowlisted installer, with its location. Four shapes: piped into a
 * shell, process substitution, command substitution, and a file that is
 * saved on one logical line and run through an interpreter on that line or
 * a later one.
 */
/**
 * Is a downloaded file checked against a hash written into this repository
 * before it is run? keyv pins a version and a SHA-256, verifies with
 * sha256sum -c under "set -e", and only then runs the installer. Swapping
 * the remote file breaks the check, which is the property a bare
 * "curl | bash" lacks and the reason that shape convicts.
 *
 * Both parts are required: the verifying command, and a hash literal
 * committed alongside it. A hash fetched from the same server would prove
 * nothing.
 *
 * This says the bytes cannot change, not that they are safe: an attacker
 * who pins the hash of their own payload still gets a caution rather than a
 * conviction. It stays reported for that reason, and fake-interview malware
 * does not work this way, since the point of that campaign is a staging
 * server whose contents can change after review.
 */
// The hash half is a property of the whole file, so the caller tests it once
// rather than per download; this is the half that has to sit after the
// download it verifies.
function checksumPinned(rest) {
  // A digest computed and compared by hand is the same check: labsai/EDDI
  // takes `sha256sum` of the downloaded installer and exits unless it equals
  // the pinned value, which is what -c would have done.
  const verifies = /\b(sha256sum|sha512sum|sha1sum|shasum|md5sum)\b[^\n]{0,80}(-c|--check)\b|\bopenssl\s+dgst\b[^\n]{0,120}|\bcertutil\b[^\n]{0,60}-hashfile|\b(sha256sum|sha512sum|shasum)\b[\s\S]{0,300}?(!=|-ne|==)\s*"?\$\{?\w*(SHA|HASH|SUM|DIGEST)\w*/i;
  return verifies.test(rest);
}

export function downloadIntoShell(content, extra = []) {
  // A command inside a quoted string, behind a shell prompt or a comment
  // marker, is an instruction being printed for a human rather than one
  // being run: pm2 prints "$ curl ... | bash", dotenv prints
  // " # or: curl ... | sh". The comment form is safe on its own terms too,
  // since a "#" ahead of the command would comment it out if this text ever
  // did reach a shell. The marker has to sit inside the same string literal,
  // so a real command later on the line is untouched.
  const isDocPrompt = (text, idx) => {
    const before = text.slice(0, idx);
    if (/["'`]\s*\$\s*$/.test(before) || /["'`][^"'`]*#[^"'`]*$/.test(before)) return true;
    // A command inside a string that echo or printf is printing is being
    // shown to the reader, not run: OpenVidu's updater prints the one-liner
    // for upgrading a cluster node, and turned red for the text of its own
    // instructions. The quote has to be still open at the match, so
    // `echo done && curl ... | sh` keeps its real command.
    // The same holds for the helpers an installer prints through and for a
    // grep pattern: A6083450/clawgod-plus tells the reader
    //   warn "    curl -fsSL https://claude.ai/install.sh | bash"
    // when its own download fails, and a hook that refuses curl-pipe-sh
    // greps for the shape. Neither hands the text to a shell.
    // Those names are ordinary words too, so they count only where a command
    // starts; echo and printf keep the looser reading they always had.
    return (
      /\b(echo|printf)\b[^"'`]*["'`][^"'`]*$/.test(before) ||
      /(?:^|[;&|({]|\b(?:then|do|else)\b)\s*(warn|warning|info|error|err|die|fail|fatal|log|log_\w+|note|msg|say|print|puts|grep|egrep|rg)\b[^"'`;&|]*["'`][^"'`]*$/.test(before)
    );
  };
  // A here-document fed to cat is text on its way to the terminal: a usage
  // block. kanfu-panda/pdlc-skills documents its remote one-liner inside
  // `cat <<EOF` in its help function and turned red for it. Only a bare cat,
  // optionally aimed at stderr: `cat > setup.sh <<EOF` writes a script that
  // can be run later, and `bash <<EOF` is the shell reading it.
  const printedDoc = new Set();
  {
    const raw = content.split("\n");
    for (let i = 0; i < raw.length; i++) {
      const open = raw[i].match(/(?:^|[\s;&|(])cat\s+(?:[12]?>&[12]\s+)?<<(-?)\s*(['"]?)(\w+)\2\s*(?:[12]?>&[12])?\s*$/);
      if (!open) continue;
      const strip = open[1] === "-";
      let j = i + 1;
      for (; j < raw.length; j++) {
        const body = raw[j].replace(/\r$/, "");
        if ((strip ? body.replace(/^\t+/, "") : body) === open[3]) break;
        printedDoc.add(j + 1);
      }
      i = j;
    }
  }
  const lines = logicalLines(content);
  // The logical lines as one string, with each line's offset into it, built
  // once. The tail a download is judged against is a slice of this, which is
  // exactly what joining the remaining lines produced per download before.
  const joined = lines.map((l) => l.text).join("\n");
  const lineStart = [];
  let at = 0;
  for (const l of lines) {
    lineStart.push(at);
    at += l.text.length + 1;
  }
  // Both asked once for the whole file rather than once per download: the
  // hash literal a checksum is pinned to is a property of the file, and where
  // anything is run at all does not change with which download is being read.
  const targets = runTargets(joined);
  const hasPinnedHash = /\b[0-9a-f]{40,128}\b/i.test(content);
  const located = (line, text, m) => {
    const start = Math.max(0, m.index - 40);
    return {
      line,
      snippet: redactSnippet(text.slice(start, m.index + Math.min(m[0].length + 140, 300))),
      command: m[0],
    };
  };
  // A line that is nothing but a comment cannot run whatever it names, which
  // is the same reasoning as isDocPrompt above, one step out: there the
  // marker had to sit inside a string literal so a real command later on the
  // line stayed visible, and on a whole-comment line there is no later
  // command to protect. Security tools document what they block, and
  // yologdev/yoyo-evolve turned red for the Rust doc comment listing
  // "Piping internet content to shell (curl | bash)" among the shapes its
  // analyser catches.
  //
  // A directive is the exception, because some comments are instructions to a
  // tool rather than to a reader: `//go:generate curl ... | sh` looks like a
  // comment and is run by `go generate`. The b10-go-generate-download sample
  // dropped from red to a caution when this skip was first written without
  // that carve-out, and the coverage catalog is what noticed.
  const COMMENT_LINE = /^\s*(#|\/\/|\/\*|\*|--|;)/;
  const EXECUTED_DIRECTIVE = /^\s*\/\/\s*go:generate|^\s*#\s*shellcheck\s+shell=/;
  for (let i = 0; i < lines.length; i++) {
    const { line, text } = lines[i];
    if (COMMENT_LINE.test(text) && !EXECUTED_DIRECTIVE.test(text)) continue;
    if (printedDoc.has(line)) continue;
    const pipe = text.match(CURL_PIPE);
    // A placeholder downloads nothing: johalputt/VayuPress prints
    // `curl -sSL <url> | sudo bash` as usage text across several lines.
    const placeholder = pipe && /\s<[\w -]{1,30}>/.test(lastDownloadCommand(pipe[0])) && !/https?:\/\//i.test(lastDownloadCommand(pipe[0]));
    if (pipe && !placeholder && !isDocPrompt(text, pipe.index) && !allUrlsAreKnownInstallers(lastDownloadCommand(pipe[0]), extra)) return located(line, text, pipe);
    for (const shape of [PROCESS_SUBSTITUTION, COMMAND_SUBSTITUTION]) {
      const m = text.match(shape);
      if (!m) continue;
      // The same exemption the pipe form gets. It was only ever applied
      // there, so `echo "sh <(curl ...)"` was read as a command while
      // `echo "curl ... | sh"` was read as the printed instruction it is.
      // OpenVidu's updater prints the first shape and turned red for it.
      if (isDocPrompt(text, m.index)) continue;
      const download = commandSegment(text, m.index + m[0].search(/curl|wget/i));
      if (allUrlsAreKnownInstallers(download, extra)) continue;
      return located(line, text, m);
    }
    // Segments tile the line rather than overlapping. A curl that falls
    // inside the segment just examined is part of that same command, since a
    // segment ends at the first unquoted separator, so re-reading from it
    // would examine the same command again. On an ordinary file this changes
    // nothing; on a line of a hundred thousand curl tokens it is the
    // difference between reading the line once and reading it once per
    // token, which at the one-megabyte file cap is seconds per file.
    let coveredUntil = 0;
    for (const m of text.matchAll(/\b(curl|wget)\b/gi)) {
      if (m.index < coveredUntil) continue;
      const segment = commandSegment(text, m.index);
      coveredUntil = m.index + segment.length;
      if (allUrlsAreKnownInstallers(segment, extra)) continue;
      if (/\s<[\w -]{1,30}>/.test(segment) && !/https?:\/\//i.test(segment)) continue;
      const file = downloadedFile(segment);
      if (file === null) continue;
      // A certificate bundle, an archive or a data file is read, not run:
      // upsun/cli downloads curl's cacert.pem for its PHP build.
      if (/\.(pem|crt|cer|json|ya?ml|toml|txt|csv|md|png|jpe?g|gif|svg|ico|zip|tar|gz|tgz|xz|bz2|zst|7z|pdf|html?|css|woff2?|ttf|db|sqlite|wasm)$/i.test(file)) continue;
      // Nothing in the file runs anything by this name at or after the
      // download, so runsFile cannot say yes and the tail need not be read.
      // This is what keeps the loop linear: without it every download on
      // every line rescanned the rest of the file.
      const runAt = targets.get(basename(file).toLowerCase());
      const from = lineStart[i] + m.index;
      if (runAt === undefined || runAt < from) continue;
      const rest = joined.slice(from);
      if (!runsFile(rest, file)) continue;
      if (hasPinnedHash && checksumPinned(rest)) continue;
      return located(line, text, { index: m.index, 0: segment });
    }
  }
  return null;
}

function finding(id, severity, file, loc, why, next, extra) {
  return { id, severity, file, line: loc?.line ?? null, snippet: loc?.snippet ?? "", why, next, ...extra };
}

/**
 * A file that starts something by itself and could not be read.
 *
 * These rules all parse a document before judging it, and a parse failure
 * used to return an empty array, which is indistinguishable from a file with
 * nothing in it. That is the same mistake the byte caps already refuse to
 * make: silence about something nobody could open is not evidence. It is
 * reported rather than convicted, because a genuinely broken config is a
 * thing that happens, and because the shape of the failure is what a reader
 * needs to see.
 */
function unparseableAutorunConfig(path, content, what, action) {
  return finding(
    "unparseable-autorun-config",
    "medium",
    path,
    matchLocation(content, /\S/) ?? { line: 1, snippet: path.split("/").pop() },
    `This ${what} could not be parsed, so what it starts was never checked. Editors and container tooling accept more than strict JSON here, which means a file they will happily act on can be one RepoCanary cannot read, and a file nobody could read is not a file that was found clean.`,
    `Open this file yourself and read every command in it before ${action}.`,
  );
}

/**
 * Programs that are part of the machine or the toolchain rather than
 * anything a repository ships. Starting one with a literal name runs that
 * tool, not code the repository downloaded: setup.py asks uname which OS it
 * is on, a Rakefile runs `bundle install`, a release script asks git for the
 * last tag, an image sample hands a file to ImageMagick. npx is not here,
 * since it fetches and runs a package by name.
 */
export const KNOWN_LOCAL_TOOL =
  "(?:git|gh|which|where|uname|ldconfig|sw_vers|lsb_release|nproc|sysctl|xcrun|xcodebuild|xcode-select|cargo|rustc|rustup|cmake|make|gmake|ninja|meson|pkg-config|gcc|g\\+\\+|clang|clang\\+\\+|cc|nvcc|hipcc|nvidia-smi|rocminfo|go|javac|mvn|gradle|npm|yarn|pnpm|bundle|bundler|gem|rake|pod|convert|magick|ffmpeg|ffprobe|tar|unzip|zip|gzip|docker|kubectl|helm|protoc|swig|cython|pip3?|python3?\\s+-m\\s+pip|brew|apt-get|dnf|yum|pacman|choco|winget|gpg|gpgv|sha256sum|shasum)";

// Python: setup.py runs at build time, pyproject backends, requirements URLs.

const SETUP_PY_EXEC = /os\.system\s*\(|subprocess\.\w+\s*\(|\bexec\s*\(|\beval\s*\(|__import__\s*\(/;
const SETUP_PY_NET =
  /urllib\.request\.urlopen|urlretrieve|requests\.(get|post)|\b(curl|wget)\b|https?:\/\/(?!github\.com\/[^\s/]+\/[^\s/]+\/blob\/)\S{1,300}\.(sh|py|zip|tar|gz|tgz|whl|exe|bin|msi)\b|b64decode|base64\.|codecs\.decode|zlib\.decompress|marshal\.loads/;
// subprocess.check_output(["git", "describe"]) reads a version stamp.
const SETUP_PY_GIT = new RegExp(`(os\\.system|subprocess\\.\\w+)\\s*\\(\\s*\\[?\\s*["']${KNOWN_LOCAL_TOOL}\\b|\\bexec\\s*\\(\\s*(?:f\\.read\\(\\)|open\\([^)]{1,120}\\)\\.read\\(\\)|compile\\(\\s*open\\()|__import__\\s*\\(\\s*["'](?:setuptools|distutils)["']\\s*\\)`);

/**
 * A command run at install time convicts only together with a download:
 * a setup.py that shells out to git for a version string, or registers a
 * cmdclass to build an extension, is ordinary packaging, and a false red on
 * it would be a bug. A command and a fetch in the same file is the dropper.
 */
export function checkSetupPy(path, content) {
  const findings = [];
  // pip runs the setup.py at the root of what it installs, whatever it
  // imports. One nested inside a package that never touches setuptools is a
  // module that happens to be called setup: raphasouthall/neurostack's
  // `neurostack setup` command, and a pulumi template's inspection helper.
  if (path.includes("/") && !/\b(setuptools|distutils|skbuild)\b/.test(content)) return findings;
  const execs = (content.match(new RegExp(SETUP_PY_EXEC.source, "g")) ?? []).length;
  const gitOnly = execs > 0 && execs === (content.match(new RegExp(SETUP_PY_GIT.source, "g")) ?? []).length;
  const runs = execs > 0 && !gitOnly;
  // The fetch has to sit near the exec. Pillow's setup.py probes pkg-config
  // with Popen and links to its docs elsewhere in the file; a dropper
  // downloads and runs within a few lines.
  const fetches = [...content.matchAll(new RegExp(SETUP_PY_EXEC.source, "g"))].some((m) =>
    SETUP_PY_NET.test(content.slice(Math.max(0, m.index - 300), m.index + 300)),
  );
  if (runs && fetches) {
    findings.push(
      finding(
        "setup-py-install-exec",
        "high",
        path,
        matchLocation(content, SETUP_PY_EXEC),
        "This Python package runs shell commands or dynamic code during pip install and reaches for the network in the same file. Like an npm install script, it fires before you review anything, which is exactly how these traps spring.",
        "Do not run pip install on this project. Read setup.py in the browser instead.",
      ),
    );
  } else if (runs) {
    findings.push(
      finding(
        "setup-py-install-exec",
        "medium",
        path,
        matchLocation(content, SETUP_PY_EXEC),
        "This Python package runs a command or dynamic code during pip install (via os.system, subprocess, exec, or eval). Real packages do this to read a git version or compile an extension, but it runs before you have read anything, so it is worth a look.",
        "Read what the command does before running pip install on this project.",
      ),
    );
  } else if (gitOnly || /cmdclass\s*=/.test(content)) {
    findings.push(
      finding(
        "setup-py-custom-command",
        "low",
        path,
        matchLocation(content, gitOnly ? SETUP_PY_GIT : /cmdclass\s*=/),
        "This setup.py plugs its own step into the install (a cmdclass, or a git command run for a version stamp). That is how extension builders and version tools work, and also where an install-time payload would live.",
        "Read the custom step before running pip install.",
      ),
    );
  }
  return findings;
}

const KNOWN_BUILD_BACKENDS = [
  "setuptools.build_meta",
  "flit_core.buildapi",
  "hatchling.build",
  "poetry.core.masonry.api",
  "pdm.backend",
  "maturin",
  "scikit_build_core.build",
  "mesonpy",
];

export function checkPyprojectToml(path, content) {
  const findings = [];
  const backendMatch = content.match(/build-backend\s*=\s*["']([^"']+)["']/);
  if (backendMatch && !KNOWN_BUILD_BACKENDS.includes(backendMatch[1])) {
    findings.push(
      finding(
        "pyproject-custom-backend",
        "medium",
        path,
        matchLocation(content, /build-backend\s*=/),
        `This project declares a custom Python build backend ("${backendMatch[1]}") instead of a standard one like setuptools or hatchling. The backend's code runs during pip install, so a custom backend is custom code executing before you review anything.`,
        "Find the backend's source in this repository and read it before installing.",
      ),
    );
  }
  if (/backend-path\s*=/.test(content)) {
    findings.push(
      finding(
        "pyproject-backend-path",
        "medium",
        path,
        matchLocation(content, /backend-path\s*=/),
        "This project points pip at build code inside the repository itself (backend-path). That local code executes during pip install, before you have reviewed it. It is a legitimate packaging feature, and also a clean way to hide an install-time payload.",
        "Read the files in the referenced backend path before running pip install.",
      ),
    );
  }
  return findings;
}

export function checkRequirementsTxt(path, content) {
  const findings = [];
  const lines = content.split("\n");
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i].trim();
    if (line.startsWith("#") || line.length === 0) continue;
    // `-i` is pip's own short form of --index-url and works in a requirements
    // file exactly the same way, so matching only the long forms let two
    // characters redirect every package the file installs.
    if (/^(--index-url|--extra-index-url|-i\s)/.test(line) && !/pypi\.org/.test(line)) {
      findings.push({
        id: "requirements-custom-index",
        severity: "medium",
        file: path,
        line: i + 1,
        snippet: line.slice(0, 160),
        why: "This requirements file redirects pip to a package index other than pypi.org. Every dependency name then resolves to whatever that server chooses to serve, which is the dependency-confusion attack in one line.",
        next: "Do not pip install with this file. Check what the custom index actually hosts.",
      });
    } else if (/@\s*(git\+)?https?:\/\/|^(git\+)?https?:\/\//.test(line)) {
      findings.push({
        id: "requirements-url-dependency",
        severity: "medium",
        file: path,
        line: i + 1,
        snippet: line.slice(0, 160),
        why: "This requirements file installs a dependency directly from a URL instead of the PyPI registry. The code that installs is whatever that URL serves at that moment, with no registry record of it.",
        next: "Open the URL and read what it serves before running pip install.",
      });
    }
  }
  return findings;
}

// Rust: build.rs runs automatically during cargo build.

const BUILD_RS_DANGEROUS =
  /Command::new\s*\(\s*"(curl|wget|sh|bash|powershell|cmd)"|reqwest|ureq|TcpStream::connect|std::net|\bhyper\b/;
// Running a downloader or shell, or running anything after a fetch, is the
// dropper. A fetch alone (wasmer's build.rs downloads a prebuilt v8 archive
// and links it) is worth a look, not a conviction.
const BUILD_RS_RUNS = /Command::new\s*\(\s*"(curl|wget|sh|bash|powershell|cmd)"|Command::new[\s\S]{0,400}(reqwest|ureq|std::net|TcpStream)|(reqwest|ureq|std::net|TcpStream)[\s\S]{0,400}Command::new/;

export function checkBuildRs(path, content) {
  const findings = [];
  if (BUILD_RS_DANGEROUS.test(content)) {
    findings.push(
      finding(
        "build-rs-network-exec",
        BUILD_RS_RUNS.test(content) ? "high" : "medium",
        path,
        matchLocation(content, BUILD_RS_DANGEROUS),
        "This Rust build script (build.rs) reaches for the network or spawns shell commands. build.rs runs automatically during cargo build, so this code executes the moment you compile, before you run the project at all. Ordinary build scripts generate code or link libraries; they do not download things.",
        "Do not run cargo build. Read build.rs in the browser and check what it fetches or executes.",
      ),
    );
  }
  return findings;
}

// Go: go:generate directives run when someone types go generate.

const GO_GENERATE_RE = /^\/\/go:generate\s+(.*)$/gm;

export function checkGoFile(path, content) {
  const findings = [];
  let m;
  // A fresh copy: exec() on the shared /g pattern would carry its lastIndex
  // into the next file and skip the start of it.
  const re = new RegExp(GO_GENERATE_RE.source, GO_GENERATE_RE.flags);
  while ((m = re.exec(content)) !== null) {
    const cmd = m[1];
    if (/curl|wget|\bsh\b|\bbash\b|https?:\/\//.test(cmd)) {
      findings.push({
        id: "go-generate-exec",
        severity: "medium",
        file: path,
        line: content.slice(0, m.index).split("\n").length,
        snippet: `//go:generate ${cmd.slice(0, 140)}`,
        why: "This Go file carries a go:generate directive that downloads or shells out. It only runs when someone types go generate, but take-home instructions often tell you to do exactly that, and the command executes with your full user permissions.",
        next: "Do not run go generate. Read the command and whatever it fetches first.",
      });
      break;
    }
  }
  return findings;
}

// Gradle and Maven: build files execute as code during a build or IDE import.

// commandLine 'x' is the Groovy DSL and commandLine("x") the Kotlin one;
// only the first was read, so a build.gradle.kts handing a download to a
// shell was invisible to this rule.
const GRADLE_EXEC = /Runtime\.getRuntime\(\)\.exec|ProcessBuilder|\.execute\(\)|javaexec|commandLine\s*(?:\(\s*)?['"]/;
const GRADLE_NET =
  /new\s+URL\s*\([^)]*\)\s*\.\s*(openStream|text|readText|getText)|\b(curl|wget)\b|https?:\/\/(?!repo\.maven\.apache\.org|plugins\.gradle\.org|jcenter|maven\.google\.com|jitpack\.io|dl\.google\.com|github\.com\/[^\s/]+\/[^\s/]+\/blob\/)\S{1,300}\.(sh|jar|zip|tar|gz|tgz|exe|bin|aar|so)\b|powershell[^\n]{0,80}(-enc|downloadstring|iwr|invoke-webrequest)/;
// "git rev-parse HEAD".execute() and commandLine 'git', ... read the
// version into the build; half of all Android build files do it.
const GRADLE_GIT_ONLY = new RegExp(`(['"]${KNOWN_LOCAL_TOOL}\\s[^'"]*['"]\\s*\\.execute\\(\\)|commandLine\\s*(?:\\(\\s*)?['"]${KNOWN_LOCAL_TOOL}['"])`);

export function checkGradle(path, content) {
  const findings = [];
  const execs = [...content.matchAll(new RegExp(GRADLE_EXEC.source, "g"))];
  const onlyGit =
    execs.length > 0 && execs.length === (content.match(new RegExp(GRADLE_GIT_ONLY.source, "g")) ?? []).length;
  if (execs.length > 0 && !onlyGit) {
    // High only when a fetch sits near an exec: a build that compiles a
    // header with ProcessBuilder and links to a docs URL elsewhere is not a
    // downloader.
    const fetches =
      execs.some((m) => GRADLE_NET.test(content.slice(Math.max(0, m.index - 300), m.index + 300))) ||
      Boolean(downloadIntoShell(content));
    findings.push(
      finding(
        "gradle-build-exec",
        fetches ? "high" : "medium",
        path,
        matchLocation(content, GRADLE_EXEC),
        fetches
          ? "This Gradle build file runs external commands and fetches URLs as part of the build. Gradle executes build files as code, so opening this project in an IDE or running any gradle task executes this logic with your user permissions."
          : "This Gradle build file runs external commands as part of the build. Gradle executes build files as code, so opening this project in an IDE runs this logic with your user permissions. Real builds do this for a version stamp or a code generator, so read what the command is.",
        fetches
          ? "Do not build or open this project in an IDE that auto-imports Gradle. Read the build file in the browser first."
          : "Read the command the build runs before opening the project in an IDE.",
      ),
    );
  }
  if (/maven\s*\{\s*url\s*['"]?http:\/\//.test(content)) {
    findings.push(
      finding(
        "gradle-insecure-repo",
        "medium",
        path,
        matchLocation(content, /maven\s*\{\s*url\s*['"]?http:\/\//),
        "This Gradle build pulls dependencies from a repository over plain, unencrypted http. Anything on the network path can substitute the artifacts, which is why every mainstream repository uses https.",
        "Do not build this project until the repository URL is explained and fixed.",
      ),
    );
  }
  return findings;
}

const MAVEN_DANGEROUS =
  /<artifactId>(exec-maven-plugin|maven-antrun-plugin|groovy-maven-plugin)<\/artifactId>[\s\S]{0,1500}?(curl|wget|<executable>\s*(bash|sh|zsh|powershell|cmd(\.exe)?)\s*<|https?:\/\/\S{1,300}\.(sh|jar|zip|tar|gz|tgz|exe|bin|ps1)\b)/;

/**
 * A shell handed a script from the project's own tree, and nothing fetched.
 * apache/maven runs its path-conversion test that way, which is how a Maven
 * build runs anything at all; the script is judged as the file it is. A
 * shell with no argument to point at, or with a download beside it, is not
 * this shape and keeps its conviction.
 */
const MAVEN_FETCHES = /curl|wget|https?:\/\/\S{1,300}\.(sh|jar|zip|tar|gz|tgz|exe|bin|ps1)\b/;
const MAVEN_OWN_SCRIPT =
  /<argument>\s*(\$\{project\.[\w.]+\}|\.{0,2}\/)[^<]*\.(sh|bash|py|rb|pl)\s*<\/argument>/i;

export function checkMavenPom(path, content) {
  const findings = [];
  const ownScriptOnly = MAVEN_OWN_SCRIPT.test(content) && !MAVEN_FETCHES.test(content);
  if (MAVEN_DANGEROUS.test(content) && !ownScriptOnly) {
    findings.push(
      finding(
        "maven-build-exec",
        "high",
        path,
        matchLocation(content, /exec-maven-plugin|maven-antrun-plugin|groovy-maven-plugin/),
        "This Maven build binds a plugin that runs arbitrary commands (exec, antrun, or groovy) to the build, and the configured command downloads or shells out. Building the project, including an IDE import that triggers a build, executes it.",
        "Do not run mvn or import this project into an IDE. Read the plugin configuration in pom.xml first.",
      ),
    );
  }
  if (/<url>http:\/\/[^<]*<\/url>/.test(content) && /<repositor/i.test(content)) {
    findings.push(
      finding(
        "maven-insecure-repo",
        "medium",
        path,
        matchLocation(content, /<url>http:\/\//),
        "This Maven build resolves dependencies from a repository over plain http, so the artifacts can be swapped in transit. Modern Maven refuses http by default; a build that re-enables it is choosing to be interceptable.",
        "Do not build this project until the repository URL is explained.",
      ),
    );
  }
  return findings;
}

// Editor and container auto-run: hooks that fire on folder open or container start.

/**
 * A command that runs a file the repository ships, rather than a tool from
 * the machine's PATH. In an automatically-run hook that is the whole attack:
 * the editor executes the repo's own program before anyone has read it.
 */
/**
 * A repository-relative path counts as the program only where a program can
 * go: the start of the command, or after an operator that begins a new one.
 * Anywhere else it is an argument, and the program is whatever was named
 * first. "go run ./hack/cmd/format" runs go, and
 * "npx @modelcontextprotocol/server-filesystem ./docs" runs npx with a
 * directory to serve; both were read as running a checked-in program.
 */
const RUNS_CHECKED_IN =
  // The flag cluster is bounded: `(-\S+\s+)*` in front of the rest is two
  // variable runs that re-divide the same text, and a command string comes
  // out of a config file the repository wrote, so it can be as long as it
  // likes. No real flag is sixty characters.
  /(^|\s)(node|sh|bash|zsh|python3?|perl|ruby|php)\s+(-\S{1,60}\s+)*\.?\.?[\w./\\-]*\.(js|mjs|cjs|sh|py|rb|pl|php)\b|(^|[;&|]\s*|\n\s*)\.\/\S+/;

/**
 * A program under node_modules is installed by the package manager, not
 * checked into the repository, so running "./node_modules/.bin/oxfmt" is a
 * project reaching for a dependency it declared. The dependency itself is
 * judged by the manifest and lockfile rules, which is where a poisoned one
 * shows up.
 */
const INSTALLED_DEPENDENCY = /(^|\s|\/)node_modules\//;

const runsCheckedIn = (cmd) => RUNS_CHECKED_IN.test(cmd) && !INSTALLED_DEPENDENCY.test(cmd);

/**
 * The repository-relative programs a command starts, so the scan can read
 * them instead of judging a repository by the shape of its command line. A
 * project running its own linter and a dropper starting a planted binary
 * write the same command; only the program tells them apart.
 */
export function autorunProgramPaths(command) {
  if (typeof command !== "string") return [];
  const out = new Set();
  const add = (raw) => {
    const p = String(raw).replace(/^\.\//, "");
    if (p && !p.startsWith("/") && !p.includes("..")) out.add(p);
  };
  const withExtension = /(\.?\/?[\w./-]+\.(?:js|cjs|mjs|ts|py|sh|rb|pl|php))\b/g;
  const byPath = /(^|\s)(\.\/[\w.-]+(?:\/[\w.-]+)*)/g;
  let m;
  while ((m = withExtension.exec(command)) !== null) add(m[1]);
  while ((m = byPath.exec(command)) !== null) add(m[2]);
  return [...out];
}

/**
 * Environment variables that preload code into the next process started,
 * so a config file that only "sets variables" still runs a repo file.
 * NODE_OPTIONS is normal on its own: --max-old-space-size is memory,
 * "--import tsx" is a package every TypeScript project loads. It is a loader
 * flag pointed at a path or a file that turns it into an injection.
 */
const PRELOAD_ENV =
  /"(LD_PRELOAD|DYLD_INSERT_LIBRARIES|PYTHONSTARTUP)"\s*:\s*"[^"]+"|"NODE_OPTIONS"\s*:\s*"[^"]*--(?:require|import|loader|experimental-loader)[= ]+['"\\\\]*(?:\.{1,2}\/[^"'\s\\\\]*|[^"'\s\\\\]*\.[cm]?[jt]s)\b/i;

export function checkVscodeTasks(path, content) {
  const findings = [];
  // VS Code parses this file, so a key written as \u0072unOn is runOn to it.
  const text = decodeJsonEscapes(content);
  if (/["']runOn["']\s*:\s*["']folderOpen["']/.test(text)) {
    // A task that runs a checked-in file, or downloads, decodes or evals,
    // is the trap. One that opens a shell, runs the TypeScript watcher or an
    // npm script (Apollo Server) is a convenience that still deserves a look.
    const commands = [...text.matchAll(/["']command["']\s*:\s*["']([^"']*)["']/g)].map((m) => m[1]);
    // args as well as command: a shell task routinely puts the payload in
    // args ("command": "sh", "args": ["-c", "curl ... | sh"]), and VS Code
    // runs the two joined, so reading only command saw "sh" and nothing else.
    const args = [...text.matchAll(/["']args["']\s*:\s*\[([^\]]{0,2000})\]/g)].map((m) =>
      [...m[1].matchAll(/["']([^"']*)["']/g)].map((a) => a[1]).join(" "),
    );
    // Joined the way VS Code runs them, per task, when the file parses:
    // "command": "node", "args": ["dist/setup.js"] is one command line, and
    // judged as two halves neither half named a checked-in program, so a
    // folder-open task starting a planted file by a bare relative path was
    // a caution rather than a conviction. The raw halves stay in the list,
    // so a file the parser rejects is judged exactly as before.
    const joined = [];
    const parsed = parseJsonc(text);
    const tasks = parsed.ok && Array.isArray(parsed.value?.tasks) ? parsed.value.tasks : [];
    for (const task of tasks) {
      if (!task || typeof task !== "object") continue;
      for (const t of [task, task.windows, task.linux, task.osx]) {
        if (!t || typeof t !== "object") continue;
        const cmd = typeof t.command === "string" ? t.command : "";
        const rest = Array.isArray(t.args) ? t.args.filter((a) => typeof a === "string").join(" ") : "";
        if (cmd || rest) joined.push(`${cmd} ${rest}`.trim());
      }
    }
    const dangerous = [...commands, ...args, ...joined].some(
      (c) => DANGEROUS_SCRIPT.test(c) || downloadIntoShell(c) || runsCheckedIn(c),
    );
    findings.push(
      finding(
        "vscode-autorun-task",
        dangerous ? "high" : "medium",
        path,
        matchLocation(text, /["']runOn["']\s*:\s*["']folderOpen["']/),
        "This project is configured to run a task automatically the moment you open the folder in VS Code (runOn: folderOpen). You do not have to press anything; opening the repo to look at it is enough to execute the command.",
        "Do not open this folder in VS Code. If you already did, treat your machine as compromised and read https://github.com/chriszemmel/repocanary/blob/main/WHAT-TO-DO-NOW.md.",
      ),
    );
  }
  return findings;
}

export function checkDevcontainer(path, content) {
  const findings = [];
  // devcontainer.json is JSONC by specification: comments and trailing commas
  // are both legal. Stripping only the line comments left the trailing comma,
  // and a document the container tooling accepts then parsed to nothing here,
  // which reported nothing at all.
  const parsed = parseJsonc(decodeJsonEscapes(content));
  const config = parsed.ok && typeof parsed.value === "object" && parsed.value !== null ? parsed.value : null;
  if (config === null) return [unparseableAutorunConfig(path, content, "dev container configuration", "reopening this project in a container")];

  const hookText = (v) => (typeof v === "string" ? v : Array.isArray(v) ? v.join(" ") : JSON.stringify(v ?? ""));

  if (config?.initializeCommand !== undefined) {
    findings.push(
      finding(
        "devcontainer-initialize-command",
        "medium",
        path,
        matchLocation(content, /initializeCommand/),
        "This dev container defines an initializeCommand, which runs on your HOST machine (not inside the container) when the container is created. The container's isolation does not apply to it.",
        "Read the command before reopening this project in a container. If it fetches or decodes anything, walk away.",
      ),
    );
  }
  for (const hook of ["postCreateCommand", "postStartCommand", "postAttachCommand", "onCreateCommand"]) {
    const value = config?.[hook];
    if (value === undefined) continue;
    // A checked-in program left running in the background is a service the
    // container needs: pypsa-at starts a TCP relay for its IDE backend from
    // .devcontainer/relay.py. The file is in the repository and is scanned
    // as one; nohup is the dropper's shape when what it runs is not.
    const text = hookText(value).replace(/\bnohup\s+(?:node|python3?|bash|sh)\s+["']?[\w./-]+\.(?:js|mjs|cjs|py|sh)["']?(?:\s+[\w./=-]+)*\s*(?:>{1,2}\s*[\w./-]+\s*)?(?:2>&1\s*)?&/g, "true");
    if (isDangerousScript(text) || downloadIntoShell(text)) {
      findings.push(
        finding(
          "devcontainer-dangerous-hook",
          "high",
          path,
          matchLocation(content, new RegExp(hook)),
          `This dev container's ${hook} downloads or decodes code and runs it as soon as the container starts. Containers limit the blast radius, but this command still runs with access to the workspace, forwarded credentials, and any mounted folders, before you have reviewed anything.`,
          "Do not reopen this project in a container. Read the hook command in the browser first.",
        ),
      );
    }
  }
  return findings;
}

/**
 * The code of every `python -c` and `node -e` in a file. A Makefile that
 * prints the Python version, checks that pytest imports, or opens the built
 * docs in a browser is running inline code the reader can see in full, and
 * numpy, Pillow and tqdm all do one of those.
 */
function inlinePrograms(content) {
  return [...content.matchAll(/\b(?:python3?\s+-c|node\s+-e)\s+(?:"((?:[^"\\\n]|\\.){0,2000})"|'((?:[^'\\\n]|\\.){0,2000})')/g)].map((m) => m[1] ?? m[2] ?? "");
}

export function checkMakefile(path, content, ownUrls = []) {
  const findings = [];
  const pipe = downloadIntoShell(content, ownUrls);
  if (pipe) {
    findings.push(
      finding(
        "makefile-remote-exec",
        "high",
        path,
        pipe,
        "This Makefile downloads a script and runs it in a shell. A README that says \"just run make\" turns that into remote code execution with your user permissions, and the server can serve different code to different victims.",
        "Do not run make. Fetch the URL yourself with curl -o and read what it serves.",
      ),
    );
  // Shell eval of a substitution, not make's own $(eval ...) function, which
  // every large Makefile uses to define rules.
  // Decoding counts where the output is run: argo-cd reads a Redis
  // password out of a Kubernetes secret with `| base64 -d`. eval counts as
  // a command word, not as the tail of a test name like kpt's fn-eval.
  } else if (
    /base64\s+(-d|--decode)\b[^\n]{0,200}\|\s*(?:sudo\s+)?(?:sh|bash|zsh|dash|python3?|node|perl|ruby|source)\b|(?:^|[\s;&|`@-])(?:eval|sh\s+-c|bash\s+-c)\b[^\n]{0,1200}(?:\$\(|`)[^\n]*base64\s+(-d|--decode)|(?:^|[\s;&|`@-])eval\s[^\n]{0,1200}\$\(/m.test(content) ||
    inlinePrograms(content).some((code) => !literalProgramIsInert(code))
  ) {
    findings.push(
      finding(
        "makefile-obfuscated-command",
        "medium",
        path,
        matchLocation(content, /base64\s+(-d|--decode)|\beval\b.*\$\(|python3?\s+-c|node\s+-e/),
        "This Makefile decodes data or evaluates inline code as part of a target. Build files have no honest reason to hide their commands behind encoding or eval.",
        "Read the target carefully before running any make command in this repository.",
      ),
    );
  }
  return findings;
}

// CI workflows: the pipeline itself as the execution vector.

// One source for the two, so the cheap precondition below cannot drift away
// from the patterns it guards. It is case-insensitive because GitHub Actions
// expressions are: `${{ SECRETS.NPM_TOKEN }}` is valid and means the same
// thing, and a precondition that misses it silently switches off every rule
// underneath it.
const SECRET_PREFIX = "\\$\\{\\{\\s*secrets\\.";
// Bounded and newline-stopped: `[^}]*` ran to end of file on a document with
// no closing brace, and every `${{ secrets.` was another start, which is
// quadratic. A secrets reference never spans a line.
const SECRET_REF = `${SECRET_PREFIX}[^}\\n]{0,200}\\}\\}`;
/**
 * How far past a `curl` these patterns look. Bounded, not `[^\n]*`, because
 * an unbounded run on a line of ten thousand `curl` tokens is rescanned from
 * every one of them, which is quadratic and stalls the scan. A curl command
 * carrying a secret fits in a few hundred characters; beyond that the match
 * would be on a different command anyway.
 */
const SAME_COMMAND = "[^\\n]{0,1200}";
/** One curl argument, quoted or bare, that has a secret inside it. */
const ARG_WITH_SECRET = `("[^"\\n]*${SECRET_REF}[^"\\n]*"|'[^'\\n]*${SECRET_REF}[^'\\n]*'|[^\\s"']*${SECRET_REF}[^\\s"']*)`;
const SECRET_IN_BODY = new RegExp(
  `curl${SAME_COMMAND}\\s(-d|--data(-binary|-raw|-urlencode|-ascii)?|-F|--form(-string)?|-T|--upload-file|--json)\\s+${ARG_WITH_SECRET}`,
  "i",
);
const SECRET_IN_URL = new RegExp(`curl${SAME_COMMAND}https?://[^\\s"'\\n]*${SECRET_REF}`, "i");
const SECRET_PIPED = new RegExp(`${SECRET_REF}${SAME_COMMAND}\\|\\s*curl`, "i");
const SECRET_IN_HEADER = new RegExp(`curl${SAME_COMMAND}\\s(-H|--header|-u|--user)\\s+${ARG_WITH_SECRET}`, "i");

/**
 * Services a workflow ordinarily authenticates to with a secret in a curl
 * header: the GitHub API, package registries, coverage and deploy targets.
 */
const KNOWN_SECRET_TARGETS =
  /(^|\.)(github\.com|githubusercontent\.com|npmjs\.org|codecov\.io|coveralls\.io|slack\.com|vercel\.com|netlify\.com|sentry\.io|heroku\.com|cloudflare\.com|pypi\.org|docker\.io|ghcr\.io|render\.com|fly\.io|railway\.app|sonarcloud\.io|snyk\.io|hf\.co|huggingface\.co)$/i;

/**
 * A secret in a request body, in a URL, or piped into curl is exfiltration
 * (high). A secret in a header or basic auth is how a workflow talks to a
 * deploy target, so that is a caution only when the host is not one of the
 * services workflows ordinarily authenticate to.
 */
/**
 * Does a secret's name say it belongs to the host it is being sent to?
 * ALGOLIA_CRAWLER_ID going to crawler.algolia.com is the credential reaching
 * the service that issued it. A victim only ever holds secrets they created,
 * so a name that matches its destination is one they set up for that service
 * on purpose, which is the opposite of exfiltration.
 */
function secretNamesItsHost(secretName, host) {
  if (!secretName || !host) return false;
  const words = (text, sep) =>
    text
      .toLowerCase()
      .split(sep)
      .filter((w) => w.length >= 4 && !GENERIC_WORDS.has(w));
  const hostWords = words(host, /[.-]/);
  return words(secretName, /[_\-.]/).some((w) => hostWords.includes(w));
}

/**
 * Words that name no particular service, on either side of the comparison.
 * DEPLOY_TOKEN sent to deploy.somewhere.example shares only the fact that
 * both concern deployment, which says nothing about who owns the endpoint.
 * A shared platform name is no better: any repository can host anything on
 * github.io.
 */
const GENERIC_WORDS = new Set([
  "github", "githubusercontent", "gitlab", "amazonaws", "herokuapp", "workers", "vercel", "netlify", "pages",
  "deploy", "deployment", "token", "secret", "apikey", "auth", "prod", "production", "staging", "test", "dev",
  "admin", "user", "users", "data", "cloud", "host", "main", "service", "services", "server", "client", "access",
  "public", "private", "internal", "external", "release", "build", "config", "webhook", "hooks", "http", "https",
  "example", "local", "storage", "bucket", "registry", "npmjs", "docker",
]);

/** Cheap: no `${{ secrets.` in the file means none of the patterns below can match. */
const MENTIONS_SECRET = new RegExp(SECRET_PREFIX, "i");

function secretIntoCurl(content) {
  // The patterns below look a long way past a `curl` for the argument that
  // carries the secret, which is what they have to do and what makes them
  // expensive on a file that is nothing but `curl` tokens. Asking the cheap
  // question first means the expensive one is only asked where it can be
  // answered yes: a workflow that mentions a secret at all.
  if (!MENTIONS_SECRET.test(content)) return null;
  for (const re of [SECRET_IN_BODY, SECRET_IN_URL, SECRET_PIPED]) {
    if (!re.test(content)) continue;
    // Check the line the secret is on: if it names its own destination, it
    // is authenticating rather than being shipped somewhere it does not
    // belong. Anything else keeps the conviction.
    const hit = [...logicalLines(content)].find(({ text }) => re.test(text));
    const name = hit?.text.match(/secrets\.([A-Z0-9_]+)/i)?.[1] ?? null;
    let host = null;
    try {
      const url = hit?.text.match(/https?:\/\/[^\s"'`]+/i);
      host = url ? new URL(url[0].replace(/\$\{\{[^}]*\}\}/g, "x")).hostname : null;
    } catch {
      host = null;
    }
    if (host && (KNOWN_SECRET_TARGETS.test(host) || secretNamesItsHost(name, host))) continue;
    // Telegram's bot API takes the bot's token in the URL path, so a secret
    // there is the credential of the bot the message goes to, and the chat
    // ID beside it is that bot's recipient. darkweid/fastapi-template alerts
    // on deploys that way. A secret posted to Telegram anywhere else, or to
    // a bot path built from something that is not a secret, keeps the finding.
    if (hit && /api\.telegram\.org\/bot\$\{\{\s*secrets\.[A-Z0-9_]+\s*\}\}\//i.test(hit.text)) continue;
    return { severity: "high", loc: matchLocation(content, re) };
  }
  // The URL often sits on a continuation line below the header flag.
  for (const { text } of logicalLines(content)) {
    const m = text.match(SECRET_IN_HEADER);
    if (!m) continue;
    const url = text.match(/https?:\/\/[^\s"'`]+/i);
    let host = null;
    try {
      host = url ? new URL(url[0]).hostname : null;
    } catch {
      host = null;
    }
    const name = text.match(/secrets\.([A-Z0-9_]+)/i)?.[1] ?? null;
    if (host !== null && (KNOWN_SECRET_TARGETS.test(host) || secretNamesItsHost(name, host))) continue;
    return { severity: "medium", host: host ?? "an unnamed host", loc: matchLocation(content, SECRET_IN_HEADER) };
  }
  return null;
}

export function checkWorkflow(path, content) {
  const findings = [];
  // The runner parses this file, so `run: "\u0063url ..."` is a curl to it.
  // Only double-quoted scalars resolve escapes, which is what the decoder
  // limits itself to; elsewhere the sequence is literally itself.
  content = decodeYamlEscapes(content);

  const hasPrTarget = /\bpull_request_target\b/.test(content);
  const headRef = content.match(/ref:\s*\$\{\{\s*github\.event\.pull_request\.head/);
  if (hasPrTarget && headRef) {
    // Checking out the head is only half the exploit; a step that runs the
    // checked-out code (a run: line, an install, a build) is the other half.
    // A labeler that only reads files after the checkout is a widespread
    // misconfiguration in honest projects, not the trap.
    const after = content.slice(headRef.index);
    const runsCode = /^[^\S\r\n]*-?[^\S\r\n]*run:|\b(npm|yarn|pnpm|pip3?|make|cargo|go)\s+(ci|install|run|build|test)\b/m.test(after);
    findings.push(
      finding(
        "workflow-pwn-request",
        // Medium when the checked-out code runs: that is what a lure asking a
        // candidate to fork and add their own secrets would exploit. A
        // labeler that only reads files after the checkout runs nothing, and
        // is a note.
        runsCode ? "medium" : "low",
        path,
        matchLocation(content, /ref:\s*\$\{\{\s*github\.event\.pull_request\.head/),
        runsCode
          ? "This workflow runs in the repository owner's GitHub Actions with the owner's secrets (pull_request_target) and executes code checked out from whoever opens a pull request. Nothing runs on your machine, but anyone can get their code run with those secrets, and if you were told to fork this repository and add your own secrets, those secrets are the target."
          : "This workflow runs with the repository's secrets (pull_request_target) and checks out code from whoever opens a pull request, though the steps after the checkout do not run that code. Honest projects carry this misconfiguration too; on its own it is a caution, not a conviction.",
        runsCode
          ? "Do not fork this repository with secrets configured, and do not open pull requests against it."
          : "Do not add secrets to a fork of this repository until the workflow is fixed to check out the base branch.",
      ),
    );
  }

  if (/runs-on:\s*\[?\s*["']?self-hosted/.test(content)) {
    findings.push(
      finding(
        "workflow-self-hosted-runner",
        // A note here; scan.js raises it to a caution when the README asks
        // the reader to register a runner, which is the only way this reaches
        // their machine.
        "low",
        path,
        matchLocation(content, /runs-on:\s*\[?\s*["']?self-hosted/),
        "This workflow targets a self-hosted runner, a machine the repo owner controls (or wants to control). If you were told to register a runner for this repo, the workflow would execute the owner's code on your machine.",
        "Never register a self-hosted runner for a repository you do not control.",
      ),
    );
  }

  const secret = secretIntoCurl(content);
  if (secret) {
    findings.push(
      finding(
        "workflow-secret-exfiltration",
        secret.severity,
        path,
        secret.loc,
        secret.severity === "high"
          ? "This workflow puts a repository secret into the body or URL of a curl request. Secrets exist to authenticate actions, not to be posted as data; this is how CI credentials get stolen in bulk."
          : `This workflow sends a repository secret in a curl header to ${secret.host}, which is not a service RepoCanary recognises. Authenticating to a deploy target this way is common, so this is a caution: check that the host is one the project has a reason to talk to.`,
        secret.severity === "high"
          ? "Do not add any secrets to a fork of this repository. Report it to GitHub at https://github.com/contact/report-abuse."
          : "Check what that host is before adding any secrets to a fork of this repository.",
      ),
    );
  }

  const pipe = downloadIntoShell(content);
  if (pipe) {
    findings.push(
      finding(
        "workflow-remote-script",
        // A note: this runs on the CI provider's machines, not on the reader's.
        // Codecov, Codacy and every Actions installer look like this, and it
        // is the maintainers' supply chain rather than a trap for whoever
        // clones the repository.
        "low",
        path,
        pipe,
        "This workflow downloads a script from a non-standard host and runs it in a shell. The server decides what runs, and it can serve different code to CI than to anyone who checks the URL by hand.",
        "Read the fetched script at its URL, and treat the repository as untrusted until it is explained.",
      ),
    );
  }

  return findings;
}

// .npmrc: registry hijack and committed tokens.

export function checkNpmrc(path, content) {
  const findings = [];
  // `[^\S\n]*`, not `\s*`: under /m the anchor is per line, and `\s` matching
  // a newline lets a run of blank lines be re-divided at every position.
  // Every registry line, not the first. Reading only the first match made one
  // ordinary scoped line above the real one the entire bypass, and a scoped
  // entry is unremarkable content for this file. The worst line decides, so a
  // benign one cannot mask a hijack further down.
  let worst = null;
  for (const line of content.matchAll(/^[^\S\r\n]*(@[\w-]+:)?registry\s*=\s*(.+)$/gim)) {
    const url = line[2].trim();
    // registry.npmjs.com is the same registry under its other name;
    // internet-identity-labs maps its own scope to it.
    if (/registry\.npmjs\.(org|com)|registry\.yarnpkg\.com|npm\.pkg\.github\.com|npm\.jsr\.io/i.test(url)) continue;
    // Azure Artifacts, JFrog, GitLab, Cloudsmith and npm mirrors host private
    // or mirrored feeds for whole companies (dotnet's repositories point at
    // an Azure public feed); a caution to read, not a hijack. An unknown
    // host stays a hijack.
    // A private registry is ordinary: every company with a Verdaccio or a
    // Nexus commits the line that points npm at it, and the scanner cannot
    // tell that host from an attacker's by its name. What it can tell is a
    // registry reached over plain http, one at a bare address, or one the
    // file also hands a token to, which is what the hijack looks like and
    // what no honest template commits. The rest is a caution to read.
    const insecure = /^https?:\/\/(?:\d{1,3}\.){3}\d{1,3}\b|^http:\/\//i.test(url);
    const withToken = /_authToken\s*=\s*\S|always-auth\s*=\s*true/i.test(content);
    const severity = insecure || withToken ? "high" : "medium";
    if (worst === null || (worst.severity === "medium" && severity === "high")) {
      worst = { severity, url, text: line[0].trim() };
    }
  }
  if (worst) {
    findings.push(
      finding(
        "npmrc-registry-override",
        worst.severity,
        path,
        locateText(content, worst.text) ?? matchLocation(content, /registry\s*=/i),
        worst.severity === "high"
          ? `This project pins npm to a non-standard registry (${worst.url.slice(0, 60)}) that is reached over plain http, sits at a bare address, or is handed a credential by this same file. Every dependency then installs from whatever that server chooses to serve, regardless of what the names say. This is dependency confusion committed straight into the repo.`
          : `This project pins npm to a non-standard registry (${worst.url.slice(0, 60)}). Companies do this for a private mirror, and an attacker does it so every dependency installs from a server they control; the name alone cannot say which.`,
        worst.severity === "high"
          ? "Do not run npm install with this .npmrc. Check what the configured registry actually serves."
          : "Before npm install, check that the registry belongs to the organisation that sent you this, and what it serves for the package names in package.json.",
      ),
    );
  }
  if (/_authToken\s*=\s*\S/i.test(content)) {
    findings.push(
      finding(
        "npmrc-committed-token",
        "medium",
        path,
        matchLocation(content, /_authToken\s*=/i),
        "This .npmrc contains an npm auth token committed into the repository. If it is real it is a leaked credential; if it points npm at an attacker's registry with a token, it is part of a hijack.",
        "Do not install. Treat any token here as compromised and rotate it.",
      ),
    );
  }
  return findings;
}

// Dockerfile: remote code fetched and run during an image build.

export function checkDockerfile(path, content, ownUrls = []) {
  const findings = [];
  const pipe = downloadIntoShell(content, ownUrls);
  // A root Dockerfile is what "just docker build ." runs. One under docker/,
  // .buildkite/ or apps/x/ is a CI or deployment image (LLVM, .NET and test
  // fixtures get installed that way in honest projects), still worth a look.
  const nested = path.includes("/");
  if (pipe) {
    findings.push(
      finding(
        "dockerfile-remote-exec",
        nested ? "medium" : "high",
        path,
        pipe,
        "This Dockerfile downloads a script and runs it in a shell during the image build. A README that says \"just docker build\" turns that into remote code execution, and the build server decides what runs.",
        "Do not build this image. Fetch the URL yourself and read what it serves.",
      ),
    );
  } else if (/^[^\S\r\n]*ADD\s+https?:\/\//im.test(content)) {
    findings.push(
      finding(
        "dockerfile-remote-add",
        "medium",
        path,
        matchLocation(content, /^[^\S\r\n]*ADD\s+https?:\/\//im),
        "This Dockerfile pulls a file straight from a URL into the image with ADD. Whatever that URL serves at build time ends up baked into the image, with no version pin and no checksum.",
        "Replace the remote ADD with a pinned, checksummed download, and read what the URL currently serves.",
      ),
    );
  }
  return findings;
}

// Package-manager install hooks (.pnpmfile.cjs, .yarnrc.yml plugins) run
// arbitrary code during install, before anything is reviewed.

export function checkInstallHook(path, content) {
  const base = path.split("/").pop();
  const findings = [];
  if (base === ".pnpmfile.cjs") {
    // Spawning "git clean" or "find ... rm" to tidy node_modules (discourse)
    // is housekeeping; spawning next to a URL, a decoder or a temp path is
    // a loader.
    const spawnsLoader = /child_process/i.test(content) && /https?:\/\/|base64|atob\(|\/tmp\/|\beval\b|node\s+-e/i.test(content);
    const dangerous = DANGEROUS_SCRIPT.test(content) || downloadIntoShell(content) !== null || spawnsLoader || /require\s*\(\s*["'`]https?:/i.test(content);
    findings.push(
      finding(
        "pnpm-install-hook",
        dangerous ? "high" : "medium",
        path,
        matchLocation(content, /hooks|readPackage|module\.exports/i) ?? { line: 1, snippet: base },
        dangerous
          ? "This .pnpmfile.cjs runs during every pnpm install and this one spawns programs or fetches code. pnpm executes it automatically, before you review anything, which makes it a perfect install-time payload."
          : "This .pnpmfile.cjs runs during every pnpm install. That is a legitimate pnpm feature for rewriting dependencies, but it is also arbitrary code that executes before you review the project.",
        "Read this file fully before running pnpm install; pnpm runs it automatically.",
      ),
    );
  }
  return findings;
}

// PHP Composer: scripts run automatically during composer install.

// Anchored on the whole key. Unanchored, any key that merely *contained* an
// event name passed, and the key was then compiled into a regex below: a
// manifest could hand the scanner a pattern of its own choosing.
const COMPOSER_INSTALL_EVENTS =
  /^(pre-install-cmd|post-install-cmd|pre-update-cmd|post-update-cmd|post-autoload-dump|pre-autoload-dump)$/;

export function checkComposerJson(path, content) {
  const findings = [];
  const parsed = safeJsonParse(content);
  const scripts = parsed.ok && parsed.value && typeof parsed.value.scripts === "object" ? parsed.value.scripts : null;
  if (!scripts) return findings;
  for (const [event, body] of Object.entries(scripts)) {
    if (!COMPOSER_INSTALL_EVENTS.test(event)) continue;
    const text = Array.isArray(body) ? body.join(" ") : String(body);
    const dangerous =
      DANGEROUS_SCRIPT.test(text) ||
      /@?php\s+-r|proc_open|shell_exec|\bsystem\s*\(|passthru|\beval\s*\(|base64_decode|(file_get_contents|fopen|copy)\s*\(\s*['"]https?:/i.test(text);
    // Low when it is plain, as the npm lifecycle rule already is: every
    // stock Laravel and Symfony manifest runs `@php artisan package:discover`
    // or `@auto-scripts` here, and a caution on the framework's own template
    // teaches people that yellow means nothing. The dangerous shape still
    // convicts, and the file the script invokes is judged on its own.
    findings.push(
      finding(
        "composer-install-script",
        dangerous ? "high" : "low",
        path,
        // locateText, not a compiled pattern: the event name is repository
        // text, and building a regex out of it let the manifest choose the
        // pattern the scanner runs.
        locateText(content, `"${event}"`),
        dangerous
          ? `This PHP project runs a "${event}" script during composer install, and that script downloads, decodes, or executes code. Like an npm install hook, it fires before you review anything.`
          : `This PHP project runs a "${event}" script automatically during composer install, before you review or run anything. Common in real projects, and also the entry point malware uses.`,
        dangerous ? "Do not run composer install. Read the script and what it invokes first." : `Read the "${event}" script before running composer install.`,
      ),
    );
  }
  return findings;
}

// Yarn Berry: yarnPath makes every yarn command run a checked-in file. A
// non-standard yarnPath is a package manager replaced by an arbitrary program.
// Plugins are not flagged: the format checks the plugin in locally and only
// records its origin URL, so a URL there is not remote execution.

// Yarn 1 reads the same hijack from `.yarnrc` as `yarn-path "./prog"`, and
// that file was never fetched: the exact trap this tool catches for Yarn
// Berry was invisible one major version down.
export function checkYarnrcClassic(path, content) {
  const findings = [];
  for (const m of content.matchAll(/^[^\S\r\n]*yarn-path[^\S\r\n]+["']?([^\n"']+)/gim)) {
    const target = m[1].trim();
    if (/\.yarn\/releases\//.test(target)) continue;
    findings.push(
      finding(
        "yarnrc-yarnpath",
        "high",
        path,
        locateText(content, m[0].trim()) ?? matchLocation(content, /yarn-path/i),
        `This project sets yarn-path to "${redactSnippet(target, 80)}", so every yarn command runs that checked-in file instead of the real Yarn. If it is not the standard .yarn/releases bundle, it is an arbitrary program masquerading as your package manager.`,
        "Do not run yarn. Read the file yarn-path points at before trusting any yarn command.",
      ),
    );
    break;
  }
  return findings;
}

export function checkYarnrc(path, content) {
  const findings = [];
  // Every yarnPath, not the first: a nested one under npmScopes placed above
  // the real top-level entry used to be the only one read, and one extra
  // stanza was the whole bypass.
  for (const yarnPath of content.matchAll(/^[^\S\r\n]*yarnPath:\s*["']?([^\n"']+)/gim)) {
    const target = yarnPath[1].trim();
    if (/\.yarn\/releases\//.test(target)) continue;
    findings.push(
      finding(
        "yarnrc-yarnpath",
        "high",
        path,
        locateText(content, yarnPath[0].trim()) ?? matchLocation(content, /yarnPath:/i),
        // Capped: this is repository text on its way into a report, and an
        // unbounded value would carry a file's worth of it.
        `This project sets yarnPath to "${redactSnippet(target, 80)}", so every yarn command runs that checked-in file instead of the real Yarn. If it is not the standard .yarn/releases bundle, it is an arbitrary program masquerading as your package manager.`,
        "Do not run yarn. Read the file yarnPath points at before trusting any yarn command.",
      ),
    );
    break; // one finding per file is enough, but only after every line was read
  }
  return findings;
}

// VS Code settings: tool-path overrides run a repo binary when the editor
// opens, and terminal.env injects variables into every integrated terminal.

const VSCODE_EXEC_PATHS =
  /"(eslint\.nodePath|eslint\.runtime|git\.path|terminal\.integrated\.automationProfile|deno\.path|python\.defaultInterpreterPath|php\.validate\.executablePath|go\.alternateTools|rust-analyzer\.server\.path|typescript\.tsdk|npm\.packageManager)"\s*:\s*"([^"]+)"/g;

export function checkVscodeSettings(path, content) {
  const findings = [];
  // VS Code parses this file, so a key written as git.path is git.path to
  // it and the hijack takes effect either way. The other three readers of
  // auto-run JSON already decoded; this one did not, and one escape was
  // enough to take a tool-path hijack from red to green with no finding at
  // all. Located against either text, the way checkMcpConfig does, because
  // decoding shifts columns and the original is what the reader opens.
  const text = decodeJsonEscapes(content);
  // A fresh copy of the global pattern: exec() on a shared /g regex keeps its
  // lastIndex between calls, so the file scanned after a hit would be read
  // from the middle and the hijack in it missed.
  const re = new RegExp(VSCODE_EXEC_PATHS.source, VSCODE_EXEC_PATHS.flags);
  let m;
  while ((m = re.exec(text)) !== null) {
    const value = m[2];
    // A path inside node_modules is the normal, recommended setup (e.g.
    // typescript.tsdk -> node_modules/typescript/lib, eslint.nodePath ->
    // node_modules). The attack is a checked-in file elsewhere in the repo
    // that the editor then runs as your linter, formatter, or git.
    // .yarn/sdks is the same thing for Yarn Berry: the documented editor SDK
    // location that every Plug'n'Play project checks in.
    // A Python virtualenv is the same thing again: the interpreter path the
    // user creates, never a file the repository can ship.
    const intoNodeModules = /(^|\/)(node_modules|\.yarn\/sdks|\.venv|venv|\.tox)(\/|$)/.test(value);
    if (/^(\.\/|\.\\|[^/\\:][\w./\\-]*\/)/.test(value) && !/^https?:/.test(value) && !intoNodeModules) {
      findings.push(
        finding(
          "vscode-tool-path-hijack",
          "high",
          path,
          locateText(content, m[1]) ?? matchLocation(text, new RegExp(m[1].replace(/[.]/g, "\\."))),
          `This project sets "${m[1]}" to a path inside the repository ("${value}"). When you open the folder, VS Code runs that checked-in file as ${m[1].split(".")[0]}, so a tool you trust is replaced by the repo's own program.`,
          "Do not open this folder in VS Code. Read the file the setting points at first.",
        ),
      );
      break;
    }
  }
  if (/"terminal\.integrated\.env\.[^"]+"\s*:/.test(text)) {
    findings.push(
      finding(
        "vscode-terminal-env",
        "medium",
        path,
        locateText(content, "terminal.integrated.env.") ?? matchLocation(text, /"terminal\.integrated\.env\./),
        "This project injects environment variables into every integrated terminal you open in VS Code. That can preload a malicious NODE_OPTIONS, PATH, or LD_PRELOAD so the next command you run is subverted.",
        "Review these variables before opening a terminal in this project.",
      ),
    );
  }
  return findings;
}

// direnv: .envrc runs automatically the moment you cd into the directory,
// if direnv is installed and the dir is allowed.

export function checkEnvrc(path, content) {
  const findings = [];
  // eval "$shellHook" is nix-direnv boilerplate: evaluating a variable the
  // shell already holds, not fetched or decoded text.
  // eval "$(devenv direnvrc)", eval "$(pyenv init -)": a local tool's own
  // shell integration, which is how devenv, pyenv and nix document it. A
  // substitution that downloads keeps the finding.
  const withoutVarEval = content
    .replace(/\beval\s+"?\$\{?\w+\}?"?/g, "")
    .replace(/\beval\s+"\$\(\s*(?!curl|wget|base64)[\w.-]+(?:\s+[\w.=-]+){0,4}\s*\)"/g, "");
  const dangerous = DANGEROUS_SCRIPT.test(withoutVarEval) || downloadIntoShell(content);
  findings.push(
    finding(
      "direnv-envrc",
      dangerous ? "high" : "low",
      path,
      matchLocation(content, /./) ?? { line: 1, snippet: "" },
      dangerous
        ? "This .envrc runs automatically when you cd into the folder (if direnv is installed), and this one downloads, decodes, or executes code. It fires before you open a single file."
        : "This .envrc runs automatically when you cd into the folder if you use direnv. Usually it just sets environment variables, but it is arbitrary shell that executes on entry.",
      dangerous ? "Do not cd into this folder with direnv enabled. Read .envrc first." : "Read .envrc before allowing direnv for this folder.",
    ),
  );
  return findings;
}

// AI editor configuration: MCP servers and agent hooks. A repository can
// ship these, and the editor starts the processes they name when the folder
// is opened, with no install step and no file for the victim to click.

/**
 * Locate a literal string from the file being scanned. Building a regex out
 * of repository text would let the repository write the pattern, so these
 * rules search for the text itself.
 */
function locateText(content, needle) {
  const index = content.indexOf(needle);
  if (index === -1) return null;
  return {
    line: lineOfIndex(content, index),
    snippet: redactSnippet(content.slice(Math.max(0, index - 40), index + needle.length + 140)),
  };
}

/**
 * Every server entry across the shapes the editors use, as name + command
 * line. Null, not an empty array, when the document could not be parsed:
 * "no servers declared" and "this file was unreadable" are different answers
 * and the caller has to be able to tell them apart.
 */
export function mcpServers(content) {
  const parsed = parseJsonc(content);
  if (!parsed.ok || typeof parsed.value !== "object" || parsed.value === null) return null;
  const tables = ["mcpServers", "servers", "context_servers"]
    .map((k) => parsed.value[k])
    .filter((t) => t && typeof t === "object");
  const servers = [];
  for (const table of tables) {
    for (const [name, entry] of Object.entries(table)) {
      if (!entry || typeof entry !== "object") continue;
      const args = Array.isArray(entry.args) ? entry.args.filter((a) => typeof a === "string") : [];
      const command = typeof entry.command === "string" ? entry.command : "";
      if (!command) continue;
      servers.push({ name, command: [command, ...args].join(" ") });
    }
  }
  return servers;
}

export function checkMcpConfig(path, content) {
  // The editor parses this file, so a key written as \u0063ommand is command
  // to it, and the server it declares starts either way.
  const text = decodeJsonEscapes(content);
  const servers = mcpServers(text);
  // A document the editor will act on and this could not read is not a
  // document with no servers in it, and reporting the two the same way made
  // one trailing comma the whole bypass.
  if (servers === null) return [unparseableAutorunConfig(path, content, "MCP server configuration", "opening this folder in an AI editor")];
  if (servers.length === 0) return [];
  const armed = servers.find(
    (s) => isDangerousScript(s.command) || downloadIntoShell(s.command) || runsCheckedIn(s.command),
  );
  const preload = PRELOAD_ENV.test(text);
  if (armed || preload) {
    // A server that starts a program from the repository is the trap's shape
    // and also how a project ships its own tooling. The command cannot tell
    // them apart, so the program it names travels with the finding and
    // scan.js reads it: a program it read and found clean relaxes this to a
    // caution, and one it could not read stays high.
    const startsLocal = armed && runsCheckedIn(armed.command) && !isDangerousScript(armed.command);
    const what = armed
      ? `the "${armed.name}" server ${startsLocal ? "starts a program checked into this repository" : "downloads, decodes, or executes code"}`
      : "it preloads code into every server process through the environment";
    return [
      finding(
        "mcp-server-autostart",
        "high",
        path,
        (armed
          ? (locateText(content, `"${armed.name}"`) ?? locateText(text, `"${armed.name}"`))
          : matchLocation(text, PRELOAD_ENV)) ?? { line: 1, snippet: "" },
        `This repository ships an MCP server configuration, and ${what}. Your editor starts these servers on its own when you open the folder in Cursor, VS Code, or Claude Code, so no install step and no README instruction is needed for it to run.`,
        "Do not open this folder in an AI editor. Read the command this server starts in the browser first.",
        startsLocal ? { programs: autorunProgramPaths(armed.command) } : undefined,
      ),
    ];
  }
  return [
    finding(
      "mcp-server-autostart",
      "low",
      path,
      matchLocation(text, /"(mcpServers|servers|context_servers)"/) ?? { line: 1, snippet: "" },
      `This repository configures ${servers.length === 1 ? "an MCP server" : `${servers.length} MCP servers`} (${servers
        .map((s) => s.name)
        .slice(0, 3)
        .join(", ")}). Your editor launches these as local processes when you open the folder, without asking, so the repository chooses a program that runs on your machine.`,
      "Read what each server command starts before opening this folder in an AI editor.",
    ),
  ];
}

/** Command strings an agent-hook config tells the editor to run for you. */
export function checkAgentHooks(path, content) {
  // The agent parses this file, so a key written as \u0068ooks is hooks to it.
  const text = decodeJsonEscapes(content);
  if (!/"hooks"/.test(text) && !PRELOAD_ENV.test(text)) return [];
  const commands = [...text.matchAll(/"command"\s*:\s*"((?:[^"\\]|\\.)*)"/g)].map((m) => ({
    raw: m[1],
    cmd: m[1].replace(/\\(["\\/])/g, "$1"),
  }));
  const armed = commands.find(
    ({ cmd }) => isDangerousScript(cmd) || downloadIntoShell(cmd) || runsCheckedIn(cmd),
  );
  const preload = PRELOAD_ENV.test(text);
  if (armed || preload) {
    // Running a program from the repository is how a project lints and tests
    // itself, and it is also the trap. The command cannot say which, so the
    // program travels with the finding for scan.js to read: clean relaxes
    // this to a caution, unreadable keeps it high.
    const runsLocal = armed && runsCheckedIn(armed.cmd) && !isDangerousScript(armed.cmd);
    return [
      finding(
        "agent-hook-autorun",
        "high",
        path,
        (armed ? (locateText(content, armed.raw) ?? locateText(text, armed.raw)) : matchLocation(text, PRELOAD_ENV)) ??
          { line: 1, snippet: "" },
        armed
          ? `This repository ships agent hooks, and one of them ${
              runsLocal ? "runs a program checked into this repository" : "downloads, decodes, or executes code"
            }. Hooks fire on their own while your coding agent works in the folder; you never approve the command, and there is nothing to install first.`
          : "This repository's agent configuration preloads code through the environment, so every process your coding agent starts in this folder loads a file the repository chose. Nothing has to be installed for it to take effect.",
        armed
          ? "Do not open this folder in an AI coding agent. Read the hook commands in the browser first."
          : "Do not open this folder in an AI coding agent. Read the environment block, and the file it preloads, in the browser first.",
        runsLocal ? { programs: autorunProgramPaths(armed.cmd) } : undefined,
      ),
    ];
  }
  if (commands.length === 0) return [];
  return [
    finding(
      "agent-hook-autorun",
      "low",
      path,
      matchLocation(text, /"hooks"/) ?? { line: 1, snippet: "" },
      `This repository defines ${commands.length === 1 ? "a hook command" : `${commands.length} hook commands`} for AI coding agents. These run automatically as the agent works, so the repository, not you, decides what gets executed in this folder.`,
      "Read the hook commands before opening this folder in an AI coding agent.",
    ),
  ];
}

// Emacs and Neovim load per-directory configuration the moment you open a
// file there. No install, no command: the editor sources the repo's file.

/**
 * An eval form whose body only sets a property or a variable to literal
 * values is configuration written in elisp, not code: `put` and `setq`
 * cannot start a process, read a file or reach the network. Clojure projects
 * carry dozens of them to teach Emacs how to indent their macros, and
 * metabase's .dir-locals.el is thirty-three lines of exactly that.
 */
const DIR_LOCALS_SETTING =
  /^\(\s*(put|setq|setq-default|setq-local|set|setenv|add-to-list|add-hook|remove-hook|defvar|push|make-local-variable)\b[^()]*(\([^()]*\)[^()]*)*\)$/;

/**
 * The elisp that reaches outside the editor: starting a process, running a
 * shell command, fetching a URL, loading or writing a file. An eval form
 * that only wires a hook or computes a path is still code the editor runs
 * on open, so it stays reported as a caution; one that does any of these is
 * the trap.
 */
const DIR_LOCALS_RUNS =
  /\((?:start-process|call-process(?:-shell-command|-region)?|shell-command(?:-to-string)?|async-shell-command|make-process|process-lines|url-retrieve(?:-synchronously)?|url-copy-file|load-file|load|require|make-network-process|open-network-stream|write-region|delete-file|delete-directory|rename-file|copy-file|byte-compile-file|compile|eshell-command|shell)\s/;

const evalForms = (content) =>
  [...content.matchAll(/\(\s*eval\s*\.\s*(\((?:[^()]|\([^()]*\))*\))/g)].map((m) => m[1]);

export function checkDirLocals(path, content) {
  // A dir-local `eval` form is arbitrary elisp attached to the directory.
  // Everything else in the file sets variables.
  if (!/\(\s*eval\s/.test(content)) return [];
  const forms = evalForms(content);
  if (forms.length > 0 && forms.every((f) => DIR_LOCALS_SETTING.test(f.trim()))) return [];
  // A form the parser could not isolate is judged on the whole file, so a
  // deeply nested one cannot hide a process call from this test.
  const runs = forms.length > 0 ? forms.some((f) => DIR_LOCALS_RUNS.test(f)) : DIR_LOCALS_RUNS.test(content);
  return [
    finding(
      "emacs-dir-locals-eval",
      runs ? "high" : "medium",
      path,
      matchLocation(content, /\(\s*eval\s/) ?? { line: 1, snippet: "" },
      runs
        ? "This .dir-locals.el attaches an eval form to the directory, which is arbitrary Emacs Lisp that runs when you open a file here, and this one starts a process, runs a shell command, fetches a URL or loads a file. Emacs asks before evaluating an unsafe form, but the prompt appears while you are opening a file you meant to read, and answering yes runs the code."
        : "This .dir-locals.el attaches an eval form to the directory, which is arbitrary Emacs Lisp that runs when you open a file here. This one wires a hook or sets something up rather than starting a process, which is what a project's own editor setup looks like, but Emacs will ask you to trust it and it is still the repository choosing what runs.",
      runs
        ? "Do not open files from this repository in Emacs, and never mark this form safe. Read the eval form in the browser first."
        : "Read the eval form in the browser before opening files from this repository in Emacs, and do not mark it safe without understanding it.",
    ),
  ];
}

// The `[^\S\n]*` is indentation, deliberately not `\s*`: `\s` matches a
// newline, so `(^|\n)\s*` lets the run of blank lines be re-divided at every
// position, and a file of a hundred thousand newlines takes seventeen seconds
// to fail. A scanner that can be stalled by a file it is asked to read is a
// scanner an attacker can switch off.
const VIM_SHELLS_OUT =
  /\b(os\.execute|io\.popen|loadstring|vim\.fn\.(system|systemlist|jobstart)|vim\.(loop|uv)\.spawn|vim\.cmd\s*\(?\s*["'][^"']*!)|(^|\n)[^\S\n]*(silent[^\S\n]*!|![^\S\n]*\S)|\bsystem\s*\(/;

// A key binding runs when someone presses the key, which is a decision, not
// the file being sourced. sst binds a build-and-run command that way.
const VIM_KEYMAP = /\b(vim\.keymap\.set|nvim_set_keymap|vim\.api\.nvim_set_keymap)\b/;

/**
 * A system() or systemlist() call whose command is a read-only question to
 * a tool on PATH: `git rev-parse --show-toplevel`, `rg --files`, `npm root`.
 * Half of all project-local Neovim configs open with one of these to find
 * the project root. A command that names a repository path, pipes, or
 * fetches anything is not this shape and keeps its conviction.
 */
const VIM_TOOL_QUERY =
  /vim\.fn\.system(?:list)?\s*\(\s*(?:\{\s*)?["'](?:git|rg|fd|find|which|command|npm|yarn|pnpm|node|python3?|go|cargo|rustup|uname|pwd|realpath|readlink|ls|hostname|env|echo|test|ruby|java)["' ](?:[^)\n]*?)\)/;
const VIM_UNSAFE_ARGS = /\.\/|\$\(|`|\||\bcurl\b|\bwget\b|https?:\/\/|\beval\b|\bsh\s+-c\b|\bbash\s+-c\b/i;

function vimQueriesOnly(content) {
  const shells = [...content.matchAll(new RegExp(VIM_SHELLS_OUT.source, "g"))];
  if (shells.length === 0) return false;
  return shells.every((m) => {
    const call = content.slice(m.index, m.index + 200);
    const q = call.match(VIM_TOOL_QUERY);
    return q !== null && !VIM_UNSAFE_ARGS.test(q[0]);
  });
}

export function checkEditorRc(path, content) {
  const base = path.split("/").pop();
  const bound =
    VIM_SHELLS_OUT.test(content) &&
    !DANGEROUS_SCRIPT.test(content) &&
    !downloadIntoShell(content) &&
    everyMatchInContext(content, VIM_SHELLS_OUT, VIM_KEYMAP, "statement");
  const queries =
    !bound && VIM_SHELLS_OUT.test(content) && !DANGEROUS_SCRIPT.test(content) && !downloadIntoShell(content) && vimQueriesOnly(content);
  if (queries) {
    return [
      finding(
        "editor-rc-autorun",
        "medium",
        path,
        matchLocation(content, VIM_SHELLS_OUT) ?? { line: 1, snippet: "" },
        `Neovim sources ${base} from the project directory itself (the 'exrc' option), and this one shells out, but only to ask a tool on your PATH a question, such as where the repository root is. That is what a project's own editor setup looks like; it is still the repository deciding what runs when you open it.`,
        `Read the commands in ${base} before opening this repository in Neovim with 'exrc' enabled.`,
      ),
    ];
  }
  const dangerous =
    !bound && (VIM_SHELLS_OUT.test(content) || DANGEROUS_SCRIPT.test(content) || Boolean(downloadIntoShell(content)));
  if (bound) {
    return [
      finding(
        "editor-rc-autorun",
        "medium",
        path,
        matchLocation(content, VIM_KEYMAP) ?? { line: 1, snippet: "" },
        `Neovim sources ${base} from the project directory itself (the 'exrc' option). Every command it shells out with is behind a key binding, so it runs when you press that key rather than when the folder opens, which is what a project's own editor setup looks like. It is still the repository choosing what that key does.`,
        `Read the bindings in ${base} before using them, and do not trust this file if Neovim prompts you.`,
      ),
    ];
  }
  return [
    finding(
      "editor-rc-autorun",
      dangerous ? "high" : "low",
      path,
      matchLocation(content, dangerous ? VIM_SHELLS_OUT : /\S/) ?? { line: 1, snippet: "" },
      dangerous
        ? `Neovim sources ${base} from the project directory itself (the 'exrc' option), and this one shells out or executes code. Opening the repository in an editor is enough to run it; nothing is installed and no file is opened by hand.`
        : `Neovim sources ${base} from the project directory itself if you enable the 'exrc' option, so this repository ships editor configuration that runs when you open it here. This one does not shell out, but it is code, not settings.`,
      dangerous
        ? `Do not open this repository in Neovim with 'exrc' enabled, and do not trust it if prompted. Read ${base} in the browser first.`
        : `Read ${base} before opening this repository in Neovim with 'exrc' enabled.`,
    ),
  ];
}

// docker-compose: a service command or build that fetches and runs code.

export function checkDockerCompose(path, content, ownUrls = []) {
  const findings = [];
  const pipe = downloadIntoShell(content, ownUrls);
  if (pipe) {
    findings.push(
      finding(
        "compose-remote-exec",
        "high",
        path,
        pipe,
        "This Compose file runs a service that downloads a script and runs it in a shell. A README that says \"docker compose up\" turns that into remote code execution.",
        "Do not run docker compose up. Read what the command fetches first.",
      ),
    );
  }
  return findings;
}

// Ruby: native gem build (extconf.rb) and Rakefile run at gem install time.

/**
 * Ruby source with its trailing comments blanked, offsets preserved.
 *
 * withoutCommentLines only blanks lines that are nothing but a comment,
 * which is the safe general rule; here the comment sits after code, and it
 * matters because backticks mean two different things on either side of the
 * "#". sinatra's Rakefile reads `Minitest::TestTask.create # Default \`test\`
 * task`, where the backticked word is markdown emphasis in a sentence, and
 * it was read as a shell command.
 *
 * The scan tracks quotes and backticks so a "#" inside a string, a comment
 * marker inside a command, or Ruby's own #{} interpolation cannot end a line
 * early. It does not know about heredocs or %w() literals, so it can still
 * blank something that is not a comment -- which costs a signal rather than
 * inventing one, the direction this has to fail in.
 */
function withoutRubyComments(content) {
  const out = content.split("");
  let i = 0;
  while (i < content.length) {
    const ch = content[i];
    if (ch === "\n") {
      i += 1;
      continue;
    }
    if (ch === '"' || ch === "'" || ch === "`") {
      const quote = ch;
      i += 1;
      while (i < content.length && content[i] !== quote && content[i] !== "\n") {
        if (content[i] === "\\") i += 1;
        i += 1;
      }
      i += 1;
      continue;
    }
    if (ch === "#") {
      while (i < content.length && content[i] !== "\n") {
        out[i] = " ";
        i += 1;
      }
      continue;
    }
    i += 1;
  }
  return out.join("");
}

export function checkRubyBuild(path, content) {
  const base = path.split("/").pop();
  const findings = [];
  // Running commands is what extconf.rb is for: it probes the compiler and
  // writes a Makefile, so every genuine C extension shells out. A fetch
  // beside that exec is the dropper, the same reading setup.py and build.rs
  // already get.
  const runs = /`[^`]*`|system\s*\(|%x\{|IO\.popen|Open3\.|Kernel\.exec/;
  // `\S{1,300}`, not `\S+`: this one is tested against the whole file, and an
  // unbounded run in front of an extension list is rescanned from every
  // "http://" on a long line with no spaces in it. Same bound and same reason
  // as DANGEROUS_SCRIPT at the top of this file.
  const fetches = /Net::HTTP|open-uri|URI\.open|\b(curl|wget)\b|https?:\/\/\S{1,300}\.(sh|rb|py|zip|tar|gz|tgz|exe|bin)\b/;
  const exec = new RegExp(`${runs.source}|${fetches.source}`);
  // A gemspec asks git which files it should package; a Rakefile asks git
  // who wrote the release notes. `git ls-files -z` is in the file bundler's
  // own `bundle gem` template generates, so every gem in existence carries
  // it, and jekyll/minima and sinatra were both cautioned for it. A git
  // query reads the checkout and runs nothing from it, which is the thing
  // this rule is about: a shell injected through #{} into one of these
  // arguments is a bug in the Rakefile, not a dropper, and nothing here
  // would have caught it anyway.
  //
  // Comments go too, and for a plainer reason: sinatra's Rakefile says
  // "# Default `test` task", and a word in backticks inside a comment was
  // read as a command.
  const GIT_QUERY = /`\s*git\s+(ls-files|shortlog|log|rev-parse|rev-list|describe|show-ref|for-each-ref|config\s+--get|status|diff|tag|branch|remote)\b[^`]*`/g;
  // A require states that a file may use a library; it is not a use. This
  // is the same reading import declarations already get in code.js.
  // sinatra-contrib's Rakefile opens with `require 'open-uri'` and then
  // never opens a URI -- the only File.open calls in it write the gemspec
  // it just built -- and the stale require was the whole of the finding.
  const REQUIRE_LINE = /^[ \t]*require(_relative)?\s+["'][^"']*["'][ \t]*$/gm;
  // The same for any named toolchain program: concurrent-ruby's Rakefile
  // asks `which`, turbo-rails runs `bundle install`, sidekiq runs
  // `bundle exec herb`. And backticks inside a quoted string are Markdown in
  // a gemspec's description, as in gitlab's auto_freeze.
  const TOOL_CALL = new RegExp(`\`\\s*${KNOWN_LOCAL_TOOL}\\b[^\`]*\`|\\bsystem\\s*\\(\\s*["']${KNOWN_LOCAL_TOOL}\\b[^"']*["']`, "g");
  const QUOTED_BACKTICKS = /"[^"\n]*`[^`"\n]*`[^"\n]*"/g;
  const built = withoutRubyComments(withoutCommentLines(content, path))
    .replace(REQUIRE_LINE, (m) => " ".repeat(m.length))
    .replace(GIT_QUERY, (m) => " ".repeat(m.length))
    .replace(TOOL_CALL, (m) => " ".repeat(m.length))
    .replace(QUOTED_BACKTICKS, (m) => " ".repeat(m.length));
  if ((base === "extconf.rb" || base === "Rakefile" || base === "rakefile" || /\.gemspec$/.test(base)) && exec.test(built)) {
    // A download handed to a build recipe together with a checksum cannot be
    // swapped, which is the same reading a pinned sha256sum gets in a shell
    // script. nokogiri fetches zlib and libxml2 this way and passes the
    // hashes from its dependencies file. It stays a caution rather than
    // clearing, because a checksum fixes the bytes without vouching for them.
    const verified = /\b(sha256|sha512|checksum)\s*[:=]/i.test(content);
    const dangerous = base === "extconf.rb" && fetches.test(built) && !verified;
    findings.push(
      finding(
        "ruby-build-exec",
        dangerous ? "high" : "medium",
        path,
        matchLocation(built, dangerous ? fetches : exec),
        `This Ruby ${base === "extconf.rb" ? "native-extension build script (extconf.rb)" : base} ${dangerous ? "reaches the network while it builds" : "shells out or reaches the network"}. extconf.rb runs automatically when the gem is installed, and a Rakefile runs when you type rake, so this executes before you review anything.${dangerous ? "" : " Probing the compiler is what a native extension's build script does, so this is a caution rather than a conviction."}`,
        "Do not install this gem or run rake. Read this file in the browser first.",
      ),
    );
  }
  return findings;
}

// README: an install-first layout that front-runs review.

export function checkReadme(path, content) {
  const findings = [];

  // ClickFix: an instruction to paste a shell command in order to "fix" a
  // fake error, CAPTCHA, or verification step. The deception is telling the
  // victim the command is a remedy, so they run it without reading it. This
  // scans the whole README, not just the head, since the fake error is often
  // in a troubleshooting section.
  const clickfix = content.match(
    /(if you (see|get|encounter)[^\n]{0,60}(error|captcha|verif|not working|blank)|to (fix|resolve|verify|continue)[^\n]{0,60}(run|paste|execute)|having (trouble|issues))[\s\S]{0,240}(powershell(\.exe)?[^\n]{0,40}(\s-\w|iex\b|iwr\b|invoke-)|iwr\b|iex\b|invoke-expression|curl[^\n]{0,60}\|\s*(sh|bash)|bash\s+-c\s+["']?\$\(|cmd(\.exe)?\s+\/c)/i,
  );
  // The payload half has to be a command, not the word "powershell". The
  // trick is a fake problem plus an instruction to run something, and
  // winget-cli's README saying "if you get an error about missing framework
  // packages" a couple of paragraphs above a "## PowerShell Module" heading
  // is neither. It was red, behind an expected-red line reading "a package
  // manager", which is not what the finding said.
  //
  // "Having trouble? curl https://bun.sh/install | bash" is a real project's
  // troubleshooting section when the URL is an established installer.
  const clickfixCommand = clickfix ? (clickfix[0].match(/(curl|wget)[^\n]*/i)?.[0] ?? "") : "";
  if (clickfix && !allUrlsAreKnownInstallers(clickfixCommand)) {
    findings.push(
      finding(
        "readme-clickfix",
        "high",
        path,
        matchLocation(content, /(powershell|iwr\b|iex\b|invoke-expression|curl[^\n]{0,60}\|\s*(sh|bash)|bash\s+-c)/i),
        "The README tells you to paste a shell command to fix an error, pass a CAPTCHA, or verify something. That framing is the ClickFix social-engineering trick: the fake problem exists only to get you to run the command, which is the attack.",
        "Do not run any command a README offers as a fix for an error. Read what it actually does first.",
      ),
    );
  }

  const head = content.split("\n").slice(0, 12).join("\n");
  const fencedCommand = head.match(/```[a-z]*\s*\n?\s*((npm|pnpm|yarn|bun)\s+(install|i\b|ci)|pip3?\s+install|curl[^\n]{0,1200}\|)/);
  if (fencedCommand) {
    findings.push(
      finding(
        "readme-install-first",
        "low",
        path,
        matchLocation(content, /```[a-z]*\s*\n?\s*(npm|pnpm|yarn|bun|pip3?|curl)/),
        "The README tells the reader to install or run something within its first lines, before explaining what the project is. Legitimate projects lead with what the code does; lures lead with the step that triggers the payload.",
        "Read the whole repository before running any command the README suggests.",
      ),
    );
  }
  return findings;
}
