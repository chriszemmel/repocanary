/**
 * The signature tables: patterns specific enough to name a technique, each
 * with the reason it matters and what to do about it.
 *
 * HIGH_SIGNATURES convict on their own; MED_SIGNATURES are a caution. The
 * rules that apply them, and decide where they may fire, live in code.js.
 */

import { lineOfIndex, redactSnippet } from "./textutil.js";

/**
 * Filesystem paths to on-disk wallet, browser, and keychain DATA. Reading
 * these is theft. This is deliberately NOT the same as an app talking to a
 * wallet (window.ethereum, a "Connect MetaMask" button), which is normal
 * dapp UX.
 */
export const WALLET_FS_PATTERNS = [
  { re: /Local Extension Settings/i, label: "browser wallet-extension data folder" },
  { re: /Sync Extension Settings/i, label: "browser extension-sync data folder" },
  // Case-sensitive, like Web Data and Local State below: the file is named
  // "Login Data", and a C# service throwing "Login data cannot be null." is
  // validating a form, not opening Chrome's password store.
  { re: /Login Data/, label: "Chrome saved-passwords database" },
  { re: /\bWeb Data\b/, label: "Chrome autofill and cards database" },
  { re: /\bLocal State\b/, label: "Chrome key store (used to decrypt saved cookies and passwords)" },
  { re: /Local Storage[\\/]+leveldb/i, label: "browser Local Storage database" },
  { re: /wallet\.dat/i, label: "Bitcoin wallet file" },
  { re: /exodus\.wallet/i, label: "Exodus wallet file" },
  { re: /electrum[\\/]+wallets|(^|[^A-Za-z_])default_wallet(?![A-Za-z_])/i, label: "Electrum wallet file" },
  { re: /login\.keychain|Library\/Keychains|security\s+(find|dump)-[a-z-]*(password|keychain)/i, label: "macOS Keychain" },
  { re: /solana\/id\.json/i, label: "Solana keypair file" },
  { re: /\.ssh[\\/]+id_(rsa|ed25519|ecdsa)/i, label: "private SSH key" },
  { re: /\.aws[\\/]+credentials/i, label: "AWS credentials file" },
  { re: /\.config[\\/]+gcloud/i, label: "Google Cloud credentials directory" },
  { re: /\.azure[\\/]+(accessTokens|azureProfile)/i, label: "Azure credentials file" },
  { re: /\.docker[\\/]+config\.json/i, label: "Docker registry credentials" },
  { re: /\.kube[\\/]+config/i, label: "Kubernetes cluster credentials" },
  { re: /\.npmrc\b[^\n]{0,40}_authToken|_authToken[^\n]{0,40}\.npmrc/i, label: "npm auth token" },
  // The directory holds the keyring and also four configuration files that
  // say nothing about keys. LightGBM's R CI appends "disable-ipv6" to
  // ~/.gnupg/dirmngr.conf so apt-key can reach a keyserver, and that read as
  // reaching for the private keyring. A copy of the directory itself still
  // matches: the lookahead only excludes the named config files.
  {
    re: /\.gnupg[\\/]+(?!(?:gpg|dirmngr|gpg-agent|scdaemon)\.conf\b)/i,
    label: "GnuPG private keyring",
  },
  { re: /\.config\/(google-chrome|BraveSoftware|chromium)/i, label: "browser profile directory" },
  {
    re: /Library\/Application Support\/(Google\/Chrome|BraveSoftware|Microsoft Edge|Exodus|com\.operasoftware)/i,
    label: "macOS browser and wallet data directory",
  },
  {
    re: /AppData[\\/]+(Local|Roaming)[\\/]+(Google|BraveSoftware|Microsoft[\\/]+Edge)/i,
    label: "Windows browser data directory",
  },
];

/**
 * Exact Chrome/Chromium wallet-extension IDs (each a 32-char [a-p] string).
 * A hardcoded wallet-extension ID inside an interview-task file is
 * essentially only ever a crypto-stealer reaching into that extension's
 * on-disk storage.
 */
export const WALLET_EXTENSION_IDS = [
  { id: "nkbihfbeogaeaoehlefnkodbefgpgknn", label: "MetaMask" },
  { id: "fhbohimaelbohpjbbldcngcnapndodjp", label: "Binance Wallet" },
  { id: "hnfanknocfeofbddgcijnmhnfnkdnaad", label: "Coinbase Wallet" },
  { id: "ibnejdfjmmkpcnlpebklmnkoeoihofec", label: "TronLink" },
  { id: "bfnaelmomeimhlpmgjnjophhpkkoljpa", label: "Phantom" },
  { id: "aeachknmefphepccionboohckonoeemg", label: "Coin98" },
  { id: "hifafgmccdpekplomjjkcfgodnhcellj", label: "Crypto.com Wallet" },
  { id: "jblndlipeogpafnldhgmapagcccfchpi", label: "Kaikas" },
  { id: "acmacodkjbdgmoleebolmdjonilkdbch", label: "Rabby" },
  { id: "dlcobpjiigpikoobohmabehhmhfoodbb", label: "Argent X" },
  { id: "aholpfdialjgjfhomihkjbmgjidlcdno", label: "Exodus Web3" },
  { id: "hdokiejnpimakedhajhdlcegeplioahd", label: "LastPass" },
];
export const WALLET_EXTENSION_ID_RE = new RegExp(WALLET_EXTENSION_IDS.map((w) => w.id).join("|"), "i");

/**
 * High-specificity code signatures: patterns that are essentially only ever
 * malware, so a single match in hand-authored code is a red flag. Kept as a
 * table so the set is easy to audit and grow.
 */
export const HIGH_SIGNATURES = [
  {
    // technique: staged loader: runs code fetched at run time via eval, require, or new Function
    id: "remote-code-execution",
    // The exception is the CommonJS wrapper triple. Parcel, Browserify and
    // webpack all construct each bundled module with the argument list
    // "require", "module", "exports" followed by its code, so that exact
    // triple is a module loader rather than a payload loader. Any other
    // dynamic construction naming "require" still convicts, in a bundle or
    // anywhere else. (Spelling the call out here would trip the invariant
    // test that forbids this scanner from building code from strings.)
    re: /new\s+Function\s*\(\s*["'`]require["'`](?!\s*,\s*["'`]module["'`]\s*,\s*["'`]exports["'`])|Function\s*\.\s*constructor\s*\(\s*["'`]require|\b(eval|require)\s*\(\s*(res(ponse)?|r)\s*\.\s*(data|body|text)\b|\b(eval|require)\s*\(\s*await\b/i,
    why: "This code takes text it fetched from the internet and runs it as a program (via eval, require, or new Function). That means the visible source is only a loader; the real payload arrives, unseen, at run time. This is the core trick of fake-interview malware.",
    next: "Do not run this repository under any circumstances. Report it to GitHub at https://github.com/contact/report-abuse.",
    // The rule is about a payload that arrives unseen. A body that is a
    // string literal doing nothing but returning require() or import() of a
    // literal module name arrives with the source and hides nothing: it is
    // the indirect-require idiom libraries use so a bundler does not follow
    // the call. urql wraps require("crypto") that way, with a comment saying
    // exactly why, and read as a staged loader. Anything built from a
    // variable, or a literal that does more than that, still convicts.
    elsewhere: {
      re: /new\s+Function\s*\(\s*["'`]require["'`]\s*,\s*(?:'\s*return\s+(?:require|import)\s*\([^']*\)\s*;?\s*'|"\s*return\s+(?:require|import)\s*\([^"]*\)\s*;?\s*")\s*\)/i,
      why: "Here the code it builds is a string spelled out in the file, and all it does is load a named module, which is how a library avoids a bundler following the call.",
      next: "Read the string it builds. This is only reported because building code from text is worth seeing at all.",
    },
  },
  {
    // technique: eval over a decoded blob, payload smuggled past a quick review
    id: "eval-decoded-blob",
    downgradeInVendored: true,
    // eval is a primitive of the dynamic languages. In Go, Rust or Java the
    // shape can only be text: xalgorix's agent prompt tells a model that an
    // XSS filter can be beaten by evaluating an atob of the payload.
    dynamicOnly: true,
    // The inner call must be a decoder; any identifier there also matches
    // ordinary eval of a compiled file.
    re: /\beval\s*\(\s*(atob|unescape|decodeURIComponent|b64decode|base64[\w$]*|[\w$]*decode[\w$]*|[\w$]*decrypt[\w$]*|inflate|gunzip)\s*\(|\beval\s*\(\s*Buffer\s*\.\s*from\s*\(/i,
    why: "This file decodes a scrambled blob and immediately runs the result with eval. Honest code has no reason to hide what it runs from anyone reading it; this is how a payload is smuggled past a quick review.",
    next: "Do not run this repository. There is no benign reading of eval over decoded data in a take-home task.",
  },
  {
    // technique: sensitive API names split across string pieces to dodge scanners
    id: "string-concat-api-hiding",
    re: /["'`](child_|ch)["'`]\s*\+\s*["'`](process|ild_process)["'`]|["'`]ev["'`]\s*\+\s*["'`]al["'`]|["'`]proc["'`]\s*\+\s*["'`]ess["'`]|\[\s*["'`]ev["'`]\s*\+\s*["'`]al["'`]\s*\]/i,
    why: 'This code splits sensitive words like "child_process" or "eval" across string pieces and glues them back together at run time. The only purpose is to slip past reviewers and automated scanners, a deliberate evasion technique.',
    next: "Do not run this repository. Code that hides its own API calls is hiding them from you.",
  },
  {
    // technique: whole-environment exfiltration, ships every secret off the machine
    id: "env-dump-exfiltration",
    downgradeInVendored: true,
    // Whole-object uses only: local_app_data = os.environ.get("X") is a
    // named read with "data" at the end of a longer name.
    //
    // `[^)]{0,400}`, never `[^)]*`: an unbounded run before a literal is
    // rescanned from every "requests.post(" in the file, which is quadratic
    // in file size. An argument list this rule reads fits on a few lines.
    re: /JSON\.stringify\s*\(\s*process\.env\s*\)|\b(data|json)\s*=\s*(dict\s*\()?\s*os\.environ\b(?!\s*[.[])|requests\.post\([^)]{0,400}os\.environ\b(?!\s*[.[])/i,
    why: "This code copies your ENTIRE set of environment variables (where API keys, tokens, and secrets live) into a message sent to a remote server. Legitimate apps read the one or two variables they need; they do not ship the whole set off your machine.",
    next: "Do not run this repository. If you already did, rotate every API key and token on this machine; see https://github.com/chriszemmel/repocanary/blob/main/WHAT-TO-DO-NOW.md.",
  },
  {
    // technique: Contagious Interview C2 fingerprint, bare IP on ports 1224/1244/1245
    id: "c2-port-fingerprint",
    re: /\b(?:\d{1,3}\.){3}\d{1,3}\s*:\s*12(24|44|45)\b/,
    why: 'This file hardcodes a raw server address on a port (1224, 1244, or 1245) used as a fingerprint by the North-Korea-linked "Contagious Interview" malware family. A dependency phoning a bare IP on these ports is a very strong indicator of that campaign.',
    next: "Do not run this repository. Report it to GitHub at https://github.com/contact/report-abuse.",
  },
  {
    // technique: BeaverTail and InvisibleFerret C2 endpoint paths
    id: "beavertail-c2-paths",
    re: /\/pdown\b|\/api\/service\/(makelog|process|token)\b|\/cldbs\b|\/api\/(ipcheck|checkStatus|ssh-key)\b/i,
    why: "This code calls remote paths (like /pdown or /api/ipcheck) that match the command-and-control layout of known fake-interview malware. These are not endpoints a real coding task would contact.",
    next: "Do not run this repository. Report it to GitHub at https://github.com/contact/report-abuse.",
  },
  {
    // technique: InvisibleFerret backdoor command-handler names
    id: "backdoor-command-handlers",
    re: /\bssh_(cmd|clip|run|upload|kill|any|env|zcp|zip|obj)\b/g,
    // Two different handler names: the backdoor defines the family, while
    // an honest tool imports one helper called ssh_cmd (borg's store).
    minMatches: 2,
    minDistinct: 2,
    why: "This file defines the remote-command handlers (ssh_cmd, ssh_upload, ssh_kill, and similar) of the InvisibleFerret backdoor. These names appear only in that malware, which lets an attacker run commands, steal files, and control your machine remotely.",
    next: "Do not run this repository. If you already did, assume full compromise and read https://github.com/chriszemmel/repocanary/blob/main/WHAT-TO-DO-NOW.md now.",
  },
  {
    // technique: Python download-and-exec loader
    id: "python-download-execute",
    pythonOnly: true,
    // Same bound as env-dump-exfiltration above, for the same reason: `[^)]*`
    // ahead of a literal walks to the end of the file from every "exec(".
    re: /exec\s*\(\s*(requests\.get|urllib\.request\.urlopen|__import__\s*\(\s*["'`]urllib)|exec\s*\(\s*compile\s*\([^)]{0,400}(requests\.|urlopen|urllib)|exec\s*\(\s*\w+\s*\.\s*(text|content)\b/i,
    why: "This Python code downloads text from the internet and runs it directly with exec. The file you can read is just a downloader; the actual malicious code is fetched and executed at install or run time.",
    next: "Do not run this repository or any of its Python files.",
  },
  {
    // technique: persistence and credential access: authorized_keys, keychain dump, silent RAT install
    fakeRootSoftens: true,
    // A bundled editor or terminal library documents authorized_keys; in
    // third-party output this is a note, as pritunl-cloud's built UI shows.
    downgradeInVendored: true,
    id: "ssh-backdoor",
    // authorized_keys counts when written to, not when named: a git server
    // regenerates it, a backdoor appends to it.
    // The bound on `open(` matters as much as the rest of the pattern: with
    // `[^)]*` a file of nothing but "open(" tokens rescanned to its end from
    // every one of them, and a megabyte of that took 251 seconds inside a
    // scan with a sixty-second ceiling. A mode argument sits next to its call.
    // The file has to be the one sshd reads, under .ssh: feschber/lan-mouse
    // keeps its own `authorized_keys: Arc<RwLock<...>>` map, whose closing
    // `>>` read as an append, and pyre's docstring for the file a git server
    // regenerates says "grants write access". Neither is ~/.ssh.
    re: /(>>|append|write|echo|cat|printf|tee|open\([^)]{0,200}['"]a)[^\n]{0,80}\.ssh(?:[\\/]|['"]?\s*[,+]\s*['"])authorized_keys|\.ssh(?:[\\/]|['"]?\s*[,+]\s*['"])authorized_keys[^\n]{0,80}(>>|append|write|\.push)|security\s+dump-keychain|--install[^\n]{0,60}--silent|taskkill\s+\/[a-z]+\s+\/im\s+(chrome|brave|msedge)\.exe/i,
    why: "This code tampers with system-level access (adding an SSH key for later login, dumping the macOS Keychain, silently installing remote-access software, or killing your browser to unlock its password database). None of this belongs in a coding-interview task.",
    next: "Do not run this repository. If you already did, assume an attacker has persistent access; see https://github.com/chriszemmel/repocanary/blob/main/WHAT-TO-DO-NOW.md.",
    // "adb shell" runs on a connected Android device, not on the machine
    // reading the repository. uutils/coreutils sets up an emulator that way
    // in its CI helper. Worth seeing, not worth "assume you are compromised".
    elsewhere: {
      re: /\badb\b[^\n]{0,80}\b(shell|emu)\b/i,
      why: "Here every such command runs through adb, so it is aimed at a connected Android device or emulator rather than at your own machine, which is what a project's device-testing helper looks like.",
      next: "Read the script before running it, and only run it if you meant to set up an Android device from this project.",
    },
    // Killing the browser is the stealer's step only beside what it unlocks:
    // the password, cookie and key stores the running browser holds open. A
    // Puppeteer bot kills Chrome to clear its own profile's SingletonLock
    // (ezzawa/BOT_AP2T), and that is a caution, not a conviction.
    mentionOnly: {
      when: /taskkill/i,
      // The stores by their file names, as written on disk: a bot that sets
      // page cookies is not reading the Cookies database.
      needs: /Login Data|Web Data|Local State|["'`\/\\]Cookies["'`]|key4\.db|logins\.json|cookies\.sqlite/,
      why: "Here the browser is closed with nothing in this file reading the password, cookie or key stores that closing it would unlock, which is what an automation bot clearing its own profile lock does.",
      next: "Check what the code does with the browser profile after closing it.",
    },
  },
  {
    // technique: PowerShell encoded command or decode-and-run, the standard
    // Windows way to hide a payload from anyone reading the script.
    id: "powershell-encoded-command",
    re: /powershell(\.exe)?[^\n]{0,60}\s-e(nc|ncodedcommand)?\s+["']?[A-Za-z0-9+/]{20,}={0,2}|FromBase64String[^\n]{0,80}(iex|invoke-expression|\.invoke)|(iex|invoke-expression)[^\n]{0,80}FromBase64String/i,
    why: "This code runs a PowerShell command that is base64-encoded (or decodes base64 and pipes it straight to Invoke-Expression). Encoding a command hides it from anyone reading the script; it is the standard way Windows malware smuggles its payload past review.",
    next: "Do not run this repository. Decode the base64 string in a safe editor to see what it actually runs.",
  },
  {
    // technique: Windows living-off-the-land download/exec via a trusted binary
    id: "windows-lolbin-download",
    re: /certutil(\.exe)?[^\n]{0,60}(-urlcache|-f\s+https?:)|bitsadmin[^\n]{0,40}\/transfer[^\n]{0,100}https?:|mshta(\.exe)?\s+["']?(https?:|javascript:)|regsvr32[^\n]{0,60}(scrobj\.dll|\/i:https?:)/i,
    why: "This code uses a trusted Windows system binary (certutil, bitsadmin, mshta, or regsvr32) to download or execute code from the internet. These living-off-the-land tricks exist to fetch a payload while looking like ordinary system activity, and have no place in a coding task.",
    next: "Do not run this repository. Report it to GitHub at https://github.com/contact/report-abuse.",
  },
  {
    // technique: macOS osascript dialog that phishes the login password
    id: "macos-password-phish",
    re: /display\s+dialog[\s\S]{0,200}hidden\s+answer|hidden\s+answer[\s\S]{0,200}display\s+dialog/i,
    why: "This code builds a native macOS password prompt (an AppleScript display dialog with a hidden answer field, run through osascript). Malware uses this to phish your login or keychain password with a box that looks like a real system request.",
    next: "Do not run this repository. No coding task needs to ask for your macOS password through a script.",
  },
  {
    // technique: silent install of a remote-desktop tool for hands-on-keyboard
    // access. The install/unattended flags are what separate it from a project
    // that merely mentions one of these tools.
    id: "remote-desktop-rat",
    re: /(anydesk|rustdesk|teamviewer|ultraviewer|screenconnect|connectwise)[^\n]{0,120}(--?(silent|install|unattended|start-with-win|service)|\/S\b|--config)|(--?(silent|install|unattended))[^\n]{0,120}(anydesk|rustdesk|teamviewer|ultraviewer|screenconnect)/i,
    why: "This code silently installs or configures a remote-desktop tool (AnyDesk, RustDesk, TeamViewer, or similar) with unattended-access flags. That hands an attacker a live desktop session on your machine, which no coding task needs.",
    next: "Do not run this repository. If you already did, check your installed programs for a remote-access tool and see https://github.com/chriszemmel/repocanary/blob/main/WHAT-TO-DO-NOW.md.",
  },
  {
    // technique: boot or login persistence via a scheduler or run key. The
    // shell-rc form is handled separately (checkCodeContent) because it needs
    // a launch command near the file to tell a payload from a shell-init line.
    id: "startup-persistence",
    // crontab - installs from stdin; -r removes every entry and -l prints
    // them, which are the opposite of persistence and the cleanup a container
    // entrypoint does on its way up. LumePart/Explo turned red for
    // "crontab -r  # Clear crontabs". -e stays a conviction, as it always
    // was, but the command now has to begin one: at a line start, or after a
    // pipe, semicolon, sudo and the rest. Neovim's documentation for
    // 'backupcopy' names "crontab -e" mid-sentence as an example of a program
    // that edits a file in place, and that sentence made an editor malware.
    //
    // The launch-agent path must be a real one. macOS loads only from a
    // Library directory, and ohmyzsh's macports plugin aliases a wrapper
    // under /opt/local/etc/LaunchDaemons/, which loads nothing and is a
    // MacPorts configuration directory that happens to share the name.
    re: /(?:^|[\n|;&(){}]|\$\(|\bsudo\s+|\bthen\s+|\bdo\s+)[ \t]*crontab\s+-(?![rl]\b)|(^|\/|["'`])Library\/Launch(Agents|Daemons)\/|reg\s+add[^\n]{0,80}\\Run\b|schtasks\s+\/create|systemctl\s+enable\s+(-{1,2}[a-zA-Z0-9][\w-]*\s+)*[^\s;&|"']*[\/~][^\s;&|"']*|\/etc\/systemd\/system\/[\s\S]{0,300}systemctl\s+enable\b|systemctl\s+enable\b[\s\S]{0,300}\/etc\/systemd\/system\//i,
    why: "This code installs itself to run again automatically, by adding a cron job or scheduled task, or registering a launch agent or Windows Run key. That is how malware survives a reboot and keeps running after you think you have closed it.",
    next: "Do not run this repository. If you already did, assume it will re-run on login; rebuild the machine and see https://github.com/chriszemmel/repocanary/blob/main/WHAT-TO-DO-NOW.md.",
    // Taking one out is the opposite of putting one in, and an uninstaller
    // names every autostart location a project ever wrote to. Netdata's
    // netdata-uninstaller.sh mentions its launch daemon exactly twice, to
    // unload it and to delete the plist, and read as persistence. This
    // softens only when EVERY match in the file sits on a removal line, so a
    // script that installs one thing and removes another stays loud.
    elsewhere: {
      // The removal has to act on the autostart entry, not merely appear on
      // the same line. Minikube installs a cron job whose command is
      // "@reboot rm -rf /var/run/reboot.in.progress", and a bare rm anywhere
      // on the line softened a real install to a caution -- which is also
      // the shape an attacker would reach for.
      re: /launchctl\s+(unload|bootout|remove)|crontab\s+-r\b|schtasks\s+\/delete|\bdisable-scheduledtask\b|\b(rm|unlink|rmdir)[\w_-]*\s+(-[^\s]+\s+)*[^\s]*Library\/Launch/i,
      why: "Here every one of those lines removes an autostart entry rather than adding one, which is what an uninstaller or a cleanup script looks like.",
      next: "Read the script and check it only removes. A file that both installs and removes would not be reported this way.",
    },
    // A launch-agent path named with nothing in the file writing a plist or
    // loading one is a path, not persistence. Homebrew's casks list every
    // agent an app leaves behind so `brew uninstall --zap` can delete them,
    // and a CLI's help text tells the reader where to put one. Only when
    // every match is such a path, and nothing in the file writes or loads.
    mentionOnly: {
      when: /Library\/Launch(Agents|Daemons)\//i,
      needs:
        /launchctl\s+(load|bootstrap|enable|submit|kickstart)|\b(cp|mv|ln|install|tee|ditto)\s[^\n]{0,200}Library\/Launch|>\s*["']?[^\n]{0,120}Library\/Launch|writeFile|WriteFile|write_text|write_bytes|writeTo(File|URL)|\.write\(\s*to:|plistlib\.dump|PropertyListSerialization|open\([^)]{0,200}['"][wa]|createWriteStream|copyFile|os\.Create|File\.(write|create)|fs::write|SMAppService|SMJobBless/i,
      why: "Here the launch-agent path is only named: nothing in this file writes a plist there or loads one, which is what a list of files to clean up or a help text looks like.",
      next: "Check whether anything else in the repository writes or loads that file.",
    },
  },
];

// Shell-rc persistence: appending a launch command to a startup file. Kept
// out of the signature table because it needs three things near each other,
// an append or redirect, a startup file, and an actual command to run, so a
// CLI framework's "add this to your ~/.bashrc" help text does not match.
const RC_FILE_RE = /\.(bashrc|zshrc|zprofile|bash_profile|profile)\b/i;
const RC_APPEND_RE = />>|append[a-z]*\s*\(|write[a-z]*\s*\(/i;
const RC_LAUNCH_RE = /node\s|python3?\s|curl|wget|nohup|\.js\b|\/tmp\/|~\/\.[\w./-]+\.(js|sh)|start\s+\/b\s+node/i;

export function checkShellPersistence(path, content) {
  const m = content.match(RC_FILE_RE);
  if (!m) return null;
  // Window around the startup-file reference; all three parts must co-occur
  // there, in either order.
  const window = content.slice(Math.max(0, m.index - 120), m.index + 120);
  // echo "export PATH=..." >> ~/.bashrc is how a dev container or installer
  // sets up a shell; a launcher appends a program to run, a temp path or a
  // download. A setup line that also carries none of those is not persistence.
  const envSetup = /echo\s+["']?(export\s+\w+=|source\s|\.\s+\S|alias\s|eval\s+["']?\$\()/i.test(window) && !/\/tmp\/|\.js\b|nohup|curl|wget|start\s+\/b/i.test(window);
  if (RC_APPEND_RE.test(window) && RC_LAUNCH_RE.test(window) && !envSetup) {
    return {
      id: "startup-persistence",
      severity: "high",
      file: path,
      line: lineOfIndex(content, m.index),
      snippet: redactSnippet(window),
      why: "This code appends a command to a shell startup file (like ~/.bashrc), so the command runs every time a shell opens. That is how malware survives a reboot and keeps running after you think you have closed it. A completion script that only tells you to edit your startup file is not this; this writes a program into it.",
      next: "Do not run this repository. If you already did, inspect your shell startup files and rebuild the machine; see https://github.com/chriszemmel/repocanary/blob/main/WHAT-TO-DO-NOW.md.",
    };
  }
  return null;
}

/**
 * Medium-specificity code signatures: strongly suspicious in an interview
 * repo, but with plausible benign uses elsewhere, so they accumulate toward
 * a verdict rather than convicting alone.
 */
export const MED_SIGNATURES = [
  {
    // technique: enabling a system service by name. minikube enables kubelet
    // and docker; a payload enables the unit it just wrote (high above).
    id: "startup-persistence",
    re: /systemctl\s+enable\b/i,
    why: "This code enables a system service to start at boot. A cluster or container tool does that for the daemons it manages; malware does it for the unit it just installed, so check which service and where it comes from.",
    next: "Read which service is enabled and whether its unit file is written by this repository.",
  },
  {
    // technique: exfiltration to a webhook, paste, messaging, or
    // anonymous-upload sink
    id: "exfil-sink",
    // A webhook host with its path, not the bare host: a settings form whose
    // placeholder reads "https://hooks.slack.com/..." is telling the user
    // where to paste theirs.
    re: /discord(app)?\.com\/api\/webhooks|api\.telegram\.org\/bot|hooks\.slack\.com\/services\/|pastebin\.com\/raw|(?<![\w.-])[a-z0-9-]+\.pipedream\.net|\.oastify\.com|\.interact\.sh|webhook\.site|(?<![\w.-])(?:requestbin|iplogger|grabify)\.[a-z]{2,4}\b|transfer\.sh|(?<![\w.-])file\.io\b|0x0\.st|gofile\.io|catbox\.moe|tmpfiles\.org|termbin\.com|\bix\.io|sprunge\.us/i,
    why: "This code contacts a webhook, paste, messaging, or anonymous file-upload endpoint of the kind used to quietly receive stolen data. It can be legitimate for notifications, but in an unsolicited repo it is a common exfiltration channel.",
    next: "Check what data the code sends to this endpoint before running anything.",
    // A Telegram bot whose token the code reads from a variable is the
    // user's own notification channel: every trading bot in the corpus
    // messages its owner that way. A token written into the code sends to
    // whoever wrote it, which is the stealer's shape and stays a caution.
    // The same holds for a Discord or Slack webhook whose ID the code fills
    // in: discord.py and python-telegram-bot are the API clients, and monolog
    // ships a Telegram handler for whoever configures one.
    lowWhen: /(?:api\.telegram\.org\/bot|discord(?:app)?\.com\/api\/webhooks\/?|hooks\.slack\.com\/services\/)(?:\{|\$\{|["'`]\s*[+,)]|%s|\$[A-Za-z_(]|<|:[a-z_]+)/i,
  },
  {
    // technique: reverse tunnel to reach the victim without a fixed server
    id: "tunneling-infra",
    re: /ngrok\.io|(?<![\w.-])[a-z0-9-]+\.trycloudflare\.com|(?<![\w.-])[a-z0-9-]+\.serveo\.net|localtunnel/i,
    why: "This code references a tunneling service (ngrok, Cloudflare quick-tunnel, serveo) that exposes a machine to the internet through a temporary address. Malware uses these to reach a victim or ship data out without a fixed server.",
    next: "Ask why this project needs a tunnel. If there is no clear answer, do not run it.",
  },
  {
    // technique: disposable free-hosting C2 endpoint
    id: "throwaway-host-c2",
    re: /https?:\/\/(?<![\w.-])[a-z0-9-]+\.vercel\.app\/(api\/)?(ipcheck|process-log|icons|settings)|api\.npoint\.io|cloudflare(insights|firewall|security)\.vercel\.app/i,
    why: "This code calls a free-hosting URL (a *.vercel.app or npoint endpoint) on a path like /api/ipcheck or /process-log, a disposable command-and-control pattern favored by these campaigns. A real dependency would not call such an endpoint.",
    next: "Do not run this repository until someone explains what that endpoint is.",
  },
  {
    // technique: dead-drop resolver: fetches a fresh C2 address from a trusted service
    //
    // Two tiers. A Google Doc exported as plain text, a Calendar link, or a
    // raw paste is a dead-drop marker on its own. A raw GitHub URL, a gist, or
    // a Steam profile is far too common in honest code (schemas, badges,
    // configs) to convict alone, so those require a decode-or-execute
    // indicator nearby, which is what turns a fetched URL into a resolver.
    // The lookahead asks only what the match needs (an indicator 10 to 280
    // characters on) before the split between URL and gap is searched: a
    // megabyte of the host name repeated otherwise tried every split at
    // every occurrence and took seconds to find nothing.
    id: "dead-drop-resolver",
    re: /docs\.google\.com\/document\/d\/[^\s"'`]+\/export\?format=txt|calendar\.app\.google|pastebin\.com\/raw|(raw\.githubusercontent\.com|gist\.githubusercontent\.com|steamcommunity\.com\/profiles)\/(?=[\s\S]{10,280}?(?:atob|decode|eval|exec|new\s+Function|\bc2\b|server\s*=|payload))[^\s"'`]{10,200}[\s\S]{0,80}(atob|decode|eval|exec|new\s+Function|\bc2\b|server\s*=|payload)/i,
    why: "This code fetches its next instruction or server address from a trusted service (a Google Doc or Calendar link, a raw GitHub gist, a paste, or a Steam profile). This dead-drop trick hands malware a fresh command server without committing it to the repo, so it can be changed at any time without a code update.",
    next: "Open the referenced URL in a browser and see what it contains before trusting this code.",
  },
  {
    // technique: VM and sandbox detection to stay dormant under a researcher
    id: "sandbox-evasion",
    re: /\b(qemu|virtualbox|vmware|parallels|vboxservice|hyperv)\b/gi,
    minMatches: 2,
    downgradeInVendored: true,
    // Detection needs a question asked of the machine. Names alone are a
    // directory called virtualbox in vagrant, an enum in localstack, a map
    // projection in d3 and a VM a CI script boots on purpose.
    needsProbe:
      /dmidecode|\/sys\/class\/dmi|product_name|sys_vendor|systeminfo|wmic\b|Win32_(ComputerSystem|BIOS|BaseBoard)|Get-(WmiObject|CimInstance)|HARDWARE\\\\|SystemBiosVersion|ioreg\b|system_profiler|sysctl\s+(-n\s+)?hw\.model|cpuid|lspci|\b(00:05:69|00:0c:29|00:1c:14|00:50:56|08:00:27)\b|VBoxGuest|vmtoolsd|prl_tools|\bhostname\s*\(|gethostname|platform\.node\(|PROCESSOR_IDENTIFIER|\bos\.cpus\(|\/proc\/cpuinfo|navigator\.(webdriver|hardwareConcurrency)/i,
    why: "This code checks whether it is running inside a virtual machine or sandbox (looking for VMware, VirtualBox, QEMU, and the like). Malware does this to stay dormant while security researchers watch, then activate on a real victim's machine.",
    next: "Ask why an application needs to detect virtual machines. If there is no good answer, do not run it.",
  },
  {
    // technique: automated JavaScript obfuscator toolmarks
    id: "obfuscator-io",
    re: /while\s*\(\s*!\!\[\]\s*\)|\(function\s*\(\s*_0x[a-f0-9]+\s*,\s*_0x[a-f0-9]+\s*\)/i,
    downgradeInVendored: true,
    why: "This file bears the toolmarks of an automated JavaScript obfuscator (a self-rotating string table and a while(!![]) loop). It is deliberately unreadable, which honest project code has no reason to be.",
    next: "Do not run this repository until the obfuscated file is explained and replaced with readable source.",
  },
  {
    // technique: filesystem sweep for wallet and secret filenames
    id: "stealer-file-globbing",
    // Wallet keywords, not generic config names, are what make a tree walk a
    // stealer signal rather than ordinary file handling.
    re: /(glob|readdirSync|walk|rglob)[^\n]{0,80}(wallet|metamask|phantom|mnemonic|seed\s?phrase|keystore)|(wallet|mnemonic|seed\s?phrase|keystore)[^\n]{0,40}(glob|readdirSync|walk)/i,
    why: 'This code walks the filesystem hunting for files whose names contain "wallet", "metamask", "seed", "mnemonic", or "keystore". That is how a stealer locates crypto keys to copy.',
    next: "Do not run this repository. If you already did, move crypto funds and rotate secrets; see https://github.com/chriszemmel/repocanary/blob/main/WHAT-TO-DO-NOW.md.",
  },
  {
    // technique: keylogger and screen-capture RAT components
    id: "spyware-dependency",
    re: /node-global-key-listener|screenshot-desktop|["'`]sharp["'`][^\n]{0,120}screenshot|socket\.io-client[^\n]{0,120}\b(?:\d{1,3}\.){3}\d{1,3}\b/i,
    why: "This code pulls in keylogging or screen-capture components (or opens a live socket to a bare IP address). Together these give an attacker eyes and hands on your machine, not something a coding task needs.",
    next: "Do not run this repository.",
  },
];
