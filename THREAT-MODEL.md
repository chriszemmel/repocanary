# Threat model

What RepoCanary defends against, what it does not, and how someone would
evade it. The evasions are written plainly on purpose: a security tool that
hides its limits misleads the people who most need the truth.

## Who this protects

A developer, often early in their career, who has been sent a repository and
asked to run it or open it. They have minutes, not hours, and probably no
access to a commercial supply-chain scanner. RepoCanary gives them a fast,
free, honest read on whether the repository matches the known shape of an
attack, so they can decide not to run it.

## What it defends against

- **Code that runs before you read anything**: package-manager lifecycle
  scripts and the files they start, Python, Rust, JVM, PHP and Ruby build
  hooks, Makefiles and Dockerfiles, and the configs an editor or agent acts on
  when a folder is opened (VS Code tasks, MCP servers, agent hooks, dev
  containers, direnv, Emacs and Neovim project files).
- **Poisoned dependency resolution**: lockfile entries off the public
  registry, git and URL dependencies, `overrides` and aliases that redirect a
  trusted name, typosquats and known-malicious package names.
- **Theft**: reading browser credential stores, wallets, SSH keys and cloud
  credentials; posting the environment out; password phishing dialogs.
- **Staged loaders**: text downloaded and run through a shell, `eval`,
  `new Function` or `exec`, in every shape the rules know.
- **Deliberate unreadability**: obfuscator toolmarks, entropy, encoded
  blobs, code parked past the edge of the screen, invisible characters and
  homoglyphs.
- **Known campaign fingerprints** from the Contagious Interview, BeaverTail
  and InvisibleFerret families.
- **Malicious CI that reaches you**: `pull_request_target` workflows that run
  untrusted code with secrets, and a self-hosted runner a README asks you to
  register.

## What it does not defend against

- **Runtime-only payloads.** Clean-looking code that fetches its payload from
  a server at run time, and serves a scanner something harmless, is invisible
  to static analysis. This is the strongest evasion and the reason green is
  never "safe".
- **Compromised legitimate dependencies.** RepoCanary reads resolution URLs
  and install-script flags, not the source of every transitive package.
- **Novel techniques.** A new execution vector fires nothing until a rule is
  written for it.
- **Attacks with no code in the repository**: "register our CI runner", "run
  this command I'll paste in the call".
- **Instructions for your coding agent written in plain language.** A
  `CLAUDE.md` or `AGENTS.md` can ask an agent to read your credentials and send
  them somewhere without a line of malicious code. RepoCanary catches the
  mechanical tricks (hidden comments, CSS-hidden text, Unicode tag characters,
  forged system turns, links carrying a secret) but cannot judge intent. Read
  those files before pointing an agent at a stranger's repository.
- **What it cannot read.** Binary files, files past the caps (170 files, about
  6 MB), symlink targets and submodules. Each is reported as a note, so a
  partial scan says so.
- **CI that only runs on someone else's machines.** A workflow that pipes a
  script into a shell on the CI provider's runner is the maintainers' risk,
  reported as a note.
- **A machine that already ran the code.** See
  [WHAT-TO-DO-NOW.md](WHAT-TO-DO-NOW.md).

## How someone would evade it

1. **Stage everything at run time** behind an API that serves the payload
   only to real victims.
2. **Hide the trigger where the scanner does not look**, past the file cap
   in a large repository or in a file type it deprioritises. The report says
   when a cap was reached, but that is disclosure, not detection.
3. **Avoid the signatures**: a new loader shape, a fresh C2 host, an
   unenumerated way to rebuild an API name. For example, a downloaded file run
   directly (`chmod +x f && ./f`) looks like every binary install and is not
   convicted.
4. **Hide inside a vendored bundle.** Obfuscation signals are downgraded in
   files that look like minified libraries. Theft rules still fire there.
5. **Use a clean registry dependency**, harmless for its first versions and
   resolving normally from the registry.
6. **Stay off the repository** and deliver the payload over chat.
7. **Squat a name a language model invents.** It imitates nothing, so no
   typosquat rule scores it.
8. **Attack the scanner**: a file crafted to make a pattern backtrack could
   stall a scan. Every rule is held to linear cost by `test/redos.test.js`,
   which measures each hostile shape at the per-file cap.

Six limits are held as executable samples in `scripts/benchmark-samples.js`
(runtime staging, a clean registry dependency, the off-repository attack, the
invented name, an uncorroborated lookalike name, and a CI workflow that pipes
a script into a shell on the provider's runner), and the benchmark asserts
they are still missed. A limit that silently changes is a change to this
document.

## Choices made on purpose

- **A lookalike name alone stays green.** It raises a caution only with a
  second signal, because the list of popular packages is never complete and a
  missing entry would otherwise turn every project that uses it yellow.
- **RepoCanary reports itself red**, like any rule set or malware corpus. Any
  exemption (skip `fixtures/`, recognise "a security tool") would be an
  evasion path, so there is none.
- **A VS Code task that runs on folder open is red whatever it runs.** In a
  stranger's repository, opening the folder to read it is the attack.
- **The hosted site's rate limit is per process.** The only shared resource
  is the site's GitHub quota, and exhausting it costs an hour of "try again
  later". A shared store would add a credential and a dependency for little
  gain.

## Design consequences

- Green is worded as "nothing known matched", never as safe.
- A scan that could not complete exits 3, never 0.
- The optional AI pass can clear a yellow or raise a green, but can never
  lower a red or produce one.
- Uncertain signals are yellow, not red, so red stays worth believing.

RepoCanary is a smoke detector, not a force field. Read the code, run
unfamiliar projects in a throwaway VM, and be suspicious of anyone who needs
you to run their code in a hurry. Found a gap? See [SECURITY.md](SECURITY.md)
and [CONTRIBUTING.md](CONTRIBUTING.md).
