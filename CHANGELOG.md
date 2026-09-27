# Changelog

All notable changes are recorded here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project
follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html). The JSON
output's `schemaVersion` is versioned separately, so consumers can depend on
it.

## [Unreleased]

## [1.0.0] - 2026-09-24

First public release. A scanner for the person a stranger's repository was
sent to: it reports whether the repository matches the known signatures of
fake-job-interview malware, and it never clones, installs, executes,
evaluates or imports the repository to find out.

### Added

- `npx repocanary owner/repo`: no install, no account, Node 20+, zero runtime
  dependencies. Human, JSON (`schemaVersion: 1`) and SARIF 2.1.0 output, and
  honest exit codes (0 green, 1 yellow, 2 red, 3 could not check). A scan
  that could not complete still writes a JSON or SARIF document, with
  `verdict: "error"`.
- The same engine on the website and as a GitHub Action with `fail-on` and
  SARIF upload, plus a README badge.
- Detection of 101 documented techniques in nine categories: install-time
  execution across npm, Python, Rust, Go, the JVM, PHP and Ruby; open-time
  autoruns (VS Code, MCP servers, agent hooks, dev containers, direnv, Emacs,
  Neovim); poisoned lockfiles, git and URL dependencies, aliases and
  typosquats; credential and wallet theft; download-and-execute loaders;
  persistence; obfuscation, including code hidden past the edge of the
  screen; campaign fingerprints; and context signals. The catalog is
  generated into THREAT-COVERAGE.md.
- An optional AI second opinion on the user's own key (Gemini, Groq, OpenAI,
  Anthropic). It can never lower a red or produce one.
- THREAT-MODEL.md with the documented evasions, six of them held as samples
  that must keep evading, and WHAT-TO-DO-NOW.md for anyone who already ran a
  suspicious repository.

### Measured

- 4,002 repositories the rules had never seen, in 29 waves. Wrong reds fell
  from 13% on the first wave to under 1% on take-home repositories, and on a
  deliberately harder pool scanned with frozen rules from 9% to 2.75% over
  the last three waves (1,198 repositories). 19 live traps were found in the
  wild along the way.
- A regression corpus of 3,408 public repositories, re-scanned weekly: 77%
  green, 21% yellow, 2% red, every red listed with its reason.
- Scan cost is linear in file size and asserted against hostile inputs; the
  worst case measured is 2.4 seconds.

Details in BENCHMARK.md.

[Unreleased]: https://github.com/chriszemmel/repocanary/compare/v1.0.0...HEAD
[1.0.0]: https://github.com/chriszemmel/repocanary/releases/tag/v1.0.0
