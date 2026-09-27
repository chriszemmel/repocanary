# Contributing to RepoCanary

Thank you for helping. The most valuable contributions are a repository
RepoCanary got wrong, in either direction, and new detection rules with
fixtures.

## Invariants

Each of these is guarded by a test, and a change that breaks one will not be
accepted:

1. RepoCanary never clones, installs, executes, evaluates or imports the
   target. It fetches text and matches patterns.
2. The caps stay: file count, bytes per file, total bytes.
3. Static rules decide the verdict. The AI pass may raise a green or clear a
   yellow, never lower a red and never produce one.
4. Green means "nothing known matched", in those words. Never imply safety.
5. No accounts, database, telemetry or analytics. The AI pass runs on the
   user's own key.
6. Zero runtime dependencies, Node 20+, MIT.
7. Honest exit codes: 0 green, 1 yellow, 2 red, 3 could not check.
8. A scan always finishes: cost is linear in file size, so no file can stall
   it.
9. A snippet never reproduces what it reports: payloads are shortened and
   control, bidirectional and invisible characters are written out.

## Setup

```bash
git clone https://github.com/chriszemmel/repocanary
cd repocanary
npm test        # offline, nothing to install
npm run lint
```

## Layout

- `cli.js`: arguments, report, exit code.
- `src/github.js`: the only module that touches the network.
- `src/scan.js`: select files, fetch within the caps, run rules, score.
- `src/selection.js`: which files a scan reads, and what they say will run.
- `src/heuristics.js`: the dispatcher, which rules each file gets.
- The rules, by what they look at: `signatures.js` (the technique tables),
  `code.js` (source and config bodies), `packagejson.js`,
  `agent-instructions.js`, `ecosystems.js` (every other manifest, build file
  and autorun), `lockfile.js`, `obfuscation.js`, `typosquat.js`, and
  `vendored.js` (generated and bundled code, where rules step down).
- `src/verdict.js`: scoring. `src/report.js`: human, JSON and SARIF output.
- `test/fixtures/corpus/`: fixture repositories.
- `scripts/benchmark-samples.js`: the threat catalog, one sample per
  technique.
- `web/`: the website, a separate workspace that imports `../src`. Nothing in
  `cli.js` or `src/` imports it.

## Adding or changing a rule

1. **Choose the severity honestly.** `high` makes a repository red on its own
   and is reserved for behaviour with essentially no honest use. Anything
   with a plausible benign explanation is `medium` or `low`. When in doubt,
   yellow: a wrong red is a bug.
2. **Write a plain-language finding.** `id`, `severity`, `file`, `line`, a
   redacted `snippet`, a `why` a non-expert understands, and a concrete
   `next` step.
3. **Add fixtures that fire and that do not.** A directory under
   `test/fixtures/corpus/<name>/` with `files/` and an `expected.json`, plus
   a benign one with `"mustNotFire"`. Add unit tests beside them.
4. **Add a benchmark sample** to `scripts/benchmark-samples.js` and run
   `node scripts/coverage.js` to regenerate THREAT-COVERAGE.md. CI fails if a
   rule fires on no sample or the catalog is stale.
5. **Keep patterns linear.** Bound every run next to a literal
   (`[^\n]{0,400}`, not `[^\n]*`) and never let two greedy runs sit side by
   side. Under `/m` a lone `\r` is a line break too, so indentation is
   `[^\S\r\n]`, never `[^\S\n]`. `test/redos.test.js` enforces the outcome.
6. **Read a config the way the program that obeys it reads it**, including
   JSON unicode escapes and case rules, or the rule is evaded by rewriting
   the file.
7. **After narrowing a rule, run `npm run guard`.** It checks that every
   malicious sample is still caught, every documented evasion still evades,
   and every red in `scripts/corpus/expected-red.txt` is still red.
8. **Before a rule change lands, run `npm run corpus:check`.** It re-scans
   the 3,408 repositories in the regression corpus and fails on any red not
   listed with a reason. It takes a couple of hours, so CI runs it weekly.

If you changed report wording on purpose, regenerate the goldens with
`UPDATE_GOLDEN=1 node --test test/golden.test.js` and read the diff.

If you changed what the site or the report looks like, regenerate the README
screenshots from a running build (`npm run build:web && npm run start:web`),
with the tools the script names at its top installed `--no-save`:
`SITE_URL=http://localhost:3000 npm run screenshots`. They are the real
engine on two example repositories, so they go stale when the output changes.

## The regression corpus

`scripts/corpus/regression.txt` lists every public repository RepoCanary
has been measured against. It is tuned on, so it proves a change did not
convict honest projects; it does not measure accuracy on new code. That is
done with fresh draws on frozen rules:

```bash
node scripts/corpus.js --list wave.txt   # scan a fresh list
node scripts/corpus.js --resume          # continue an interrupted run
```

A line in `expected-red.txt` needs a reason a reader can check: an honest
project that really does the thing, such as piping an installer into a
shell. Never widen a rule so a repository turns green when the flagged line
really does what the rule describes.

## Style

- No em dashes, in code, comments, docs or commit messages.
- Comments say why, in a sentence or two. A reason worth keeping is worth a
  test named after it.
- A rule's result must not depend on scan order: no shared global regex with
  `lastIndex`, no cache keyed on anything but the content it describes.
- Keep the tool small enough to read in one sitting. It does one job.

## Repository settings the release relies on

The workflows assume these, and nothing in the repository can enforce them:

- `main`: a ruleset requiring a pull request, code-owner review and the CI
  checks. The release checks that a tag is on `main`, which is only worth
  what protects `main`.
- `v*` tags: a ruleset blocking update and deletion and limiting who may
  create them. Action users run whatever a tag points at.
- The `npm-publish` environment: required reviewers, self-review blocked,
  deployments limited to `v*` tags. npm Trusted Publishing is configured for
  `release.yml` in that environment, and no npm token exists anywhere.
- Private vulnerability reporting is on, and the labels `detection gap` and
  `false positive` exist for the issue templates.
