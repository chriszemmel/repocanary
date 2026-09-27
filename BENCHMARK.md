# Benchmark

What RepoCanary was measured on, what it got right, and where it is still
wrong. Every number here comes from a run you can repeat with the commands at
the end. Last measured on 2026-09-24.

## At a glance

| What                                                    | Result                                     |
| ------------------------------------------------------- | ------------------------------------------ |
| Repositories scanned the rules had never seen           | 4,002                                      |
| Public repositories in the regression corpus            | 3,408                                      |
| Wrong reds on unseen repositories, rules frozen         | 2.75% (33 of the last 1,198), down from 13% |
| Corpus verdicts on the last full run                    | 77% green, 21% yellow, 2% red              |
| Live traps found in the wild while measuring            | 19                                         |
| Documented attack techniques caught                     | 101 of 101                                 |
| Documented evasions still missed, by design             | 6 of 6                                     |
| Worst case for one scan, on a repository built to stall | 2.0 to 2.4 seconds                         |

"Wrong red" means one thing: an honest repository called red. A yellow is a
caution, not an accusation, and is counted separately.

## Wrong reds on code the rules had never seen

A scanner always looks good on the code it was tuned on, so the number that
counts is measured on repositories nobody had scanned before: 4,002 of them in
29 waves. Every red in a wave was opened and read, and the rules were fixed
for what the wave got wrong before the next one was drawn.

<img alt="Wrong reds per wave of unseen repositories: waves 1 to 15 fell from 13.1% to 0.4%; waves 16 to 29, a harder pool on frozen rules, fell from 9% to 2.75%" src="assets/chart-wrong-reds.svg">

**Waves 1 to 15** were broad draws: mixed ecosystems, infrastructure,
libraries, tutorials, application projects, and finally 246 take-home and
starter repositories of the kind a candidate is sent. The rate fell from 13%
to under 1% on that last wave.

**Waves 16 to 29** changed two things. The pool got harder on purpose: famous
projects, crypto and trading bots, coding-agent tooling and the newest
repositories in the big languages, which install services and pipe installers
into shells for a living. And the method got stricter: rules frozen at a
commit before each draw, nothing changed until every red was read. The first
of these waves came in at 9%.

| Wave  | What was drawn                                               | Repositories | Wrong reds | Wrong % |
| ----- | ------------------------------------------------------------ | ------------ | ---------- | ------- |
| 1     | Ten mixed batches, the original corpus                       | 505          | 66         | 13.1    |
| 2     | Mixed ecosystems and AI tooling                              | 43           | 3          | 7.0     |
| 3     | Learning projects, cloud starters, build tools               | 100          | 4          | 4.0     |
| 4     | Python, Go, Rust, JVM, PHP, Ruby, .NET, ML, DevOps           | 125          | 0          | 0       |
| 5     | Infrastructure, observability, developer tooling             | 119          | 2          | 1.7     |
| 6     | Java, Kotlin, PHP, Ruby, .NET, Go libraries                  | 119          | 4          | 3.4     |
| 7     | Package managers, editors, desktop and CLI tools             | 107          | 0          | 0       |
| 8     | Tutorials, course repositories, portfolio starters           | 49           | 3          | 6.1     |
| 9-12  | Mixed languages, most recently updated, drawn four times     | 400          | 15         | 3.75    |
| 13-14 | Application projects by stars, drawn twice                   | 200          | 3          | 1.5     |
| 15    | Take-home, challenge and starter topics, newest first        | 246          | 1          | 0.4     |
| 16    | Famous projects, crypto bots, take-homes, agent tooling      | 100          | 9          | 9.0     |
| 17-19 | The same pools, frozen rules                                 | 300          | 16         | 5.3     |
| 20-23 | The same pools, drawn again                                  | 391          | 15         | 3.8     |
| 24-27 | TypeScript, JavaScript, Go, Rust, newest first               | 400          | 11         | 2.75    |
| 28    | Python, TypeScript, PHP, Java, Vue, newest first             | 400          | 11         | 2.75    |
| 29    | The wave 16 pools, drawn a third time                        | 398          | 11         | 2.8     |

On the harder pool the rate fell by two thirds and then held for three
waves in a row, at about one wrong red in 36 honest repositories. That is the honest limit of a
scanner that reads files and runs nothing. Each wrong red was fixed with a
general principle rather than an exception, next to a test that keeps the
trap shape it must still catch:

- **Red needs something that runs by itself.** A download, a service unit or
  a key write in a script nobody runs and nobody is told to run is a
  maintainer's tool and at most a caution. Root-level scripts, lifecycle
  hooks, editor and agent autoruns, and what they start keep full weight.
- **Text is not a command.** A download written in a comment, a help text, a
  printed usage block, a Go string or a regex is only a command where it
  reaches a shell.
- **Mention is not action.** A credential path in a filter list, under a
  made-up home directory, or in documentation is not a read.
- **Known things are known everywhere.** Official installers, registry
  mirrors, loopback addresses and the repository's own URLs.

## The reds that are right

Not every red on an honest-looking repository is a mistake. Of the reds in
the waves, two kinds were correct:

- **Live traps**, 19 in total. An obfuscated loader hidden after 382 spaces
  on a line `npm start` runs. One developer account whose thirteen
  repositories all carry the same `global.o=` loader after the last line of a
  config file. A trading bot built with an obfuscator. A script that execs
  whatever a URL returns.
- **Honest projects doing exactly what the attack does**: piping an installer
  into a shell from a root script, writing a service that starts at login,
  reading other sites' tokens out of a browser profile. The report says what
  the code does; whether that is what you want is your call.

Every red in the corpus is named with its reason in
[`scripts/corpus/expected-red.txt`](scripts/corpus/expected-red.txt), and the
weekly corpus run fails on any red that is not.

## Yellow

A caution that fires on a third of honest projects teaches people to skip
it. The yellows were read class by class in the same way, and the ones that
were not worth a reader's time were fixed: data nothing decodes, data that
names itself (fonts, images, bytecode), maintainer scripts nothing runs,
method names in compiled languages, webhooks whose address the user supplies,
and git dependencies pinned to a release.

<img alt="Verdicts on the regression corpus: before, 73% green, 25% yellow, 2% red; now, 77% green, 21% yellow, 2% red" src="assets/chart-verdicts.svg">

What remains yellow on honest projects is mostly worth the look it asks for:
a download next to a program start in code that runs, a maintainer installer
that writes a service, a git dependency pinned to a branch rather than a
release. On a set of 71 well-known projects chosen to be hard (native
addons, package managers, crypto libraries, build systems), 53 are green and
two are red, pm2 and zod, both correctly: pm2 installs a boot service, and
zod's dev container pipes an installer into bash.

## Detection

[`THREAT-COVERAGE.md`](THREAT-COVERAGE.md) lists 101 techniques these
campaigns use, in nine categories, each reproduced as a whole plausible
repository with inert endpoints, and the rules that fire on each. All 101
are caught, and CI fails if one stops being caught.

That is a regression guard, not a detection rate. Every rule must have a
sample, so the catalog is a subset of what the rules catch by construction.
An honest detection rate needs malware written by someone else and scanned on
frozen rules, and there is not one yet. The six documented evasions in
[`THREAT-MODEL.md`](THREAT-MODEL.md) are held as samples that must keep
evading, so a limit that silently changes is noticed too.

## Shelf life

Numbers measured by cloning other people's repositories move without a
commit here: a project that adds `curl | bash` to its dev container tonight
changes tomorrow's corpus run. That is why the corpus is re-scanned weekly and
why every figure on this page carries a date.

## Reproduce it

```bash
npm test                          # offline: rules, fixtures, the 101 samples
npm run guard:offline             # nothing caught before is missed now
npm run benchmark                 # clones the 71 standing repositories
npm run corpus:check              # clones all 3,408; a couple of hours
node scripts/corpus.js --list wave.txt   # a fresh draw of your own
```
