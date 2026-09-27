# The regression corpus

- `regression.txt`: every public repository RepoCanary has been measured
  against, 3,408 of them, across JavaScript, Python, Go, Rust, the JVM, PHP,
  Ruby, .NET and more.
- `expected-red.txt`: every repository in it that comes out red, with the
  reason it earns one. Lines marked `WRONG` are known mistakes still open.

```bash
npm run corpus           # scan all of them and print a summary
npm run corpus:check     # exit 1 on any red not listed in expected-red.txt
node scripts/corpus.js --list wave.txt   # a fresh list instead
node scripts/corpus.js --resume          # continue an interrupted run
node scripts/corpus.js --shard 2/6       # one sixth, as CI runs it
```

Each repository is cloned shallowly, scanned and deleted; nothing is
executed. Every report is also rendered and checked, so a run fails on a
report that disagrees with its own verdict. The corpus is tuned on, so a clean
run proves no regression and measures nothing about new code; see
[BENCHMARK.md](../../BENCHMARK.md) for the numbers on unseen repositories.
`.github/workflows/corpus.yml` runs it weekly against the live repositories.
