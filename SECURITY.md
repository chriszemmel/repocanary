# Security policy

## Reporting a vulnerability in RepoCanary

If you find a way to make RepoCanary execute repository content, leak the
scanned URL anywhere other than GitHub (or, with `--ai`, the AI provider you
chose), stall or crash on crafted input, or
otherwise behave unsafely, please report it privately first: use **Report a
vulnerability** under this repository's Security tab. Include what you did,
what happened, what you expected, and why it matters. Please allow a
reasonable window before disclosing publicly.

## Reporting a detection gap

A missed trap or an honest repository wrongly flagged is not a vulnerability
in this sense. Open a normal issue with the repository URL; a fixture that
reproduces it is the most useful thing you can attach (see
[CONTRIBUTING.md](CONTRIBUTING.md)). Signature matching always trails new
techniques, and reported gaps are how coverage grows.

## What RepoCanary does with your data

Nothing leaves your machine except:

- requests to `api.github.com` to read the repository you asked it to scan;
- only with `--ai`, the findings (file paths, redacted snippets, reasons, up
  to 600 redacted bytes of an install script a finding points at, and public
  repository metadata) to the AI provider you chose, with your own key.

A key is never accepted as a command-line argument, a pasted key is hidden
while typed and held in memory for that run only, and no key is written to
disk or included in a report. There are no accounts, no database, no
analytics and no telemetry.

## Not yet audited

- The website in `web/` has tests but has not been reviewed line by line.
  Treat the CLI as the audited surface.
- `src/github.js` has not been fuzzed against hostile API responses.
- The hosting deployment's configuration has not been reviewed, and its rate
  limit is per process (see [THREAT-MODEL.md](THREAT-MODEL.md)).
- The optional AI pass has not been tested against repository text written to
  manipulate the model. The structural defense does not depend on the model:
  it can never lower a static red.

## Supported versions

RepoCanary is run with `npx`, so you get the latest published version. Fixes
land in a new release; there are no maintenance branches.
