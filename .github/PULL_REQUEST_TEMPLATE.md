## What this changes

<!-- One or two sentences. Which rule, surface, or document, and why. -->

## Checklist

- [ ] `npm test`, `npm run lint` and `node scripts/coverage.js --check` pass
- [ ] A new or changed rule has a fixture that fires it and a benign fixture that does not (see CONTRIBUTING.md)
- [ ] A new rule has a sample in `scripts/benchmark-samples.js` and `THREAT-COVERAGE.md` was regenerated
- [ ] Report wording changes came with regenerated goldens (`UPDATE_GOLDEN=1 node --test test/golden.test.js`) and the diff was read
- [ ] No runtime dependencies added; the CLI still ships zero
- [ ] No em dashes; comments say why, not what
