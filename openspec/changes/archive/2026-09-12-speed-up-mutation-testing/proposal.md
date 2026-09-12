## Why

A full mutation run takes about 30 minutes at four workers (1,250 mutants, each re-running a package's tests), so it is run once per change at the very end and never during development. Most changes touch a small share of the mutable files, and the machine has more cores than the wrapper uses.

## What Changes

- `make test-mutation` mutates only handwritten Go files that differ from a base ref (`CLAVIS_MUTATION_DIFF`, default `main`), selected in the repository root and passed to the tool as exclusions of everything else; the report states the scope. A run whose diff touches no eligible file reports the empty state explicitly, as the spec already requires.
- `make test-mutation-full` runs the whole scope with the extended budget (3,600 s unless overridden), for archive and release verification.
- The worker default becomes the available core count minus two (at least one) instead of two; `CLAVIS_MUTATION_WORKERS` still overrides.
- README documents the two commands and the variables.

## Capabilities

### New Capabilities

None.

### Modified Capabilities

- `project-bootstrap`: "Focused mutation testing" gains the diff-scoped default, the full-scope command and the derived concurrency default.

## Impact

- `scripts/mutation.mjs`, `scripts/mutation-inputs.mjs` (changed-file selection helper) and its test, `Makefile`, `README.md`. No Go code, no dependencies.

## Non-goals

Line-level diff mutation, test tagging to skip slow tests, changing mutant kinds, CI wiring.
