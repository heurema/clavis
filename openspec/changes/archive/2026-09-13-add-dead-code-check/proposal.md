## Why

Three changes have added and removed whole layers (an audit journal built and then deleted, seams added and replaced). golangci-lint's `unused` linter catches unexported identifiers nobody references, but nothing reports exported functions that no executable reaches, so test-only helpers and leftovers can live in production packages unnoticed. The official `deadcode` tool answers exactly that question by whole-program reachability from `main`.

## What Changes

- Pin `golang.org/x/tools/cmd/deadcode` like the other Go tools (`install-deadcode`, installed by `make setup`) and add `make check-dead-code`, which fails when any function is unreachable from the two executables; tests are not roots, so test-only helpers in production code are findings. `make check` runs it.
- Remove the one finding today: the CLI's stdout-only `Run` wrapper, used by two tests, which now call the real entry point.
- Document the command and what a finding means.

## Capabilities

### New Capabilities

None.

### Modified Capabilities

- `project-bootstrap`: "Repeatable quality and smoke checks" gains the dead-code check among the static analyses.

## Impact

- `Makefile`, `README.md`, `internal/cli/cli.go` (delete `Run`), two CLI tests. No dependencies beyond the pinned tool binary under `.tools`.

## Non-goals

A baseline or allowlist mechanism (the tree is clean, so none is needed); dead-code detection for JavaScript; treating tests as roots.
