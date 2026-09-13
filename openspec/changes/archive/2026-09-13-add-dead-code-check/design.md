## Context

golangci-lint (pinned, `standard` linters) already runs `unused`, which finds unexported identifiers with no references inside a package. `golang.org/x/tools/cmd/deadcode` builds the SSA call graph from `main` packages and reports functions no executable can reach; `-test` would add test binaries as roots, which hides test-only helpers living in production code. The tool exits 0 whatever it finds, so the check must fail on output. Versions of `x/tools` before 0.50.0 panic on Go 1.27 syntax in this module.

## Goals / Non-Goals

**Goals:** one command, pinned, in `make check` and `make setup`, failing on any finding.
**Non-Goals:** baselines, JavaScript, tests as roots.

## Inherited decisions

| Decision | Source | Status |
|---|---|---|
| Pinned tool binaries under `.tools`, installed by `make setup` with versioned `go install` | project-bootstrap "Documented and reproducible project setup" | Retained; `DEADCODE_VERSION := 0.50.0`, `.tools/deadcode/bin/deadcode` |
| `make check` is the non-mutating gate and identifies the failing stage | project-bootstrap "Repeatable quality and smoke checks" | Extended with `check-dead-code` after `lint-go` |

## Decisions

1. **Roots are the executables only.** `deadcode ./...` without `-test`. A function only tests reach is dead production code and is reported; the fix is to move it into a test file or delete it. The single current finding, `cli.Run`, is deleted and its two tests call `RunWithIO`.
2. **Fail on output.** The target captures the tool's output and exits 1 when it is non-empty, printing it first so the stage names the function and location.
3. **Generated code** is included in the analysis (it is real code the executables link) but the tool's `-generated` flag is not set, so a generated function nobody calls is reported like any other; sqlc only generates methods for queries that exist, so this is a check on query files too.

## Risks / Trade-offs

- [A legitimately exported library function with no caller yet] → this module has no library consumers; add the caller or delete the function.
- [Tool panics on a future Go syntax] → bump the pin; the check names the tool version in its output on failure.

## Migration Plan

None.

## Open Questions

None.
