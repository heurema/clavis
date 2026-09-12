## Context

`scripts/mutation.mjs` copies handwritten Go sources into a temporary workspace without git metadata, runs the baseline tests there, then runs Gremlins 0.6.0 with `--exclude-files` for every non-eligible file. Gremlins has a `--diff <ref>` option, but it needs a git checkout in its working directory, which the isolated copy is not. Workers default to two and each test run is pinned to one core.

## Goals / Non-Goals

**Goals:** a per-change run in minutes; the full run unchanged in meaning; no new tooling.
**Non-Goals:** line-level diffs, test tagging, CI.

## Inherited decisions

| Decision | Source | Status |
|---|---|---|
| Isolated copy, compatibility probe, source-unchanged check, machine-readable summary | project-bootstrap "Focused mutation testing" | Retained |
| Exclusions by file regexp | `.gremlins.yaml` and the wrapper | Retained; diff mode adds exclusions for unchanged eligible files |
| Default bound 600 s; extended budget documented | archived add-connections tasks 7.3 | Explicitly changed: 600 s stays for the diff-scoped default, the full command defaults to 3,600 s |

## Decisions

1. **File-level selection in the repository root.** `changedSources(root, ref)` in `mutation-inputs.mjs` returns the union of `git diff --name-only <ref> -- '*.go'` (committed and working-tree differences against the ref) and `git ls-files --others --exclude-standard -- '*.go'` (new files), resolved to absolute paths. Targets are the eligible sources in that set; every other eligible source is added to `--exclude-files`. A ref that `git rev-parse --verify` rejects fails the run with a message naming `CLAVIS_MUTATION_DIFF`. An empty `CLAVIS_MUTATION_DIFF` means full scope.
2. **Report fields.** `run.scope` is `{ "mode": "diff", "ref": "main" }` or `{ "mode": "full" }`; `run.targets` already lists the selected files. The empty message names the ref.
3. **Workers.** `Math.max(1, availableParallelism() - 2)` from `node:os` when `CLAVIS_MUTATION_WORKERS` is unset.
4. **Makefile.** `test-mutation` unchanged in shape (diff default comes from the script); `test-mutation-full` sets `CLAVIS_MUTATION_DIFF=` and `CLAVIS_MUTATION_TIMEOUT_SECONDS` to 3,600 unless already set.
5. **Baseline tests** still run for the whole copy: a diff-scoped run must not skip the proof that the suite passes.

## Risks / Trade-offs

- [A changed file's tests live elsewhere] → mutants are still run against the whole package's tests, as before; only target selection narrows.
- [Diff against a stale local `main`] → the report names the ref; contributors fetch before archiving, and the full command exists for that step.

## Migration Plan

None; tooling only.

## Open Questions

None.
