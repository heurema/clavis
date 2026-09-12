## MODIFIED Requirements

### Requirement: Focused mutation testing

The project SHALL provide a documented, non-interactive mutation-testing command separate from ordinary quality and smoke checks. The command SHALL test selected handwritten backend behavior using the existing Go tests, exclude generated code and test files from mutation targets, and produce a machine-readable report that distinguishes detected, surviving, uncovered, timed-out, and non-viable mutations. The initial bootstrap SHALL report findings without imposing a numerical mutation-score threshold.

The default command SHALL scope mutation targets to the eligible files that differ from a documented base ref (`CLAVIS_MUTATION_DIFF`, default `main`), including uncommitted and untracked files, and a separate documented command SHALL run the full scope with a documented extended bound. The report SHALL state the scope it ran with (the base ref or full) and the targets selected. When the base ref cannot be resolved, the command SHALL fail with a diagnostic naming the variable rather than silently running the full scope. Concurrency SHALL default to the available processor count minus two, at least one, and remain overridable.

The command SHALL fail with a nonzero exit status if the baseline tests fail or the tool cannot complete the analysis. A run with no eligible mutations SHALL explicitly report that state without claiming test effectiveness. The command SHALL use documented resource bounds and leave application source unchanged after completion or failure.

#### Scenario: Evaluate tests for selected backend logic
- **WHEN** a contributor runs mutation testing with passing baseline tests and eligible mutations in the configured scope
- **THEN** the command produces a machine-readable report identifying each mutation's location and outcome
- **AND** surviving mutations remain visible even though the initial reporting mode does not enforce a numerical score threshold

#### Scenario: Diff-scoped run
- **WHEN** a contributor runs the default command on a branch that changed two eligible files against the base ref
- **THEN** only mutations in those two files are executed, the report names them and the base ref, and every other file is excluded

#### Scenario: Nothing changed against the base ref
- **WHEN** the default command runs on a checkout identical to the base ref for every eligible file
- **THEN** it reports the empty state naming the base ref, exits successfully and claims no effectiveness

#### Scenario: Full scope on request
- **WHEN** a contributor runs the full-scope command
- **THEN** every eligible file is a target and the report states the full scope

#### Scenario: Exclude generated and test code
- **WHEN** generated query code or test files exist alongside the selected application logic
- **THEN** the command does not mutate those files or include them as mutation targets in its score

#### Scenario: Detect an invalid or incomplete run
- **WHEN** baseline tests fail, the tool is incompatible with the selected runtime, the base ref cannot be resolved, or the overall analysis cannot complete within its configured bound
- **THEN** the command exits unsuccessfully with a useful diagnostic and does not present a partial or previous report as a successful current run

#### Scenario: Preserve source and report an empty scope
- **WHEN** a mutation run completes or fails, including a run with no eligible mutations
- **THEN** application source retains its original contents
- **AND** a run with no eligible mutations explicitly reports that state without claiming a successful mutation score
