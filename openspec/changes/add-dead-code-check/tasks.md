One slice; implementation and independent acceptance review are separate tasks. Expect under 60 changed handwritten lines.

## 1. Dead-code check

Requirements: project-bootstrap "Repeatable quality and smoke checks" (dead-code scenario). Owned paths: `Makefile`, `README.md`, `internal/cli/cli.go`, `internal/cli/cli_test.go`, `internal/cli/io_test.go`. Verify: `make install-deadcode && make check-dead-code && make check`, and a deliberate unreachable function makes `make check-dead-code` fail naming it.

- [x] 1.1 Pin and install `deadcode` 0.50.0 under `.tools`, add `check-dead-code` (fails on any output) to `check`, add the install to `setup`, delete the CLI's `Run` wrapper and point its two tests at `RunWithIO`, document the command.
- [x] 1.2 Independent acceptance review; record the revision. Reviewed 2026-09-13 on the working tree over `da0f385`: ACCEPT WITH FOLLOW-UPS, both applied (the README pin-provenance sentence names `DEADCODE_VERSION`; a test buffer renamed after the removed wrapper). Verified: the target follows the golangci-lint pinning pattern, fails with exit 1 naming the function, location and tool version on any finding, passes with a success line otherwise, and a missing binary fails rather than passes; `make check` passes with the stage; the deliberate unreachable-function probe failed as specified. Handwritten about 50 changed lines.
