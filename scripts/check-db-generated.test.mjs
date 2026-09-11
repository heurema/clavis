import assert from "node:assert/strict"
import { spawnSync } from "node:child_process"
import {
  cpSync,
  existsSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  readdirSync,
  rmSync,
  statSync,
  symlinkSync,
  writeFileSync,
} from "node:fs"
import { join } from "node:path"
import { test } from "node:test"
import { fileURLToPath } from "node:url"

const root = fileURLToPath(new URL("../", import.meta.url))
const output = "internal/database/sqlc"
const query = "internal/database/queries/fixture.sql"

function fixture(t) {
  mkdirSync(join(root, ".local"), { recursive: true })
  const directory = mkdtempSync(join(root, ".local/check-db-generated-"))
  t.after(() => rmSync(directory, { recursive: true, force: true }))
  for (const path of ["Makefile", "sqlc.yaml"])
    cpSync(join(root, path), join(directory, path))
  for (const path of ["migrations", "queries"])
    mkdirSync(join(directory, "internal/database", path), { recursive: true })
  writeFileSync(
    join(directory, "internal/database/migrations/00001_fixture.sql"),
    "-- +goose Up\nCREATE TABLE fixtures (id bigint PRIMARY KEY);\n-- +goose Down\nDROP TABLE fixtures;\n",
  )
  writeFileSync(
    join(directory, query),
    "-- name: FindFixture :one\nSELECT id FROM fixtures WHERE id = $1;\n",
  )
  // Inputs outside the maintained SQL paths must never enter generation.
  for (const path of [
    ".env",
    "go.mod",
    "go.sum",
    "internal/web/assets/app.css",
  ]) {
    mkdirSync(join(directory, path, ".."), { recursive: true })
    writeFileSync(join(directory, path), "untouched sentinel\n")
  }
  return directory
}

function make(directory, target, expected = 0, tool) {
  const result = spawnSync(
    "make",
    [
      target,
      `SQLC=${tool ?? join(root, ".tools/sqlc/bin/sqlc")}`,
      "NODE=false",
      "PNPM=false",
    ],
    { cwd: directory, encoding: "utf8", timeout: 30_000 },
  )
  assert.ifError(result.error)
  assert.equal(result.status, expected, result.stdout + result.stderr)
  return result.stdout + result.stderr
}

function snapshot(directory) {
  return Object.fromEntries(
    readdirSync(directory, { recursive: true })
      .sort()
      .filter((path) => statSync(join(directory, path)).isFile())
      .map((path) => [
        path,
        {
          content: readFileSync(join(directory, path)).toString("base64"),
          modified: statSync(join(directory, path)).mtimeMs,
        },
      ]),
  )
}

function checkUnchanged(directory, expected = 0) {
  const before = snapshot(directory)
  const result = make(directory, "check-db-generated", expected)
  assert.deepEqual(snapshot(directory), before)
  return result
}

test("Make compares the complete generated tree without changing SQL, assets or source", (t) => {
  const directory = fixture(t)
  const inputs = snapshot(directory)
  make(directory, "generate-db")
  for (const [path, value] of Object.entries(inputs))
    assert.deepEqual(snapshot(directory)[path], value)
  checkUnchanged(directory)

  for (const [path, content] of [
    [`${output}/db.go`, "// stale\n"],
    [`${output}/db.go`, null],
    [`${output}/extra.go`, "// unexpected\n"],
    [`${output}/nested/extra.txt`, "unexpected non-Go file\n"],
  ]) {
    const absolute = join(directory, path)
    if (content === null) rmSync(absolute)
    else {
      mkdirSync(join(absolute, ".."), { recursive: true })
      writeFileSync(absolute, content)
    }
    assert.match(checkUnchanged(directory, 2), /db\.go|extra|nested/)
    make(directory, "generate-db")
    checkUnchanged(directory)
    assert.equal(existsSync(join(directory, output, "extra.go")), false)
    assert.equal(existsSync(join(directory, output, "nested")), false)
  }

  rmSync(join(directory, output), { recursive: true })
  checkUnchanged(directory, 2)
  make(directory, "generate-db")
  writeFileSync(
    join(directory, query),
    readFileSync(join(directory, query), "utf8").replace(
      "FindFixture",
      "FindChangedFixture",
    ),
  )
  checkUnchanged(directory, 2)
  make(directory, "generate-db")
  assert.match(
    readFileSync(join(directory, output, "fixture.sql.go"), "utf8"),
    /FindChangedFixture/,
  )
  checkUnchanged(directory)
})

test("native YAML comments and ordinary options preserve identical generation", (t) => {
  const directory = fixture(t)
  make(directory, "generate-db")
  const config = join(directory, "sqlc.yaml")
  writeFileSync(
    config,
    `# Maintained sqlc configuration\n---\n${readFileSync(config, "utf8")}`,
  )
  checkUnchanged(directory)
  // Native sqlc, not a bespoke options allowlist, owns valid configuration.
  writeFileSync(
    config,
    readFileSync(config, "utf8").replace(
      "package: sqlc",
      "package: sqlc\n        emit_sql_as_comment: true",
    ),
  )
  checkUnchanged(directory, 2)
  make(directory, "generate-db")
  checkUnchanged(directory)
})

test("invalid SQL or YAML never replaces existing generated output", (t) => {
  const directory = fixture(t)
  make(directory, "generate-db")
  for (const [path, broken] of [
    [query, "INVALID SQL"],
    ["sqlc.yaml", "version: [broken"],
  ]) {
    const absolute = join(directory, path)
    const original = readFileSync(absolute)
    writeFileSync(absolute, broken)
    const before = snapshot(directory)
    for (const target of ["check-db-generated", "generate-db"]) {
      make(directory, target, 2)
      assert.deepEqual(snapshot(directory), before)
    }
    writeFileSync(absolute, original)
  }
})

test("Make isolates generation, disables remote access and discards failed partial output", (t) => {
  const directory = fixture(t)
  make(directory, "generate-db")
  const tool = join(directory, "failing-sqlc")
  writeFileSync(
    tool,
    `#!/bin/sh
set -eu
test "$*" = "generate --no-remote"
test -f sqlc.yaml
test -f internal/database/queries/fixture.sql
test ! -e .env
test ! -e go.mod
test ! -e internal/web
test ! -e internal/database/sqlc
mkdir internal/database/sqlc
echo partial > internal/database/sqlc/db.go
echo isolated-generation >&2
exit 1
`,
    { mode: 0o755 },
  )
  const before = snapshot(directory)
  for (const target of ["check-db-generated", "generate-db"]) {
    assert.match(make(directory, target, 2, tool), /isolated-generation/)
    assert.deepEqual(snapshot(directory), before)
  }
})

test("fixed SQL input/output boundaries reject symlinks without changing their targets", (t) => {
  const directory = fixture(t)
  make(directory, "generate-db")
  for (const path of [
    "sqlc.yaml",
    "internal",
    "internal/database",
    "internal/database/migrations",
    query,
    output,
    `${output}/db.go`,
  ]) {
    const absolute = join(directory, path)
    const saved = join(directory, "saved")
    cpSync(absolute, saved, { recursive: true })
    rmSync(absolute, { recursive: true })
    symlinkSync(saved, absolute)
    const before = snapshot(directory)
    for (const target of ["check-db-generated", "generate-db"]) {
      make(directory, target, 2)
      assert.deepEqual(snapshot(directory), before)
    }
    rmSync(absolute)
    cpSync(saved, absolute, { recursive: true })
    rmSync(saved, { recursive: true })
  }
})

test("repository SQL checks leave maintained and generated files unchanged", () => {
  const paths = ["internal/database", "internal/web"]
  const before = paths.map((path) => snapshot(join(root, path)))
  const config = readFileSync(join(root, "sqlc.yaml"))
  make(root, "check-db-generated")
  assert.deepEqual(
    paths.map((path) => snapshot(join(root, path))),
    before,
  )
  assert.deepEqual(readFileSync(join(root, "sqlc.yaml")), config)
})
