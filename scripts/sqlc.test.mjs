import assert from "node:assert/strict"
import {
  chmodSync,
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
import { runSqlc, sqlInputs, sqlOutput } from "./sqlc.mjs"

const root = fileURLToPath(new URL("../", import.meta.url))

function fixture(t) {
  mkdirSync(join(root, ".local"), { recursive: true })
  const directory = mkdtempSync(join(root, ".local/sqlc-test-"))
  t.after(() => rmSync(directory, { recursive: true, force: true }))
  writeFileSync(join(directory, ".sqlc-version"), "1.31.1\n")
  writeFileSync(join(directory, "go.mod"), "module fixture\n\ngo 1.27.1\n")
  writeFileSync(
    join(directory, "go.sum"),
    "// maintained dependency sentinel\n",
  )
  mkdirSync(join(directory, ".tools/sqlc/bin"), { recursive: true })
  symlinkSync(
    join(root, ".tools/sqlc/bin/sqlc"),
    join(directory, ".tools/sqlc/bin/sqlc"),
  )
  for (const path of sqlInputs.slice(1))
    mkdirSync(join(directory, path), { recursive: true })
  writeFileSync(
    join(directory, "sqlc.yaml"),
    JSON.stringify({
      version: "2",
      sql: [
        {
          engine: "postgresql",
          schema: sqlInputs[1],
          queries: sqlInputs[2],
          gen: {
            go: { package: "sqlc", out: sqlOutput, sql_package: "pgx/v5" },
          },
        },
      ],
    }),
  )
  writeFileSync(
    join(directory, sqlInputs[1], "00001_fixture.sql"),
    "-- +goose Up\nCREATE TABLE fixtures (id bigint PRIMARY KEY);\n-- +goose Down\nDROP TABLE fixtures;\n",
  )
  writeFileSync(
    join(directory, sqlInputs[2], "fixture.sql"),
    "-- name: FindFixture :one\nSELECT id FROM fixtures WHERE id = $1;\n",
  )
  return directory
}

function snapshot(root) {
  function walk(directory, prefix = "") {
    return readdirSync(directory, { withFileTypes: true }).flatMap((entry) => {
      if (entry.name === ".tools") return []
      const path = join(directory, entry.name)
      const name = `${prefix}${entry.name}`
      return entry.isDirectory()
        ? walk(path, `${name}/`)
        : [
            [
              name,
              {
                content: readFileSync(path).toString("base64"),
                modified: statSync(path).mtimeMs,
              },
            ],
          ]
    })
  }
  return Object.fromEntries(walk(root))
}

function failsUnchanged(directory, command, pattern) {
  const before = snapshot(directory)
  assert.throws(() => runSqlc(directory, command), pattern)
  assert.deepEqual(snapshot(directory), before)
}

test("pinned sqlc generates and checks isolated complete file sets without input writes", (t) => {
  const directory = fixture(t)
  const inputs = snapshot(directory)
  runSqlc(directory, "generate")
  for (const [path, value] of Object.entries(inputs))
    assert.deepEqual(snapshot(directory)[path], value)
  const initial = snapshot(directory)
  runSqlc(directory, "check")
  assert.deepEqual(snapshot(directory), initial)

  const query = join(directory, sqlInputs[2], "fixture.sql")
  writeFileSync(
    query,
    readFileSync(query, "utf8").replace("FindFixture", "FindChangedFixture"),
  )
  failsUnchanged(directory, "check", /Stale\/missing/)
  runSqlc(directory, "generate")
  assert.match(
    readFileSync(join(directory, sqlOutput, "fixture.sql.go"), "utf8"),
    /FindChangedFixture/,
  )
  runSqlc(directory, "check")

  rmSync(join(directory, sqlOutput, "db.go"))
  failsUnchanged(directory, "check", /db\.go/)
  runSqlc(directory, "generate")
  writeFileSync(join(directory, sqlOutput, "obsolete.go"), "// obsolete\n")
  failsUnchanged(directory, "check", /obsolete\.go/)
  runSqlc(directory, "generate")
  assert.equal(existsSync(join(directory, sqlOutput, "obsolete.go")), false)
  rmSync(join(directory, sqlOutput), { recursive: true })
  failsUnchanged(directory, "check", /Stale\/missing/)
  runSqlc(directory, "generate")
  const removedQuery = join(directory, sqlInputs[2], "removed.sql")
  writeFileSync(
    removedQuery,
    "-- name: CountFixtures :one\nSELECT count(*) FROM fixtures;\n",
  )
  runSqlc(directory, "generate")
  rmSync(removedQuery)
  failsUnchanged(directory, "check", /removed\.sql\.go/)
  runSqlc(directory, "generate")
  assert.equal(existsSync(join(directory, sqlOutput, "removed.sql.go")), false)
  rmSync(query)
  failsUnchanged(directory, "check", /./)
})

test("omit_unused_structs filters only unused models and preserves isolated query output", (t) => {
  const directory = fixture(t)
  writeFileSync(
    join(directory, sqlInputs[1], "00002_details.sql"),
    "-- +goose Up\nCREATE TABLE fixture_details (id bigint PRIMARY KEY, title text NOT NULL);\n-- +goose Down\nDROP TABLE fixture_details;\n",
  )
  writeFileSync(
    join(directory, sqlInputs[2], "details.sql"),
    "-- name: FindFixtureDetail :one\nSELECT * FROM fixture_details WHERE id = $1;\n",
  )
  const path = join(directory, "sqlc.yaml")
  const config = JSON.parse(readFileSync(path, "utf8"))
  config.sql[0].gen.go.omit_unused_structs = false
  writeFileSync(path, JSON.stringify(config))
  runSqlc(directory, "generate")
  const unfiltered = snapshot(join(directory, sqlOutput))
  const models = join(directory, sqlOutput, "models.go")
  assert.match(readFileSync(models, "utf8"), /type Fixture struct/)
  assert.match(readFileSync(models, "utf8"), /type FixtureDetail struct/)

  config.sql[0].gen.go.omit_unused_structs = true
  writeFileSync(path, JSON.stringify(config))
  failsUnchanged(directory, "check", /models\.go/)
  const inputs = snapshot(directory)
  runSqlc(directory, "generate")
  const generated = snapshot(directory)
  for (const [path, value] of Object.entries(inputs))
    if (!path.startsWith(`${sqlOutput}/`))
      assert.deepEqual(generated[path], value)
  const filtered = snapshot(join(directory, sqlOutput))
  assert.deepEqual(Object.keys(filtered), Object.keys(unfiltered))
  for (const [path, value] of Object.entries(unfiltered))
    if (path !== "models.go")
      assert.equal(filtered[path].content, value.content)
  assert.doesNotMatch(readFileSync(models, "utf8"), /type Fixture struct/)
  assert.match(readFileSync(models, "utf8"), /type FixtureDetail struct/)
  runSqlc(directory, "check")
  assert.deepEqual(snapshot(directory), generated)
  rmSync(models)
  failsUnchanged(directory, "check", /models\.go/)
})

test("wrong/missing tools and malformed pins fail closed even for install", (t) => {
  const directory = fixture(t)
  const binary = join(directory, ".tools/sqlc/bin/sqlc")
  rmSync(binary)
  failsUnchanged(directory, "check", /Missing pinned sqlc/)
  writeFileSync(binary, "#!/bin/sh\nprintf 'v0.0.0\\n'\n")
  chmodSync(binary, 0o755)
  for (const command of ["check", "generate", "install"])
    failsUnchanged(directory, command, /Expected sqlc v1\.31\.1/)
  assert.equal(readFileSync(binary, "utf8"), "#!/bin/sh\nprintf 'v0.0.0\\n'\n")
  writeFileSync(join(directory, ".sqlc-version"), "latest\n")
  failsUnchanged(directory, "install", /exact release/)
  failsUnchanged(directory, "wat", /Usage/)
})

test("failed explicit installation preserves pins and cleans partial tools", (t) => {
  const directory = fixture(t)
  rmSync(join(directory, ".tools/sqlc/bin"), { recursive: true })
  const path = process.env.PATH
  try {
    // No compiler on PATH: installation must fail, not fall back to another pin.
    process.env.PATH = join(directory, ".tools")
    failsUnchanged(directory, "install", /ENOENT/)
  } finally {
    process.env.PATH = path
  }
  assert.deepEqual(readdirSync(join(directory, ".tools/sqlc")), [])
})

test("invalid SQL/config and escaping paths never modify source", (t) => {
  const directory = fixture(t)
  runSqlc(directory, "generate")
  const path = join(directory, "sqlc.yaml")
  const config = JSON.parse(readFileSync(path, "utf8"))
  config.sql[0].gen.go.omit_unused_structs = true
  const valid = JSON.stringify(config)
  for (const edit of [
    (config) => {
      config.sql[0].gen.go.out = root
    },
    (config) => {
      config.sql[0].schema = "../schema.sql"
    },
    (config) => {
      config.sql[0].gen.go.output_db_file_name = "../escaped.go"
    },
    (config) => {
      config.plugins = [{ name: "arbitrary" }]
    },
    (config) => {
      config.sql[0].engine = "mysql"
    },
    (config) => {
      config.sql[0].gen.go.emit_sql_as_comment = true
    },
    (config) => {
      config.sql[0].gen.plugin = {}
    },
  ]) {
    const config = JSON.parse(valid)
    edit(config)
    writeFileSync(path, JSON.stringify(config))
    failsUnchanged(directory, "check", /./)
    failsUnchanged(directory, "generate", /./)
  }
  for (const value of ["true", 1, null, {}, []]) {
    const config = JSON.parse(valid)
    config.sql[0].gen.go.omit_unused_structs = value
    writeFileSync(path, JSON.stringify(config))
    for (const command of ["check", "generate"])
      failsUnchanged(
        directory,
        command,
        /Expected boolean.*omit_unused_structs/,
      )
  }
  writeFileSync(path, "version: [broken")
  failsUnchanged(directory, "check", /JSON/)
  writeFileSync(path, valid)
  writeFileSync(join(directory, sqlInputs[2], "fixture.sql"), "INVALID SQL")
  failsUnchanged(directory, "generate", /Command failed/)
  rmSync(path)
  failsUnchanged(directory, "check", /ENOENT/)
})

test("sqlc input isolation rejects symlinks, including directory ancestors", (t) => {
  const directory = fixture(t)
  const queries = join(directory, sqlInputs[2])
  const original = join(directory, "fixture-queries")
  cpSync(queries, original, { recursive: true })
  rmSync(queries, { recursive: true })
  symlinkSync(original, queries, "dir")
  assert.throws(() => runSqlc(directory, "check"), /Symlinks/)
})

test("repository sqlc checks leave maintained/generated inputs unchanged", () => {
  const paths = [".sqlc-version", ...sqlInputs, sqlOutput]
  const before = Object.fromEntries(
    paths.map((path) => [
      path,
      statSync(join(root, path)).isDirectory()
        ? snapshot(join(root, path))
        : readFileSync(join(root, path)).toString("base64"),
    ]),
  )
  runSqlc(root, "check")
  for (const [path, expected] of Object.entries(before))
    assert.deepEqual(
      statSync(join(root, path)).isDirectory()
        ? snapshot(join(root, path))
        : readFileSync(join(root, path)).toString("base64"),
      expected,
    )
})
