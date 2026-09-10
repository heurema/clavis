import { execFileSync } from "node:child_process"
import {
  cpSync,
  existsSync,
  lstatSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  readdirSync,
  renameSync,
  rmSync,
} from "node:fs"
import { tmpdir } from "node:os"
import { join, resolve } from "node:path"
import { fileURLToPath } from "node:url"

export const sqlInputs = [
  "sqlc.yaml",
  "internal/database/migrations",
  "internal/database/queries",
]
export const sqlOutput = "internal/database/sqlc"

export function pinnedVersion(root) {
  const version = readFileSync(join(root, ".sqlc-version"), "utf8").trim()
  if (!/^\d+\.\d+\.\d+$/.test(version))
    throw new Error("Expected an exact release in .sqlc-version")
  return version
}

export function verifySqlc(root) {
  const binary = join(root, ".tools/sqlc/bin/sqlc")
  if (!existsSync(binary))
    throw new Error("Missing pinned sqlc; run make install-sqlc")
  const expected = `v${pinnedVersion(root)}`
  const actual = execFileSync(binary, ["version"], { encoding: "utf8" }).trim()
  if (actual !== expected)
    throw new Error(`Expected sqlc ${expected}, found ${actual}`)
  return binary
}

function keys(value, allowed, label) {
  if (!value || typeof value !== "object" || Array.isArray(value))
    throw new Error(`Invalid ${label}`)
  for (const key of Object.keys(value))
    if (!allowed.includes(key))
      throw new Error(
        `Unsupported ${label} option ${key}; review isolation before extending`,
      )
}

function validateConfig(root) {
  // JSON is valid YAML. Use its standard parser rather than a partial YAML parser.
  // Keep paths and generators explicit: sqlc must never write outside isolation.
  const config = JSON.parse(readFileSync(join(root, "sqlc.yaml"), "utf8"))
  keys(config, ["version", "sql"], "sqlc config")
  if (
    config.version !== "2" ||
    !Array.isArray(config.sql) ||
    config.sql.length !== 1
  )
    throw new Error("Expected sqlc version 2 with one SQL block")
  const block = config.sql[0]
  keys(block, ["engine", "schema", "queries", "gen"], "SQL block")
  if (
    block.engine !== "postgresql" ||
    block.schema !== sqlInputs[1] ||
    block.queries !== sqlInputs[2]
  )
    throw new Error(
      "SQL inputs must use the approved migrations and queries directories",
    )
  keys(block.gen, ["go"], "generators")
  const go = block.gen.go
  keys(
    go,
    [
      "package",
      "out",
      "sql_package",
      "overrides",
      "omit_unused_structs",
      "emit_json_tags",
      "emit_interface",
      "emit_empty_slices",
      "emit_pointers_for_null_types",
    ],
    "Go generator",
  )
  if (
    go.package !== "sqlc" ||
    go.out !== sqlOutput ||
    go.sql_package !== "pgx/v5"
  )
    throw new Error(
      "Expected package sqlc, pgx/v5 and output internal/database/sqlc",
    )
  if (
    Object.hasOwn(go, "omit_unused_structs") &&
    typeof go.omit_unused_structs !== "boolean"
  )
    throw new Error("Expected boolean Go generator option omit_unused_structs")
}

function files(directory, prefix = "") {
  if (!existsSync(directory)) return []
  return readdirSync(directory)
    .sort()
    .flatMap((name) => {
      const path = join(directory, name)
      const stat = lstatSync(path)
      if (stat.isSymbolicLink())
        throw new Error(
          `Symlinks are not allowed in sqlc inputs/output: ${path}`,
        )
      if (stat.isDirectory()) return files(path, `${prefix}${name}/`)
      if (!stat.isFile()) throw new Error(`Expected a regular file: ${path}`)
      return [`${prefix}${name}`]
    })
}

export function copySqlInputs(root, workspace) {
  validateConfig(root)
  for (const path of sqlInputs) {
    const source = join(root, path)
    // Check each parent too: cpSync must not follow a directory link outside root.
    let ancestor = root
    for (const part of path.split("/")) {
      ancestor = join(ancestor, part)
      if (lstatSync(ancestor).isSymbolicLink())
        throw new Error(`Symlinks are not allowed in sqlc inputs: ${ancestor}`)
    }
    if (lstatSync(source).isDirectory()) files(source)
    mkdirSync(join(workspace, path, ".."), { recursive: true })
    cpSync(source, join(workspace, path), { recursive: true })
  }
}

function install(root) {
  const version = pinnedVersion(root)
  const destination = join(root, ".tools/sqlc/bin")
  if (existsSync(join(destination, "sqlc"))) {
    verifySqlc(root)
    return
  }
  mkdirSync(join(root, ".tools/sqlc"), { recursive: true })
  const temporary = mkdtempSync(join(root, ".tools/sqlc/.install-"))
  try {
    execFileSync(
      "go",
      ["install", `github.com/sqlc-dev/sqlc/cmd/sqlc@v${version}`],
      {
        cwd: temporary,
        env: { ...process.env, GOBIN: temporary, GOWORK: "off" },
        stdio: "inherit",
      },
    )
    const actual = execFileSync(join(temporary, "sqlc"), ["version"], {
      encoding: "utf8",
    }).trim()
    if (actual !== `v${version}`)
      throw new Error(`Expected sqlc v${version}, found ${actual}`)
    renameSync(temporary, destination)
  } finally {
    rmSync(temporary, { recursive: true, force: true })
  }
}

export function runSqlc(root, command) {
  if (!["install", "generate", "check", "version"].includes(command))
    throw new Error(
      "Usage: node scripts/sqlc.mjs install|generate|check|version",
    )
  if (command === "install") return install(root)
  const binary = verifySqlc(root)
  if (command === "version") return console.log(`sqlc v${pinnedVersion(root)}`)
  const workspace = mkdtempSync(join(tmpdir(), "clavis-sqlc-"))
  try {
    copySqlInputs(root, workspace)
    execFileSync(binary, ["generate", "-f", "sqlc.yaml"], {
      cwd: workspace,
      stdio: "inherit",
    })
    const generated = join(workspace, sqlOutput)
    const expected = files(generated)
    if (!expected.length) throw new Error("sqlc produced no generated files")
    const destination = join(root, sqlOutput)
    // Reject output links before either reading or replacing the generated tree.
    let ancestor = root
    for (const part of sqlOutput.split("/")) {
      ancestor = join(ancestor, part)
      if (existsSync(ancestor) && lstatSync(ancestor).isSymbolicLink())
        throw new Error(`Symlinks are not allowed in sqlc output: ${ancestor}`)
    }
    const actual = files(destination)
    if (command === "check") {
      const changed = [...new Set([...expected, ...actual])].filter(
        (file) =>
          !expected.includes(file) ||
          !actual.includes(file) ||
          !readFileSync(join(generated, file)).equals(
            readFileSync(join(destination, file)),
          ),
      )
      if (changed.length)
        throw new Error(
          `Stale/missing sqlc output: ${changed.join(", ")}; run make generate-db`,
        )
      console.log("[sqlc] Generated database source is current")
    } else {
      // This directory is exclusively generated. Explicit generation also removes
      // obsolete files, so its result matches a fresh sqlc invocation exactly.
      rmSync(destination, { recursive: true, force: true })
      cpSync(generated, destination, { recursive: true })
    }
  } finally {
    rmSync(workspace, { recursive: true, force: true })
  }
}

if (
  process.argv[1] &&
  resolve(process.argv[1]) === fileURLToPath(import.meta.url)
) {
  try {
    if (process.argv.length !== 3)
      throw new Error("Expected exactly one sqlc command")
    runSqlc(fileURLToPath(new URL("../", import.meta.url)), process.argv[2])
  } catch (error) {
    console.error(`[sqlc] ${error.message}`)
    process.exitCode = 1
  }
}
