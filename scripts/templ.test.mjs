import assert from "node:assert/strict"
import { spawnSync } from "node:child_process"
import {
  mkdirSync,
  mkdtempSync,
  readFileSync,
  readdirSync,
  rmSync,
  statSync,
  writeFileSync,
} from "node:fs"
import { join } from "node:path"
import { test } from "node:test"
import { fileURLToPath } from "node:url"

const root = fileURLToPath(new URL("../", import.meta.url))

function generate(path, check = false) {
  const result = spawnSync(
    process.execPath,
    [
      "scripts/templ.mjs",
      "generate",
      "-path",
      path,
      ...(check ? ["-check"] : []),
    ],
    { cwd: root, encoding: "utf8" },
  )
  assert.ifError(result.error)
  return result
}

function snapshot(directory) {
  return Object.fromEntries(
    readdirSync(directory, { recursive: true })
      .sort()
      .filter((file) => statSync(join(directory, file)).isFile())
      .map((file) => [
        file,
        {
          content: readFileSync(join(directory, file), "utf8"),
          modified: statSync(join(directory, file)).mtimeMs,
        },
      ]),
  )
}

test("generation checks detect stale or missing output without rewriting files", (t) => {
  const local = join(root, ".local")
  mkdirSync(local, { recursive: true })
  const directory = mkdtempSync(join(local, "templ-check-"))
  t.after(() => rmSync(directory, { recursive: true, force: true }))
  const source = join(directory, "fixture.templ")
  const generated = join(directory, "fixture_templ.go")
  writeFileSync(
    source,
    "package fixture\n\ntempl Example() {\n\t<p>Original</p>\n}\n",
  )

  const first = generate(directory)
  assert.equal(first.status, 0, first.stdout + first.stderr)
  const initial = snapshot(directory)
  assert.equal(generate(directory, true).status, 0)
  assert.deepEqual(snapshot(directory), initial)

  writeFileSync(
    source,
    readFileSync(source, "utf8").replace("Original", "Changed"),
  )
  const stale = snapshot(directory)
  const check = generate(directory, true)
  assert.notEqual(check.status, 0, "stale generated output must fail")
  assert.deepEqual(snapshot(directory), stale)

  const explicit = generate(directory)
  assert.equal(explicit.status, 0, explicit.stdout + explicit.stderr)
  assert.match(readFileSync(generated, "utf8"), /Changed/)
  assert.equal(generate(directory, true).status, 0)

  rmSync(generated)
  const missing = snapshot(directory)
  assert.notEqual(generate(directory, true).status, 0)
  assert.deepEqual(snapshot(directory), missing)
})

test("repository template checks leave maintained and generated sources unchanged", () => {
  const directory = join(root, "internal/web")
  const before = snapshot(directory)
  const result = spawnSync(
    process.execPath,
    ["scripts/check-web-generated.mjs"],
    {
      cwd: root,
      encoding: "utf8",
    },
  )
  assert.ifError(result.error)
  assert.equal(result.status, 0, result.stdout + result.stderr)
  assert.deepEqual(snapshot(directory), before)
})
