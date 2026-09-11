import assert from "node:assert/strict"
import { spawnSync } from "node:child_process"
import {
  cpSync,
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

function generate(path, check = false) {
  const result = spawnSync(
    join(root, ".tools/templ/bin/templ"),
    ["generate", "-path", path, ...(check ? ["-check"] : [])],
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

test("Make rejects unformatted templates without rewriting source or generated output", (t) => {
  mkdirSync(join(root, ".local"), { recursive: true })
  const directory = mkdtempSync(join(root, ".local/templ-format-"))
  t.after(() => rmSync(directory, { recursive: true, force: true }))
  for (const path of ["scripts", "internal/web"])
    mkdirSync(join(directory, path), { recursive: true })
  for (const path of ["Makefile", "scripts/check-web-generated.mjs"])
    cpSync(join(root, path), join(directory, path))
  symlinkSync(join(root, ".tools"), join(directory, ".tools"), "dir")
  writeFileSync(
    join(directory, "internal/web/fixture.templ"),
    "package fixture\n\ntempl Example() {\n<p>Unformatted</p>\n}\n",
  )
  const generated = generate(join(directory, "internal/web"))
  assert.equal(generated.status, 0, generated.stdout + generated.stderr)
  const before = snapshot(join(directory, "internal/web"))
  const result = spawnSync("make", ["check-web-generated"], {
    cwd: directory,
    encoding: "utf8",
  })
  assert.ifError(result.error)
  assert.equal(result.status, 2, result.stdout + result.stderr)
  assert.match(result.stderr, /needs formatting/)
  assert.deepEqual(snapshot(join(directory, "internal/web")), before)
})

test("repository template checks leave maintained and generated sources unchanged", () => {
  const directory = join(root, "internal/web")
  const before = snapshot(directory)
  const result = spawnSync("make", ["check-web-generated"], {
    cwd: root,
    encoding: "utf8",
  })
  assert.ifError(result.error)
  assert.equal(result.status, 0, result.stdout + result.stderr)
  assert.deepEqual(snapshot(directory), before)
})
