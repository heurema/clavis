import assert from "node:assert/strict"
import {
  copyFileSync,
  existsSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  readdirSync,
  rmSync,
  symlinkSync,
  writeFileSync,
} from "node:fs"
import { join } from "node:path"
import { test } from "node:test"
import { fileURLToPath } from "node:url"
import { buildWebAssets } from "./build-web-assets.mjs"

const root = fileURLToPath(new URL("../", import.meta.url))

function fixture(t) {
  const local = join(root, ".local")
  mkdirSync(local, { recursive: true })
  const directory = mkdtempSync(join(local, "assets-test-"))
  t.after(() => rmSync(directory, { recursive: true, force: true }))
  for (const path of [
    "web/styles",
    "web/scripts",
    "internal/web/ui/utils",
    "internal/web/ui/icon",
  ])
    mkdirSync(join(directory, path), { recursive: true })
  for (const path of [
    "web/package.json",
    "web/styles/app.css",
    "web/scripts/appearance.js",
    "web/scripts/readiness.js",
    "internal/web/ui/utils/templui.go",
    "internal/web/ui/icon/icon.templ",
  ])
    copyFileSync(join(root, path), join(directory, path))
  symlinkSync(
    join(root, "web/node_modules"),
    join(directory, "web/node_modules"),
    "dir",
  )
  writeFileSync(
    join(directory, "internal/web/fixture.templ"),
    'package web\n\ntempl Fixture() { <div class="sr-only p-6">Fixture</div> }\n',
  )
  return directory
}

function snapshot(directory) {
  return Object.fromEntries(
    readdirSync(directory)
      .sort()
      .map((name) => [name, readFileSync(join(directory, name), "utf8")]),
  )
}

test("asset preparation is deterministic and packages only the public inputs", (t) => {
  const directory = fixture(t)
  const assets = join(directory, "internal/web/assets")
  buildWebAssets(directory)
  const first = snapshot(assets)
  assert.deepEqual(Object.keys(first), [
    "app.css",
    "appearance.js",
    "htmx.min.js",
    "notices.txt",
    "readiness.js",
  ])
  assert.match(first["app.css"], /\.sr-only/)
  assert.match(first["app.css"], /\.p-6/)
  assert.equal(
    first["htmx.min.js"],
    readFileSync(
      join(root, "web/node_modules/htmx.org/dist/htmx.min.js"),
      "utf8",
    ),
  )
  for (const notice of [
    "Axel Adrian",
    "Oudwin",
    "Cole Bemis",
    "htmx 4.0.0",
    "Tailwind CSS 4.3.3",
  ])
    assert.ok(first["notices.txt"].includes(notice), notice)
  writeFileSync(join(assets, ".private"), "SECRET")
  buildWebAssets(directory)
  assert.deepEqual(snapshot(assets), first)
  assert.equal(
    readdirSync(join(directory, "internal/web")).some((name) =>
      name.startsWith(".assets-"),
    ),
    false,
  )
})

for (const [name, damage] of [
  [
    "missing application script",
    (directory) => rmSync(join(directory, "web/scripts/readiness.js")),
  ],
  [
    "missing stylesheet",
    (directory) => rmSync(join(directory, "web/styles/app.css")),
  ],
  [
    "invalid stylesheet",
    (directory) =>
      writeFileSync(
        join(directory, "web/styles/app.css"),
        '@import "missing-clavis-stylesheet";',
      ),
  ],
  [
    "missing notices",
    (directory) =>
      writeFileSync(
        join(directory, "internal/web/ui/utils/templui.go"),
        "package utils\n",
      ),
  ],
  [
    "mismatched installed version",
    (directory) => {
      const manifest = JSON.parse(
        readFileSync(join(directory, "web/package.json"), "utf8"),
      )
      manifest.devDependencies["htmx.org"] = "0.0.0"
      writeFileSync(
        join(directory, "web/package.json"),
        JSON.stringify(manifest),
      )
    },
  ],
]) {
  test(`asset preparation fails closed with ${name}`, (t) => {
    const directory = fixture(t)
    buildWebAssets(directory)
    damage(directory)
    assert.throws(() => buildWebAssets(directory))
    assert.equal(existsSync(join(directory, "internal/web/assets")), false)
    assert.equal(
      readdirSync(join(directory, "internal/web")).some((entry) =>
        entry.startsWith(".assets-"),
      ),
      false,
    )
  })
}
