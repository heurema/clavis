import assert from "node:assert/strict"
import { spawnSync } from "node:child_process"
import {
  existsSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  readdirSync,
  rmSync,
} from "node:fs"
import { join, relative } from "node:path"
import { test } from "node:test"
import { fileURLToPath } from "node:url"
import {
  copyMutationInputs,
  goSources,
  isMutationTarget,
} from "./mutation-inputs.mjs"

const root = fileURLToPath(new URL("../", import.meta.url))

test("mutation targets include handwritten web behavior, not generated/vendor/fixture code", () => {
  const targets = goSources(root)
    .filter((path) => isMutationTarget(root, path))
    .map((path) => relative(root, path))
  for (const path of [
    "internal/web/assets.go",
    "internal/web/readiness.go",
    "internal/web/render.go",
    "internal/auth/password.go",
    "internal/platform/readiness.go",
    "internal/database/initialize.go",
  ])
    assert(targets.includes(path), `Missing mutation target ${path}`)
  assert(targets.some((path) => path.startsWith("internal/cli/")))
  assert(targets.some((path) => path.startsWith("internal/config/")))
  assert(targets.some((path) => path.startsWith("internal/server/")))
  assert(
    !targets.some((path) =>
      /(^cmd\/|\/ui\/|\/testdata\/|\/authtest\/|\/sqlc\/|_test\.go$|_templ\.go$)/.test(
        path,
      ),
    ),
  )
})

test("isolated mutation inputs compile with embedded assets and exclude developer files", (t) => {
  mkdirSync(join(root, ".local"), { recursive: true })
  const workspace = mkdtempSync(join(root, ".local/mutation-inputs-test-"))
  t.after(() => rmSync(workspace, { recursive: true, force: true }))
  copyMutationInputs(root, workspace, goSources(root))
  for (const path of [".env", ".tools", "reports", "web"])
    assert.equal(existsSync(join(workspace, path)), false)
  for (const name of readdirSync(join(root, "internal/web/assets")))
    assert.deepEqual(
      readFileSync(join(workspace, "internal/web/assets", name)),
      readFileSync(join(root, "internal/web/assets", name)),
    )
  assert.deepEqual(
    readFileSync(join(workspace, "sqlc.yaml")),
    readFileSync(join(root, "sqlc.yaml")),
  )
  for (const directory of ["migrations", "queries", "sqlc"])
    for (const name of readdirSync(join(root, "internal/database", directory)))
      assert.deepEqual(
        readFileSync(join(workspace, "internal/database", directory, name)),
        readFileSync(join(root, "internal/database", directory, name)),
      )
  const result = spawnSync("go", ["test", "./..."], {
    cwd: workspace,
    encoding: "utf8",
    timeout: 120_000,
  })
  assert.ifError(result.error)
  assert.equal(result.status, 0, result.stdout + result.stderr)
})
