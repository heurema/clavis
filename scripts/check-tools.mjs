import { readFileSync } from "node:fs"
import { execFileSync } from "node:child_process"
import { fileURLToPath } from "node:url"
import { pinnedVersion } from "./sqlc.mjs"

const expectedNode = readFileSync(
  new URL("../.node-version", import.meta.url),
  "utf8",
).trim()
const expectedGo = readFileSync(
  new URL("../go.mod", import.meta.url),
  "utf8",
).match(/^go (.+)$/m)[1]
const manifest = JSON.parse(
  readFileSync(new URL("../web/package.json", import.meta.url), "utf8"),
)
const expectedPnpm = manifest.packageManager.split("@")[1]
try {
  // Setup runs before tool installation; validate the pin, not binary presence.
  console.log(
    `sqlc pin ${pinnedVersion(fileURLToPath(new URL("../", import.meta.url)))}`,
  )
  for (const [name, actual, expected] of [
    ["Node.js", process.versions.node, expectedNode],
    [
      "Go",
      execFileSync("go", ["env", "GOVERSION"], { encoding: "utf8" }).trim(),
      `go${expectedGo}`,
    ],
    [
      "pnpm",
      execFileSync("pnpm", ["--version"], { encoding: "utf8" }).trim(),
      expectedPnpm,
    ],
  ]) {
    if (actual !== expected)
      throw new Error(
        `${name}: expected ${expected}, found ${actual}. Install the documented version before setup.`,
      )
    console.log(`${name} ${actual}`)
  }
} catch (error) {
  console.error(error.message)
  process.exitCode = 1
}
