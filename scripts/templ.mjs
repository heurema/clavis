import { execFileSync, spawnSync } from "node:child_process"
import {
  existsSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  renameSync,
  rmSync,
} from "node:fs"
import { join } from "node:path"
import { fileURLToPath } from "node:url"

// The runtime requirement is also the compiler pin: upgrade them together.
const root = fileURLToPath(new URL("../", import.meta.url))
const version = readFileSync(join(root, "go.mod"), "utf8").match(
  /^\s*github\.com\/a-h\/templ (v\S+)$/m,
)?.[1]
const tools = join(root, ".tools")

function verify(binary) {
  const actual = execFileSync(binary, ["version"], { encoding: "utf8" }).trim()
  if (actual !== version)
    throw new Error(`Expected templ ${version}, found ${actual}`)
}

try {
  if (!version) throw new Error("Missing exact templ runtime version in go.mod")
  const destination = join(tools, `templ-${version}`)
  const binary = join(destination, "templ")
  if (!existsSync(binary)) {
    mkdirSync(tools, { recursive: true })
    const temporary = mkdtempSync(join(tools, ".templ-"))
    try {
      console.log(`[templ] Installing ${version} into .tools`)
      execFileSync(
        "go",
        ["install", `github.com/a-h/templ/cmd/templ@${version}`],
        {
          cwd: root,
          env: { ...process.env, GOBIN: temporary },
          stdio: "inherit",
        },
      )
      verify(join(temporary, "templ"))
      renameSync(temporary, destination)
    } finally {
      rmSync(temporary, { recursive: true, force: true })
    }
  }
  verify(binary)
  const args = process.argv.slice(2)
  const result = spawnSync(binary, args[0] === "install" ? ["version"] : args, {
    cwd: root,
    stdio: "inherit",
  })
  if (result.error) throw result.error
  process.exitCode = result.status ?? 1
} catch (error) {
  console.error(`[templ] ${error.message}`)
  process.exitCode = 1
}
