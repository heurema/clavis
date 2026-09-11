import { execFileSync } from "node:child_process"
import { readFileSync, readdirSync } from "node:fs"
import { fileURLToPath } from "node:url"

const templ = fileURLToPath(
  new URL("../.tools/templ/bin/templ", import.meta.url),
)

try {
  execFileSync(templ, ["generate", "-check", "-path", "internal/web"], {
    stdio: "inherit",
  })
  for (const file of readdirSync("internal/web", { recursive: true }).sort()) {
    if (!file.endsWith(".templ")) continue
    const path = `internal/web/${file}`
    // fmt -fail still writes files. Compare stdout instead to keep checks read-only.
    const formatted = execFileSync(templ, ["fmt", "-stdout", path], {
      encoding: "utf8",
      stdio: ["ignore", "pipe", "inherit"],
    })
    if (formatted !== readFileSync(path, "utf8"))
      throw new Error(`${path} needs formatting; run make format explicitly`)
  }
} catch (error) {
  console.error(`[check-web-generated] ${error.message}`)
  process.exitCode = 1
}
