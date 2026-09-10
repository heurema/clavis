import { spawnSync } from "node:child_process"
import { readdirSync } from "node:fs"

function run(label, command, args) {
  console.log(`\n[check] ${label}`)
  const result = spawnSync(command, args, { stdio: "inherit" })
  if (result.error || result.status !== 0) {
    console.error(`[check] Failed: ${label}`)
    process.exit(result.status || 1)
  }
}
run("Toolchain", process.execPath, ["scripts/check-tools.mjs"])
console.log("\n[check] Go formatting")
const sources = ["cmd", "internal"].flatMap((directory) =>
  readdirSync(directory, { recursive: true })
    .filter((file) => file.endsWith(".go") && !file.endsWith("_templ.go"))
    .map((file) => `${directory}/${file}`),
)
const format = spawnSync("gofmt", ["-l", ...sources], {
  encoding: "utf8",
})
if (format.status !== 0 || format.stdout.trim()) {
  console.error(format.stdout || format.stderr || "Go formatting check failed")
  console.error("[check] Run make format to format source explicitly.")
  process.exit(1)
}
run("Template formatting and generated source", "make", ["check-web-generated"])
run("Embedded asset preparation", "make", ["build-web-assets"])
run("Build tooling tests", process.execPath, ["--test", "scripts/*.test.mjs"])
run("Go lint (including vet)", "make", ["lint-go"])
run("Go tests", "go", ["test", "./..."])
run("JavaScript/tooling formatting", "pnpm", ["--dir", "web", "format:check"])
run("JavaScript/tooling lint", "pnpm", ["--dir", "web", "lint"])
run("Production builds", "make", ["build"])
run("Browser behavior", "pnpm", ["--dir", "web", "test"])
console.log("\n[check] All checks passed.")
