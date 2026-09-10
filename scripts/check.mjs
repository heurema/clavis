import { spawnSync } from "node:child_process"

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
const format = spawnSync("gofmt", ["-l", "cmd", "internal"], {
  encoding: "utf8",
})
if (format.status !== 0 || format.stdout.trim()) {
  console.error(format.stdout || format.stderr || "Go formatting check failed")
  console.error("[check] Run make format to format source explicitly.")
  process.exit(1)
}
run("Go lint (including vet)", "make", ["lint-go"])
run("Go tests", "go", ["test", "./..."])
run("Frontend formatting", "pnpm", ["--dir", "web", "format:check"])
run("Frontend type checking and route generation", "pnpm", [
  "--dir",
  "web",
  "typecheck",
])
run("Frontend lint", "pnpm", ["--dir", "web", "lint"])
run("Frontend tests", "pnpm", ["--dir", "web", "test"])
run("Production builds", "make", ["build"])
console.log("\n[check] All checks passed.")
