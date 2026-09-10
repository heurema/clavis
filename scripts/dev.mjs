import { existsSync } from "node:fs"
import { spawn } from "node:child_process"
import { fileURLToPath } from "node:url"

const root = fileURLToPath(new URL("../", import.meta.url))
process.chdir(root)
// Node parses dotenv as data: shell substitutions and commands are never run.
if (existsSync(".env")) process.loadEnvFile(".env")
const compose = [
  "compose",
  "--file",
  "compose.yaml",
  "--project-name",
  "clavis",
]
const actions = {
  db: ["docker", ...compose, "up", "-d", "--wait", "--wait-timeout", "60"],
  down: ["docker", ...compose, "down"],
  reset: ["docker", ...compose, "down", "--volumes"],
  api: ["./bin/server"],
  web: ["pnpm", "--dir", "web", "dev"],
}
const command = actions[process.argv[2]]
if (!command) {
  console.error("Choose db, api, web, down, or reset.")
  process.exit(2)
}
if (process.argv[2] === "api" && !process.env.CLAVIS_DATABASE_URL) {
  console.error(
    "CLAVIS_DATABASE_URL is required. Copy .env.example to .env and configure the local database.",
  )
  process.exit(2)
}
if (process.argv[2] === "reset")
  console.log(
    "Resetting only the clavis development database volume; its local data will be deleted.",
  )
const child = spawn(command[0], command.slice(1), {
  stdio: "inherit",
  detached: true,
})
for (const signal of ["SIGINT", "SIGTERM"])
  process.on(signal, () => {
    try {
      process.kill(-child.pid, signal)
    } catch (error) {
      if (error.code !== "ESRCH") throw error
    }
  })
child.on("error", () => {
  console.error("Could not start the requested development command.")
  process.exitCode = 1
})
child.on("exit", (code, signal) => {
  process.exitCode = code ?? (signal === "SIGINT" ? 130 : 143)
})
