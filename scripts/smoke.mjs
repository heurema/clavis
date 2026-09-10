import assert from "node:assert/strict"
import { spawn } from "node:child_process"
import { randomBytes } from "node:crypto"
import { mkdirSync, writeFileSync } from "node:fs"
import { createServer } from "node:net"
import { join } from "node:path"
import { setTimeout as delay } from "node:timers/promises"
import { fileURLToPath } from "node:url"

const root = fileURLToPath(new URL("../", import.meta.url))
const reports = join(root, "reports")
mkdirSync(reports, { recursive: true })
const project = `clavis-smoke-${process.pid}-${randomBytes(4).toString("hex")}`
const compose = [
  "compose",
  "--env-file",
  "/dev/null",
  "--file",
  join(root, "compose.yaml"),
  "--project-name",
  project,
]
const env = { ...process.env }
const children = new Set()
const deadline = Date.now() + 180_000
const summary = {
  project,
  status: "running",
  startedAt: new Date().toISOString(),
}
let cleaning = false,
  composeStarted = false,
  stopped = false,
  before
function persist() {
  writeFileSync(
    join(reports, "smoke-summary.json"),
    JSON.stringify(summary, null, 2) + "\n",
  )
}
persist()

function start(command, args, name, options = {}) {
  if (!cleaning && (stopped || Date.now() >= deadline))
    throw new Error("Smoke run cancelled or exceeded 180 seconds")
  const log = join(reports, `smoke-${name}.log`)
  writeFileSync(log, "")
  const child = spawn(command, args, {
    cwd: root,
    env,
    detached: true,
    ...options,
  })
  children.add(child)
  let output = ""
  const record = (chunk) => {
    output += chunk.toString()
    writeFileSync(log, chunk, { flag: "a" })
  }
  child.stdout.on("data", record)
  child.stderr.on("data", record)
  child.finished = new Promise((resolve) => {
    child.on("error", (error) => {
      children.delete(child)
      resolve({ code: 1, output: error.message })
    })
    child.on("close", (code) => {
      children.delete(child)
      resolve({ code, output })
    })
  })
  return child
}
async function stop(child) {
  if (!children.has(child)) return
  try {
    process.kill(-child.pid, "SIGTERM")
  } catch (error) {
    if (error.code !== "ESRCH") throw error
  }
  const timer = setTimeout(() => {
    try {
      process.kill(-child.pid, "SIGKILL")
    } catch (error) {
      if (error.code !== "ESRCH") throw error
    }
  }, 3_000)
  try {
    await child.finished
  } finally {
    clearTimeout(timer)
  }
}
async function execute(command, args, name, options = {}, expected = 0) {
  const child = start(command, args, name, options)
  const timer = setTimeout(
    () => {
      void stop(child)
    },
    cleaning ? 20_000 : Math.max(1, deadline - Date.now()),
  )
  try {
    const result = await child.finished
    assert.equal(
      result.code,
      expected,
      `${name} failed; see reports/smoke-${name}.log`,
    )
    return result.output.trim()
  } finally {
    clearTimeout(timer)
  }
}
async function snapshot() {
  const containers = await execute(
    "docker",
    ["ps", "-aq", "--no-trunc"],
    "inventory-containers",
  )
  const volumes = await execute(
    "docker",
    ["volume", "ls", "--format", "{{.Name}}"],
    "inventory-volumes",
  )
  return {
    containers: containers.split("\n").filter(Boolean),
    volumes: volumes.split("\n").filter(Boolean),
  }
}
async function freePort() {
  const server = createServer()
  await new Promise((resolve, reject) => {
    server.once("error", reject)
    server.listen(0, "127.0.0.1", resolve)
  })
  const port = server.address().port
  await new Promise((resolve) => server.close(resolve))
  return port
}
async function waitHTTP(url, expected) {
  while (Date.now() < deadline && !stopped) {
    try {
      const response = await fetch(url, { signal: AbortSignal.timeout(1_000) })
      if (response.status === expected) return
    } catch {
      /* Startup may not have bound the port yet. */
    }
    await delay(150)
  }
  throw new Error(
    `Startup did not reach HTTP ${expected} within the smoke deadline`,
  )
}
for (const signal of ["SIGINT", "SIGTERM"])
  process.on(signal, () => {
    stopped = true
    for (const child of children) void stop(child)
  })

try {
  console.log(`[smoke] Isolated project ${project}; 180 second bound`)
  before = await snapshot()
  // Docker can reassign a published port of zero when the database restarts.
  env.CLAVIS_DB_PORT = String(await freePort())
  composeStarted = true
  await execute(
    "docker",
    [...compose, "up", "-d", "--wait", "--wait-timeout", "60"],
    "database-start",
  )
  const binding = await execute(
    "docker",
    [...compose, "port", "db", "5432"],
    "database-port",
  )
  assert.equal(binding, `127.0.0.1:${env.CLAVIS_DB_PORT}`)
  const apiPort = await freePort()
  const apiURL = `http://127.0.0.1:${apiPort}`
  const api = start(join(root, "bin/server"), [], "api", {
    env: {
      ...env,
      CLAVIS_HTTP_ADDR: `127.0.0.1:${apiPort}`,
      CLAVIS_DATABASE_URL: `postgres://clavis:clavis-local-only@${binding}/clavis?sslmode=disable`,
      CLAVIS_DB_CHECK_TIMEOUT: "500ms",
      CLAVIS_SHUTDOWN_TIMEOUT: "2s",
      CLAVIS_LOG_LEVEL: "info",
    },
  })
  await waitHTTP(`${apiURL}/health/ready`, 200)
  const doctor = JSON.parse(
    await execute(
      join(root, "bin/clavis"),
      ["doctor", "--server", apiURL],
      "doctor-ready",
    ),
  )
  assert.equal(doctor.schemaVersion, 1)
  assert.equal(doctor.ok, true)
  assert.equal(doctor.data.database, "ready")
  const webPort = await freePort()
  const webURL = `http://127.0.0.1:${webPort}`
  start(
    process.execPath,
    [
      join(root, "web/node_modules/vite/bin/vite.js"),
      "preview",
      "--host",
      "127.0.0.1",
      "--port",
      String(webPort),
      "--strictPort",
    ],
    "web",
    { cwd: join(root, "web"), env: { ...env, CLAVIS_API_PROXY: apiURL } },
  )
  await waitHTTP(webURL, 200)
  if (process.env.CLAVIS_SMOKE_FAIL === "after-start")
    throw new Error("Injected smoke failure after resources started")
  const browserEnv = {
    ...env,
    CLAVIS_SMOKE_PROJECT: project,
    CLAVIS_SMOKE_COMPOSE: join(root, "compose.yaml"),
    CLAVIS_SMOKE_API_URL: apiURL,
    CLAVIS_SMOKE_WEB_URL: webURL,
    CLAVIS_SMOKE_REPORTS: reports,
    CLAVIS_SMOKE_CLI: join(root, "bin/clavis"),
  }
  await execute("pnpm", ["--dir", "web", "test:browser"], "browser", {
    env: { ...browserEnv, CLAVIS_SMOKE_PHASE: "recovery" },
  })
  console.log(
    "[smoke] Real API, CLI, browser, database outage/recovery and appearance passed",
  )
  await stop(api)
  const unavailable = JSON.parse(
    await execute(
      join(root, "bin/clavis"),
      ["doctor", "--server", apiURL],
      "doctor-unreachable",
      {},
      1,
    ),
  )
  assert.equal(unavailable.data.api, "unreachable")
  await execute(
    "pnpm",
    ["--dir", "web", "test:browser"],
    "browser-unreachable",
    { env: { ...browserEnv, CLAVIS_SMOKE_PHASE: "unreachable" } },
  )
  summary.status = "passed"
} catch (error) {
  summary.status = "failed"
  summary.message = error.message
  console.error(`[smoke] ${error.message}`)
  process.exitCode = 1
} finally {
  cleaning = true
  try {
    for (const child of [...children]) await stop(child)
    if (composeStarted)
      await execute(
        "docker",
        [...compose, "down", "--volumes", "--remove-orphans", "--timeout", "5"],
        "cleanup",
      )
    const after = await snapshot()
    if (before)
      for (const kind of ["containers", "volumes"]) {
        assert(
          before[kind].every((id) => after[kind].includes(id)),
          `Pre-existing ${kind} disappeared during the smoke run`,
        )
      }
    assert(
      !after.volumes.some((name) => name.startsWith(project + "_")),
      "Temporary smoke volume was not cleaned up",
    )
    const ownContainers = await execute(
      "docker",
      ["ps", "-aq", "--filter", `label=com.docker.compose.project=${project}`],
      "cleanup-verify",
    )
    assert.equal(
      ownContainers,
      "",
      "Temporary smoke container was not cleaned up",
    )
    summary.cleanup = "passed"
    summary.preExistingResourcesPreserved = true
  } catch (error) {
    summary.cleanup = "failed"
    summary.status = "failed"
    summary.cleanupError = error.message
    process.exitCode = 1
    console.error(`[smoke] Cleanup verification failed: ${error.message}`)
  }
  summary.finishedAt = new Date().toISOString()
  persist()
  console.log(
    `[smoke] ${summary.status}; cleanup ${summary.cleanup}; reports/smoke-summary.json`,
  )
}
