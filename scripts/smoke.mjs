import assert from "node:assert/strict"
import { spawn } from "node:child_process"
import { randomBytes } from "node:crypto"
import {
  copyFileSync,
  existsSync,
  mkdirSync,
  mkdtempSync,
  readdirSync,
  rmSync,
  writeFileSync,
} from "node:fs"
import { createServer } from "node:net"
import { join } from "node:path"
import { setTimeout as delay } from "node:timers/promises"
import { fileURLToPath } from "node:url"
import { launchSmokeBrowser } from "../web/tests/smoke-browser.mjs"

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
  scope: "browser-api-cli",
  status: "running",
  startedAt: new Date().toISOString(),
}
let cleaning = false,
  composeStarted = false,
  stopped = false,
  before,
  runtime,
  browser
const servers = []
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
  if (!children.has(child) || !child.pid) return
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
      await response.arrayBuffer()
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
function cancel() {
  stopped = true
  for (const child of children) void stop(child)
  // The same close promise is awaited (and any error reported) in finally.
  void browser?.close().catch(() => {})
}
for (const signal of ["SIGINT", "SIGTERM"]) process.on(signal, cancel)
const watchdog = setTimeout(cancel, Math.max(1, deadline - Date.now()))

function injectFailure(stage) {
  if (process.env.CLAVIS_SMOKE_FAIL === stage)
    throw new Error(`Injected smoke failure ${stage}`)
}

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
  mkdirSync(join(root, ".local"), { recursive: true })
  runtime = mkdtempSync(join(root, ".local/smoke-runtime-"))
  summary.runtime = { directory: runtime, path: "", serverPIDs: [] }
  assert.deepEqual(readdirSync(runtime), [])
  const executable = join(runtime, "server")
  copyFileSync(join(root, "bin/server"), executable)
  const serverEnv = {
    PATH: "",
    CLAVIS_HTTP_ADDR: `127.0.0.1:${apiPort}`,
    CLAVIS_DATABASE_URL: `postgres://clavis:clavis-local-only@${binding}/clavis?sslmode=disable`,
    CLAVIS_DB_CHECK_TIMEOUT: "500ms",
    CLAVIS_SHUTDOWN_TIMEOUT: "2s",
    CLAVIS_LOG_LEVEL: "info",
  }
  summary.origin = apiURL
  function startAPI() {
    assert.deepEqual(readdirSync(runtime), ["server"])
    const child = start(executable, [], `api-${servers.length + 1}`, {
      cwd: runtime,
      env: serverEnv,
    })
    servers.push(child)
    summary.runtime.serverPIDs.push(child.pid)
    return child
  }
  const api = startAPI()
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
  browser = await launchSmokeBrowser(apiURL, reports)
  summary.browser = browser.evidence
  await browser.open()
  await browser.retry("ready")
  console.log(
    "[smoke] Copied binary serves styled, interactive UI with PATH empty",
  )
  injectFailure("after-start")

  await execute("docker", [...compose, "stop", "db"], "database-stop")
  await waitHTTP(`${apiURL}/health/live`, 200)
  await waitHTTP(`${apiURL}/health/ready`, 503)
  const databaseUnavailable = JSON.parse(
    await execute(
      join(root, "bin/clavis"),
      ["doctor", "--server", apiURL],
      "doctor-database-unavailable",
      {},
      1,
    ),
  )
  assert.equal(databaseUnavailable.ok, false)
  assert.deepEqual(databaseUnavailable.data, {
    api: "reachable",
    database: "unavailable",
  })
  await browser.retry("database-unavailable")
  await execute(
    "docker",
    [...compose, "up", "-d", "--wait", "--wait-timeout", "45"],
    "database-restart",
  )
  assert.equal(
    await execute(
      "docker",
      [...compose, "port", "db", "5432"],
      "database-restarted-port",
    ),
    binding,
  )
  await waitHTTP(`${apiURL}/health/ready`, 200)
  const recovered = JSON.parse(
    await execute(
      join(root, "bin/clavis"),
      ["doctor", "--server", apiURL],
      "doctor-recovered",
    ),
  )
  assert.equal(recovered.ok, true)
  assert.equal(recovered.data.database, "ready")
  await browser.retry("ready")
  console.log(
    "[smoke] Real browser, API, CLI and database outage/recovery passed",
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
  await browser.retry("server-unavailable")
  startAPI()
  await waitHTTP(`${apiURL}/health/ready`, 200)
  await browser.retry("ready")
  console.log(
    "[smoke] Same-address server restart recovered the loaded page without reload",
  )
  injectFailure("after-restart")
  assert(!stopped && Date.now() < deadline, "Smoke run exceeded its deadline")
  assert.deepEqual(readdirSync(runtime), ["server"])
  summary.status = "passed"
} catch (error) {
  summary.status = "failed"
  summary.message = error.message
  console.error(`[smoke] ${error.message}`)
  process.exitCode = 1
} finally {
  cleaning = true
  clearTimeout(watchdog)
  // Attempt every cleanup even when an earlier step fails. Only the unique
  // project, copied runtime and explicitly tracked processes belong to us.
  const errors = []
  async function cleanup(label, action) {
    try {
      await action()
    } catch (error) {
      errors.push(`${label}: ${error.message}`)
    }
  }
  await cleanup("browser", async () => {
    await browser?.close()
  })
  for (const child of children)
    await cleanup(`process ${child.pid}`, () => stop(child))
  if (composeStarted)
    await cleanup("database", () =>
      execute(
        "docker",
        [...compose, "down", "--volumes", "--remove-orphans", "--timeout", "5"],
        "cleanup",
      ),
    )
  await cleanup("runtime", () => {
    if (runtime) {
      rmSync(runtime, { recursive: true, force: true })
      assert(!existsSync(runtime), "Temporary runtime was not removed")
      summary.runtime.removed = true
    }
    assert.equal(children.size, 0, "Smoke child processes are still tracked")
    for (const server of servers)
      assert(
        server.exitCode !== null || server.signalCode !== null,
        `Server ${server.pid} did not exit`,
      )
    summary.serverProcessesStopped = true
  })
  await cleanup("Docker inventory", async () => {
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
    const ownNetworks = await execute(
      "docker",
      [
        "network",
        "ls",
        "-q",
        "--filter",
        `label=com.docker.compose.project=${project}`,
      ],
      "cleanup-verify-networks",
    )
    assert.equal(ownNetworks, "", "Temporary smoke network was not cleaned up")
    summary.preExistingResourcesPreserved = true
  })
  summary.cleanup = errors.length ? "failed" : "passed"
  if (errors.length) {
    summary.status = "failed"
    summary.cleanupErrors = errors
    process.exitCode = 1
    console.error(`[smoke] Cleanup verification failed: ${errors.join("; ")}`)
  }
  summary.finishedAt = new Date().toISOString()
  persist()
  console.log(
    `[smoke] ${summary.status}; cleanup ${summary.cleanup}; reports/smoke-summary.json`,
  )
}
