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
import { createConnection, createServer } from "node:net"
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
const secrets = new Set()
function redact(value) {
  for (const secret of secrets) value = value.replaceAll(secret, "[REDACTED]")
  return value
}
const deadline = Date.now() + 180_000
const summary = {
  project,
  scope: "api-cli",
  status: "running",
  startedAt: new Date().toISOString(),
}
let cleaning = false,
  composeStarted = false,
  stopped = false,
  before,
  runtime,
  privateDirectory
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
  const { input, ...spawnOptions } = options
  const child = spawn(command, args, {
    cwd: root,
    env,
    detached: true,
    ...spawnOptions,
  })
  if (input !== undefined) {
    child.stdin.on("error", () => {})
    child.stdin.end(input)
  }
  children.add(child)
  let output = ""
  const record = (chunk) => {
    output += chunk.toString()
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
      // Buffer before redaction so a secret split across output chunks cannot
      // be written partially into reports.
      writeFileSync(log, redact(output))
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
async function waitListener(port) {
  while (Date.now() < deadline && !stopped) {
    const ready = await new Promise((resolve) => {
      const socket = createConnection({ host: "127.0.0.1", port })
      const finish = (value) => {
        socket.destroy()
        resolve(value)
      }
      socket.setTimeout(500)
      socket.once("connect", () => finish(true))
      socket.once("error", () => finish(false))
      socket.once("timeout", () => finish(false))
    })
    if (ready) return
    await delay(150)
  }
  throw new Error("HTTPS fixture did not start within the smoke deadline")
}
function cancel() {
  stopped = true
  for (const child of children) void stop(child)
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
  privateDirectory = mkdtempSync(join(root, ".local/smoke-private-"))
  const passwordFile = join(privateDirectory, "initial-password")
  const password = randomBytes(32).toString("hex")
  secrets.add(password)
  writeFileSync(passwordFile, password, { mode: 0o600 })
  const homes = new Map()
  function clientEnv(name) {
    if (!homes.has(name)) {
      const home = join(privateDirectory, name)
      mkdirSync(home, { mode: 0o700 })
      homes.set(name, home)
    }
    return {
      ...env,
      HOME: homes.get(name),
      XDG_CONFIG_HOME: join(homes.get(name), ".config"),
    }
  }
  async function cli(name, args, expected = 0, input) {
    const result = JSON.parse(
      await execute(
        join(root, "bin/clavis"),
        [...args, "--server", apiURL],
        `auth-${name}-${args[0]}`,
        { env: clientEnv(name), input },
        expected,
      ),
    )
    assert.equal(result.schemaVersion, 1)
    assert.equal(result.ok, expected === 0)
    assert(!JSON.stringify(result).includes(password), "CLI exposed a password")
    return result
  }
  async function login(name, username = "smoke-admin") {
    return cli(
      name,
      ["login", "--username", username, "--password-stdin"],
      0,
      password + "\n",
    )
  }
  async function sql(statement, name) {
    return execute(
      "docker",
      [
        ...compose,
        "exec",
        "-T",
        "db",
        "psql",
        "-U",
        "clavis",
        "-d",
        "clavis",
        "-At",
        "-v",
        "ON_ERROR_STOP=1",
        "-c",
        statement,
      ],
      name,
    )
  }
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
    CLAVIS_BOOTSTRAP_USERNAME: "smoke-admin",
    CLAVIS_BOOTSTRAP_PASSWORD_FILE: passwordFile,
  }
  summary.origin = apiURL
  function startAPI(overrides = {}) {
    assert.deepEqual(readdirSync(runtime), ["server"])
    const child = start(executable, [], `api-${servers.length + 1}`, {
      cwd: runtime,
      env: { ...serverEnv, ...overrides },
    })
    servers.push(child)
    summary.runtime.serverPIDs.push(child.pid)
    return child
  }
  let api = startAPI()
  const secondPort = await freePort()
  const second = startAPI({ CLAVIS_HTTP_ADDR: `127.0.0.1:${secondPort}` })
  await waitHTTP(`${apiURL}/health/ready`, 200)
  await waitHTTP(`http://127.0.0.1:${secondPort}/health/ready`, 200)
  await stop(second)
  assert.equal(
    await sql("SELECT count(*) FROM users", "bootstrap-account-count"),
    "1",
  )
  assert.equal(
    await sql(
      "SELECT count(*) FROM auth_events WHERE action='bootstrap'",
      "bootstrap-event-count",
    ),
    "1",
  )
  summary.concurrentBootstrap = "passed"
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
  // HTTP availability only: no rendering or client-side interaction is tested.
  for (const [path, contentType] of [
    ["/", "text/html"],
    ["/login", "text/html"],
    ["/assets/app.css", "text/css"],
    ["/assets/appearance.js", "text/javascript"],
    ["/assets/readiness.js", "text/javascript"],
    ["/assets/htmx.min.js", "text/javascript"],
    ["/assets/notices.txt", "text/plain"],
  ]) {
    const response = await fetch(apiURL + path, {
      redirect: "error",
      signal: AbortSignal.timeout(2_000),
    })
    assert.equal(response.status, 200, `${path} is unavailable`)
    assert.equal(
      response.headers.get("content-type")?.split(";")[0],
      contentType,
    )
    assert((await response.text()).trim(), `${path} is empty`)
  }
  summary.httpDocumentsAndAssets = "passed"
  console.log(
    "[smoke] Copied binary serves HTTP documents and embedded assets with PATH empty",
  )
  injectFailure("after-start")

  const administrator = (await login("admin-one")).data.user
  assert.equal(administrator.username, "smoke-admin")
  assert.equal(
    (await cli("admin-one", ["whoami"])).data.user.id,
    administrator.id,
  )
  await login("admin-two")
  await cli("admin-one", ["sessions", "revoke", "--user", administrator.id])
  for (const name of ["admin-one", "admin-two"])
    assert.equal((await cli(name, ["whoami"], 1)).error.code, "UNAUTHENTICATED")

  await login("admin-one")
  // Direct SQL is confined to this disposable fixture, not a product management
  // API. It exercises current roles/expiry without inventing user-management UI.
  await sql(
    "UPDATE users SET role='member' WHERE username='smoke-admin'",
    "fixture-demote",
  )
  assert.equal(
    (
      await cli(
        "admin-one",
        ["sessions", "revoke", "--user", administrator.id],
        1,
      )
    ).error.code,
    "FORBIDDEN",
  )
  await sql(
    "UPDATE users SET role='admin' WHERE username='smoke-admin'",
    "fixture-restore-role",
  )
  await sql(
    "UPDATE sessions SET expires_at=clock_timestamp()-interval '1 second' WHERE user_id IN (SELECT id FROM users WHERE username='smoke-admin')",
    "fixture-expire",
  )
  assert.equal(
    (await cli("admin-one", ["whoami"], 1)).error.code,
    "UNAUTHENTICATED",
  )

  await sql(
    "INSERT INTO users(id,username,password_hash,role) SELECT gen_random_uuid(),'smoke-member',password_hash,'member' FROM users WHERE username='smoke-admin'",
    "fixture-member",
  )
  await login("member", "smoke-member")
  assert.equal(
    (await cli("member", ["sessions", "revoke", "--user", administrator.id], 1))
      .error.code,
    "FORBIDDEN",
  )
  await sql(
    "UPDATE users SET disabled=true WHERE username='smoke-member'",
    "fixture-disable",
  )
  assert.equal(
    (await cli("member", ["whoami"], 1)).error.code,
    "UNAUTHENTICATED",
  )
  await login("admin-one")
  await cli("admin-one", ["logout"])
  assert.equal(
    (await cli("admin-one", ["whoami"], 1)).error.code,
    "UNAUTHENTICATED",
  )
  await cli("admin-two", ["logout"])
  await cli("member", ["logout"])
  await login("outage")
  summary.authentication = "passed"
  console.log(
    "[smoke] Real API/CLI login, logout, role/disabled checks, expiry and multi-client revocation passed",
  )

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
  const offlineLogout = await cli("outage", ["logout", "--timeout", "2s"], 1)
  assert.notEqual(offlineLogout.data?.revoked, true)
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
  summary.databaseOutageRecovery = "passed"
  console.log("[smoke] Real API, CLI and database outage/recovery passed")
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
  const changedPassword = randomBytes(32).toString("hex")
  secrets.add(changedPassword)
  writeFileSync(passwordFile, changedPassword)
  serverEnv.CLAVIS_BOOTSTRAP_USERNAME = "changed-admin"
  api = startAPI()
  await waitHTTP(`${apiURL}/health/ready`, 200)
  summary.serverOutageRecovery = "passed"
  console.log("[smoke] Same-address server restart recovered HTTP readiness")
  injectFailure("after-restart")
  assert.equal((await login("restart")).data.user.id, administrator.id)
  await cli("restart", ["logout"])
  await stop(api)
  rmSync(passwordFile)
  startAPI()
  await waitHTTP(`${apiURL}/health/ready`, 200)
  assert.equal((await login("without-secret")).data.user.id, administrator.id)
  await cli("without-secret", ["logout"])
  summary.bootstrapCredentialsIgnoredAfterInitialization = "passed"
  const securePort = await freePort()
  const secureOrigin = `https://127.0.0.1:${securePort}`
  const proxyExecutable = join(privateDirectory, "https-proxy")
  await execute(
    "go",
    ["build", "-o", proxyExecutable, "./internal/server/testdata/https-proxy"],
    "https-proxy-build",
  )
  start(
    proxyExecutable,
    ["--listen", `127.0.0.1:${securePort}`, "--upstream", apiURL],
    "https-proxy",
  )
  await waitListener(securePort)
  // The unmodified CLI must reject this in-memory self-signed certificate;
  // no OS trust store changes, private key files or insecure CLI flag are used.
  const untrustedTLS = JSON.parse(
    await execute(
      join(root, "bin/clavis"),
      ["whoami", "--server", secureOrigin],
      "auth-untrusted-tls",
      { env: clientEnv("tls") },
      1,
    ),
  )
  assert.equal(untrustedTLS.error.code, "SERVER_UNREACHABLE")
  summary.cliUntrustedTLS = "passed"
  console.log(
    "[smoke] CLI rejected the local HTTPS fixture's untrusted certificate",
  )
  injectFailure("after-https")
  assert(!stopped && Date.now() < deadline, "Smoke run exceeded its deadline")
  assert.deepEqual(readdirSync(runtime), ["server"])
  summary.status = "passed"
} catch (error) {
  summary.status = "failed"
  summary.message = redact(error.message)
  console.error(`[smoke] ${summary.message}`)
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
  await cleanup("private inputs and client homes", () => {
    if (privateDirectory) {
      rmSync(privateDirectory, { recursive: true, force: true })
      assert(
        !existsSync(privateDirectory),
        "Private smoke files were not removed",
      )
    }
    summary.privateResourcesRemoved = true
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
