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
import { createServer as createHTTPServer } from "node:http"
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
  // Connection credentials are encrypted under this key; it is a private
  // input like the password file and is removed during cleanup.
  const keyFile = join(privateDirectory, "encryption-key")
  writeFileSync(keyFile, randomBytes(32).toString("hex") + "\n", {
    mode: 0o600,
  })
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
    for (const secret of secrets)
      assert(!JSON.stringify(result).includes(secret), "CLI exposed a password")
    return result
  }
  async function login(
    name,
    username = "smoke-admin",
    secret = password,
    expected = 0,
  ) {
    return cli(
      name,
      ["login", "--username", username, "--password-stdin"],
      expected,
      secret + "\n",
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
    CLAVIS_ENCRYPTION_KEY_FILE: keyFile,
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
  // Users are created and managed through the product CLI. The only fixture
  // SQL left here forces expiry and counts events, which have no product API.
  const memberPassword = randomBytes(32).toString("hex")
  secrets.add(memberPassword)
  const created = await cli(
    "admin-one",
    ["users", "create", "--username", "smoke-member", "--password-stdin"],
    0,
    memberPassword + "\n",
  )
  const member = created.data
  assert.equal(member.username, "smoke-member")
  assert.equal(member.role, "member")
  assert.equal(member.disabled, false)
  assert.equal(
    (
      await cli(
        "admin-one",
        ["users", "create", "--username", "smoke-member", "--password-stdin"],
        1,
        memberPassword + "\n",
      )
    ).error.code,
    "USERNAME_TAKEN",
  )
  const listed = await cli("admin-one", ["users", "list"])
  assert.deepEqual(
    listed.data.users.map((user) => user.username),
    ["smoke-admin", "smoke-member"],
  )
  assert.equal(listed.data.truncated, false)
  const listedText = await execute(
    join(root, "bin/clavis"),
    ["users", "list", "--output", "text", "--server", apiURL],
    "auth-admin-one-users-text",
    { env: clientEnv("admin-one") },
  )
  assert(listedText.includes(`${member.id} smoke-member member enabled`))
  assert(!listedText.includes("Truncated"))

  await login("member", "smoke-member", memberPassword)
  for (const args of [
    ["sessions", "revoke", "--user", administrator.id],
    ["users", "list"],
    ["users", "block", "--user", administrator.id],
  ])
    assert.equal((await cli("member", args, 1)).error.code, "FORBIDDEN")
  // Administrators are peers who cannot remove themselves.
  assert.equal(
    (await cli("admin-one", ["users", "block", "--user", administrator.id], 1))
      .error.code,
    "SELF_TARGET",
  )
  assert.equal(
    (
      await cli(
        "admin-one",
        ["users", "set-role", "--user", administrator.id, "--role", "member"],
        1,
      )
    ).error.code,
    "SELF_TARGET",
  )
  assert.equal(
    (
      await cli(
        "admin-one",
        ["users", "block", "--user", "00000000-0000-4000-8000-000000000000"],
        1,
      )
    ).error.code,
    "USER_NOT_FOUND",
  )
  // Blocking revokes the member's session and refuses new sign-ins.
  const blocked = await cli("admin-one", [
    "users",
    "block",
    "--user",
    member.id,
  ])
  assert.equal(blocked.data.user.disabled, true)
  assert.equal(blocked.data.sessionsRevoked, true)
  assert.equal(
    (await cli("member", ["whoami"], 1)).error.code,
    "UNAUTHENTICATED",
  )
  assert.equal(
    (await login("member", "smoke-member", memberPassword, 1)).error.code,
    "INVALID_CREDENTIALS",
  )
  const unblocked = await cli("admin-one", [
    "users",
    "unblock",
    "--user",
    member.id,
  ])
  assert.equal(unblocked.data.user.disabled, false)
  assert.equal(unblocked.data.sessionsRevoked, false)
  await login("member", "smoke-member", memberPassword)
  // A reset replaces the password and revokes every session.
  const resetPassword = randomBytes(32).toString("hex")
  secrets.add(resetPassword)
  const reset = await cli(
    "admin-one",
    ["users", "reset-password", "--user", member.id, "--password-stdin"],
    0,
    resetPassword + "\n",
  )
  assert.equal(reset.data.sessionsRevoked, true)
  assert.equal(
    (await cli("member", ["whoami"], 1)).error.code,
    "UNAUTHENTICATED",
  )
  assert.equal(
    (await login("member", "smoke-member", memberPassword, 1)).error.code,
    "INVALID_CREDENTIALS",
  )
  await login("member", "smoke-member", resetPassword)
  // Promotion authorizes the member's existing session; peers manage each
  // other; demotion removes authority while identity still works.
  const promoted = await cli("admin-one", [
    "users",
    "set-role",
    "--user",
    member.id,
    "--role",
    "admin",
  ])
  assert.equal(promoted.data.user.role, "admin")
  await cli("member", ["users", "list"])
  await cli("member", [
    "users",
    "set-role",
    "--user",
    administrator.id,
    "--role",
    "member",
  ])
  assert.equal(
    (await cli("admin-one", ["users", "list"], 1)).error.code,
    "FORBIDDEN",
  )
  assert.equal((await cli("admin-one", ["whoami"])).data.user.role, "member")
  assert.equal(
    (
      await cli(
        "member",
        ["users", "set-role", "--user", member.id, "--role", "member"],
        1,
      )
    ).error.code,
    "SELF_TARGET",
  )
  await cli("member", [
    "users",
    "set-role",
    "--user",
    administrator.id,
    "--role",
    "admin",
  ])
  await cli("admin-one", [
    "users",
    "set-role",
    "--user",
    member.id,
    "--role",
    "member",
  ])
  assert.equal(
    (await cli("member", ["users", "list"], 1)).error.code,
    "FORBIDDEN",
  )
  for (const [filter, expected] of [
    ["action='user.create' AND outcome='success'", "1"],
    ["action='user.create' AND outcome='username_taken'", "1"],
    ["action='user.block' AND outcome='self_target'", "1"],
    ["action='user.demote' AND outcome='self_target'", "2"],
    ["action='user.block' AND outcome='user_not_found'", "1"],
    ["action='user.block' AND outcome='success'", "1"],
    ["action='user.unblock' AND outcome='success'", "1"],
    ["action='user.reset_password' AND outcome='success'", "1"],
    ["action='user.promote' AND outcome='success'", "2"],
    ["action='user.demote' AND outcome='success'", "2"],
    ["action='users.list' AND outcome='forbidden'", "3"],
    ["action='users.list' AND outcome='success'", "0"],
    ["outcome='last_administrator'", "0"],
  ])
    assert.equal(
      await sql(
        `SELECT count(*) FROM auth_events WHERE ${filter}`,
        `events-${filter.replace(/[^a-z_]+/g, "-")}`,
      ),
      expected,
      filter,
    )
  summary.userAdministration = "passed"
  console.log(
    "[smoke] Real CLI user creation, listing, blocking, password reset, role changes and self-protection passed",
  )

  // Connections are registered through the product CLI with encrypted secrets
  // and probed against the smoke database itself and a local VictoriaMetrics
  // health stub. Only event counts come from fixture SQL.
  const databasePassword = "clavis-local-only"
  secrets.add(databasePassword)
  const databasePasswordFile = join(privateDirectory, "database-password")
  writeFileSync(databasePasswordFile, databasePassword + "\n", { mode: 0o600 })
  const databaseURL = (port) =>
    `postgres://clavis@127.0.0.1:${port}/clavis?sslmode=disable`
  const registered = await cli("admin-one", [
    "connections",
    "create",
    "--name",
    "smoke-postgres",
    "--provider",
    "postgresql",
    "--url",
    databaseURL(env.CLAVIS_DB_PORT),
    "--label",
    "env=smoke",
    "--label",
    "service=platform",
    "--title",
    "Smoke database",
    "--password-file",
    databasePasswordFile,
  ])
  const pgConnection = registered.data
  assert.equal(pgConnection.name, "smoke-postgres")
  assert.equal(pgConnection.enabled, true)
  assert.equal(pgConnection.lastCheck, null)
  assert(
    !JSON.stringify(registered).includes("envelope"),
    "no ciphertext leaves the server",
  )
  const check = async (name, expected, code = 0) => {
    const result = await cli(
      "admin-one",
      ["connections", "check", "--connection", name],
      code,
    )
    if (code === 0) assert.equal(result.data.check.outcome, expected, name)
    return result
  }
  await check("smoke-postgres", "reachable")
  await cli(
    "admin-one",
    [
      "connections",
      "set-credentials",
      "--connection",
      pgConnection.id,
      "--password-stdin",
    ],
    0,
    "wrong-password-value\n",
  )
  assert.equal(
    (
      await cli("admin-one", [
        "connections",
        "get",
        "--connection",
        "smoke-postgres",
      ])
    ).data.lastCheck,
    null,
    "replacing credentials clears the last check",
  )
  await check("smoke-postgres", "auth_rejected")
  await cli("admin-one", [
    "connections",
    "set-credentials",
    "--connection",
    "smoke-postgres",
    "--password-file",
    databasePasswordFile,
  ])
  const closedPort = await freePort()
  await cli("admin-one", [
    "connections",
    "update",
    "--connection",
    "smoke-postgres",
    "--url",
    databaseURL(closedPort),
  ])
  await check("smoke-postgres", "unreachable")
  const updated = await cli("admin-one", [
    "connections",
    "update",
    "--connection",
    "smoke-postgres",
    "--url",
    databaseURL(env.CLAVIS_DB_PORT),
    "--statement-timeout",
    "45s",
  ])
  assert.equal(updated.data.connection.statementTimeoutMs, 45000)
  assert.equal(updated.data.connection.id, pgConnection.id)
  await check("smoke-postgres", "reachable")

  const metricsToken = randomBytes(16).toString("hex")
  secrets.add(metricsToken)
  const metricsPort = await freePort()
  const metrics = createHTTPServer((request, response) => {
    const authorized =
      request.url === "/health" &&
      request.headers.authorization === `Bearer ${metricsToken}`
    response.writeHead(authorized ? 200 : 401, { "content-type": "text/plain" })
    response.end(authorized ? "OK" : "unauthorized")
  })
  await new Promise((resolve) =>
    metrics.listen(metricsPort, "127.0.0.1", resolve),
  )
  metrics.unref()
  await cli(
    "admin-one",
    [
      "connections",
      "create",
      "--name",
      "smoke-metrics",
      "--provider",
      "victoriametrics",
      "--url",
      `http://127.0.0.1:${metricsPort}`,
      "--auth",
      "bearer",
      "--label",
      "env=smoke",
      "--password-stdin",
    ],
    0,
    metricsToken + "\n",
  )
  await check("smoke-metrics", "reachable")
  await cli(
    "admin-one",
    [
      "connections",
      "set-credentials",
      "--connection",
      "smoke-metrics",
      "--password-stdin",
    ],
    0,
    "not-the-token\n",
  )
  await check("smoke-metrics", "auth_rejected")
  metrics.close()

  const selected = await cli("admin-one", [
    "connections",
    "list",
    "--selector",
    "env=smoke,service",
  ])
  assert.deepEqual(
    selected.data.connections.map((connection) => connection.name),
    ["smoke-postgres"],
  )
  assert.equal(selected.data.truncated, false)
  const everything = await cli("admin-one", ["connections", "list"])
  assert.deepEqual(
    everything.data.connections.map((connection) => connection.name),
    ["smoke-metrics", "smoke-postgres"],
  )
  // A member without grants lists nothing rather than being refused.
  assert.deepEqual((await cli("member", ["connections", "list"])).data, {
    connections: [],
    truncated: false,
  })
  const guarded = await cli(
    "admin-one",
    ["connections", "delete", "--connection", "smoke-metrics", "--dry-run"],
    1,
  )
  assert.equal(guarded.error.code, "CONNECTION_IN_USE")
  assert(guarded.error.hint, "guard failures carry a hint")
  await cli("admin-one", [
    "connections",
    "disable",
    "--connection",
    "smoke-metrics",
  ])
  const rehearsal = await cli("admin-one", [
    "connections",
    "delete",
    "--connection",
    "smoke-metrics",
    "--dry-run",
  ])
  assert.equal(rehearsal.data.dryRun, true)
  assert.equal(rehearsal.data.deleted, true)
  assert.equal(
    (
      await cli("admin-one", [
        "connections",
        "get",
        "--connection",
        "smoke-metrics",
      ])
    ).data.enabled,
    false,
    "a dry run changes nothing",
  )
  assert.equal(
    (
      await cli("admin-one", [
        "connections",
        "delete",
        "--connection",
        "smoke-metrics",
      ])
    ).data.deleted,
    true,
  )
  assert.equal(
    (
      await cli(
        "admin-one",
        ["connections", "get", "--connection", "smoke-metrics"],
        1,
      )
    ).error.code,
    "CONNECTION_NOT_FOUND",
  )
  const connectionsText = await execute(
    join(root, "bin/clavis"),
    ["connections", "list", "--output", "text", "--server", apiURL],
    "auth-admin-one-connections-text",
    { env: clientEnv("admin-one") },
  )
  assert(
    connectionsText.includes(
      `${pgConnection.id} smoke-postgres postgresql enabled reachable`,
    ),
  )
  for (const [filter, expected] of [
    ["action='connection.create' AND outcome='success'", "2"],
    ["action='connection.check' AND outcome='success'", "3"],
    ["action='connection.check' AND outcome='check_failed'", "3"],
    ["action='connection.set_credentials' AND outcome='success'", "3"],
    ["action='connection.update' AND outcome='success'", "2"],
    ["action='connection.disable' AND outcome='success'", "1"],
    ["action='connection.delete' AND outcome='success'", "1"],
    ["action='connection.delete' AND outcome='connection_in_use'", "0"],
    ["action='connections.list' AND outcome='forbidden'", "0"],
    ["action='connections.list' AND outcome='success'", "0"],
  ])
    assert.equal(
      await sql(
        `SELECT count(*) FROM auth_events WHERE ${filter}`,
        `events-${filter.replace(/[^a-z_]+/g, "-")}`,
      ),
      expected,
      filter,
    )
  assert.equal(
    await sql(
      "SELECT count(*) FROM connections WHERE secret_envelope NOT LIKE 'v1:%'",
      "envelopes-versioned",
    ),
    "0",
  )

  // The key is a required startup input: no key fails closed before listening,
  // a different key makes stored credentials unusable, the original key restores them.
  await stop(api)
  const withoutKey = startAPI({ CLAVIS_ENCRYPTION_KEY_FILE: "" })
  const missingKey = await withoutKey.finished
  assert.notEqual(missingKey.code, 0)
  assert(missingKey.output.includes("CLAVIS_ENCRYPTION_KEY_FILE"))
  assert(!missingKey.output.includes("server_started"))
  const otherKeyFile = join(privateDirectory, "other-encryption-key")
  writeFileSync(otherKeyFile, randomBytes(32).toString("hex") + "\n", {
    mode: 0o600,
  })
  api = startAPI({ CLAVIS_ENCRYPTION_KEY_FILE: otherKeyFile })
  await waitHTTP(`${apiURL}/health/ready`, 200)
  const undecryptable = await check("smoke-postgres", "", 1)
  assert.equal(undecryptable.error.code, "CREDENTIALS_UNAVAILABLE")
  assert(undecryptable.error.hint)
  assert.equal(
    (
      await cli("admin-one", [
        "connections",
        "get",
        "--connection",
        "smoke-postgres",
      ])
    ).data.lastCheck.outcome,
    "credentials_unavailable",
  )
  await stop(api)
  api = startAPI()
  await waitHTTP(`${apiURL}/health/ready`, 200)
  await check("smoke-postgres", "reachable")
  summary.connectionManagement = "passed"
  console.log(
    "[smoke] Real CLI connection registration, probes, updates, dry runs, deletion and key handling passed",
  )

  // Grants connect users to connections by name, members discover exactly
  // what they hold in the reduced projection, and revocation takes effect on
  // the next call. A second connection proves the delete guard and deletion.
  await cli("admin-one", [
    "connections",
    "create",
    "--name",
    "smoke-grants",
    "--provider",
    "victoriametrics",
    "--url",
    "http://127.0.0.1:9",
    "--auth",
    "none",
  ])
  const rehearsedGrant = await cli("admin-one", [
    "grants",
    "create",
    "--user",
    "smoke-member",
    "--connection",
    "smoke-postgres",
    "--dry-run",
  ])
  assert.equal(rehearsedGrant.data.dryRun, true)
  assert.equal(rehearsedGrant.data.created, true)
  assert.equal(await sql("SELECT count(*) FROM grants", "grants-none"), "0")
  const granted = await cli("admin-one", [
    "grants",
    "create",
    "--user",
    "smoke-member",
    "--connection",
    "smoke-postgres",
  ])
  assert.equal(granted.data.created, true)
  assert.deepEqual(granted.data.grant.user, {
    id: member.id,
    name: "smoke-member",
  })
  assert.deepEqual(granted.data.grant.connection, {
    id: pgConnection.id,
    name: "smoke-postgres",
  })
  assert.equal(granted.data.grant.createdBy.name, "smoke-admin")
  const repeated = await cli("admin-one", [
    "grants",
    "create",
    "--user",
    member.id,
    "--connection",
    pgConnection.id,
  ])
  assert.equal(repeated.data.created, false)
  await cli("admin-one", [
    "grants",
    "create",
    "--user",
    "smoke-member",
    "--connection",
    "smoke-grants",
  ])
  const identity = await cli("member", ["whoami"])
  assert.deepEqual(identity.data.connections, [
    "smoke-grants",
    "smoke-postgres",
  ])
  assert.equal(identity.data.connectionsTruncated, undefined)
  const visible = await cli("member", [
    "connections",
    "list",
    "--selector",
    "service=platform",
  ])
  assert.deepEqual(
    visible.data.connections.map((connection) => connection.name),
    ["smoke-postgres"],
  )
  const seen = await cli("member", [
    "connections",
    "get",
    "--connection",
    "smoke-postgres",
  ])
  assert.equal(seen.data.id, pgConnection.id)
  assert.equal(seen.data.target, undefined, "members never see targets")
  assert.equal(seen.data.maxRows, undefined, "members never see bounds")
  assert(!JSON.stringify(seen).includes("127.0.0.1:" + env.CLAVIS_DB_PORT))
  const memberText = await execute(
    join(root, "bin/clavis"),
    [
      "connections",
      "get",
      "--connection",
      "smoke-postgres",
      "--output",
      "text",
      "--server",
      apiURL,
    ],
    "auth-member-connections-get-text",
    { env: clientEnv("member") },
  )
  assert(memberText.includes("smoke-postgres"))
  assert(!memberText.includes("Target"))
  for (const args of [
    ["connections", "check", "--connection", "smoke-postgres"],
    [
      "grants",
      "create",
      "--user",
      "smoke-member",
      "--connection",
      "smoke-grants",
    ],
    [
      "grants",
      "revoke",
      "--user",
      "smoke-member",
      "--connection",
      "smoke-grants",
    ],
    ["grants", "list", "--user", "smoke-admin"],
  ])
    assert.equal((await cli("member", args, 1)).error.code, "FORBIDDEN")
  const own = await cli("member", ["grants", "list"])
  assert.deepEqual(
    own.data.grants.map((grant) => grant.connection.name),
    ["smoke-grants", "smoke-postgres"],
  )
  const grantsText = await execute(
    join(root, "bin/clavis"),
    ["grants", "list", "--output", "text", "--server", apiURL],
    "auth-member-grants-text",
    { env: clientEnv("member") },
  )
  assert(grantsText.includes("smoke-member smoke-postgres "))
  assert(!grantsText.includes("Truncated"))
  const filtered = await cli("admin-one", [
    "grants",
    "list",
    "--connection",
    "smoke-grants",
  ])
  assert.equal(filtered.data.grants.length, 1)
  assert.equal(filtered.data.grants[0].user.name, "smoke-member")
  // The delete guard names both conditions and counts the grants.
  const stillGranted = await cli(
    "admin-one",
    ["connections", "delete", "--connection", "smoke-grants", "--dry-run"],
    1,
  )
  assert.equal(stillGranted.error.code, "CONNECTION_IN_USE")
  assert(stillGranted.error.hint.includes("1 grant"), stillGranted.error.hint)
  await cli("admin-one", [
    "connections",
    "disable",
    "--connection",
    "smoke-grants",
  ])
  const disabledView = await cli("member", [
    "connections",
    "get",
    "--connection",
    "smoke-grants",
  ])
  assert.equal(disabledView.data.enabled, false, "disabled grants stay visible")
  const revokedGrant = await cli("admin-one", [
    "grants",
    "revoke",
    "--user",
    "smoke-member",
    "--connection",
    "smoke-grants",
  ])
  assert.equal(revokedGrant.data.revoked, true)
  const revokedAgain = await cli("admin-one", [
    "grants",
    "revoke",
    "--user",
    "smoke-member",
    "--connection",
    "smoke-grants",
  ])
  assert.equal(revokedAgain.data.revoked, false)
  assert.equal(
    (
      await cli(
        "member",
        ["connections", "get", "--connection", "smoke-grants"],
        1,
      )
    ).error.code,
    "CONNECTION_NOT_FOUND",
  )
  const removed = await cli("admin-one", [
    "connections",
    "delete",
    "--connection",
    "smoke-grants",
  ])
  assert.equal(removed.data.deleted, true)
  // Username references work on the existing user commands, and grants
  // survive blocking.
  const blockedByName = await cli("admin-one", [
    "users",
    "block",
    "--user",
    "smoke-member",
  ])
  assert.equal(blockedByName.data.user.id, member.id)
  assert.equal(
    (await cli("member", ["whoami"], 1)).error.code,
    "UNAUTHENTICATED",
  )
  await cli("admin-one", ["users", "unblock", "--user", "smoke-member"])
  await login("member", "smoke-member", resetPassword)
  assert.deepEqual((await cli("member", ["whoami"])).data.connections, [
    "smoke-postgres",
  ])
  assert.equal(
    (await cli("admin-one", ["whoami"])).data.connections,
    undefined,
    "administrators need no grants",
  )
  assert.equal(
    (
      await cli(
        "admin-one",
        [
          "grants",
          "create",
          "--user",
          "nobody-here",
          "--connection",
          "smoke-postgres",
        ],
        1,
      )
    ).error.code,
    "USER_NOT_FOUND",
  )
  assert.equal(
    (
      await cli(
        "admin-one",
        [
          "grants",
          "create",
          "--user",
          "Nobody Here",
          "--connection",
          "smoke-postgres",
        ],
        2,
      )
    ).error.code,
    "INVALID_ARGUMENT",
  )
  for (const [filter, expected] of [
    ["action='grant.create' AND outcome='success'", "2"],
    ["action='grant.create' AND outcome='forbidden'", "1"],
    ["action='grant.create' AND outcome='user_not_found'", "1"],
    ["action='grant.revoke' AND outcome='success'", "1"],
    ["action='grant.revoke' AND outcome='forbidden'", "1"],
    ["action='grants.list' AND outcome='forbidden'", "1"],
    ["action='grants.list' AND outcome='success'", "0"],
    ["action='connection.check' AND outcome='forbidden'", "1"],
    ["action='connection.get' AND outcome='connection_not_found'", "0"],
    ["action='connection.delete' AND outcome='connection_in_use'", "0"],
    [
      "action='grant.create' AND connection_id IS NULL AND outcome='success'",
      "0",
    ],
  ])
    assert.equal(
      await sql(
        `SELECT count(*) FROM auth_events WHERE ${filter}`,
        `events-${filter.replace(/[^a-z_]+/g, "-")}`,
      ),
      expected,
      filter,
    )
  summary.connectionGrants = "passed"
  console.log(
    "[smoke] Real CLI grants, member visibility, username references and revocation passed",
  )

  await sql(
    "UPDATE sessions SET expires_at=clock_timestamp()-interval '1 second' WHERE user_id IN (SELECT id FROM users WHERE username='smoke-admin')",
    "fixture-expire",
  )
  assert.equal(
    (await cli("admin-one", ["whoami"], 1)).error.code,
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
