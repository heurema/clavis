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
  env.CLAVIS_VM_PORT = String(await freePort())
  env.CLAVIS_VL_PORT = String(await freePort())
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
  // SQL left here forces expiry and inspects fixtures that have no product API.
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
  summary.userAdministration = "passed"
  console.log(
    "[smoke] Real CLI user creation, listing, blocking, password reset, role changes and self-protection passed",
  )

  // Connections are registered through the product CLI with encrypted secrets
  // and probed against the smoke database itself and a local VictoriaMetrics
  // health stub. Only fixture checks come from SQL.
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
    response.writeHead(authorized ? 200 : 401, {
      "content-type": "text/plain",
    })
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
  summary.connectionGrants = "passed"
  console.log(
    "[smoke] Real CLI grants, member visibility, username references and revocation passed",
  )

  // Queries run through the product CLI against the smoke database itself:
  // pass-through scripts, bounds with explicit truncation, distinguishable
  // failures, and nothing written to the platform database by any of it.
  const platformRows = async (name) =>
    sql(
      "SELECT (SELECT count(*) FROM users) || ':' || (SELECT count(*) FROM sessions) || ':' || (SELECT count(*) FROM connections) || ':' || (SELECT count(*) FROM grants)",
      name,
    )
  const query = (name, args, expected = 0, input) =>
    cli(
      name,
      ["query", "--connection", "smoke-postgres", ...args],
      expected,
      input,
    )
  const rowsBefore = await platformRows("query-rows-before")
  const script = await query("member", [
    "--sql",
    "create temp table smoke_query as select generate_series(1, 3) as n; select n from smoke_query order by n;",
  ])
  assert.equal(script.data.results.length, 2)
  assert.equal(script.data.results[0].command, "SELECT")
  assert.deepEqual(script.data.results[0].rows, [])
  assert.deepEqual(
    script.data.results[1].columns.map((column) => column.name),
    ["n"],
  )
  assert.deepEqual(script.data.results[1].rows, [["1"], ["2"], ["3"]])
  assert.equal(script.data.results[1].rowCount, 3)
  assert.equal(script.data.truncated, false)
  assert(Number.isInteger(script.data.durationMs))
  const typed = await query("admin-one", [
    "--sql",
    "select 12345678901234567890::numeric as big, null::text as missing, 1, 1",
  ])
  assert.deepEqual(typed.data.results[0].rows, [
    ["12345678901234567890", null, "1", "1"],
  ])
  assert.deepEqual(
    typed.data.results[0].columns.map((column) => column.type),
    ["numeric", "text", "int4", "int4"],
  )
  const wide = await query("member", [
    "--sql",
    "select generate_series(1, 2000)",
  ])
  assert.equal(wide.data.results[0].rows.length, 1000)
  assert.equal(wide.data.results[0].truncated, true)
  assert.equal(wide.data.truncated, true)
  const narrow = await query("member", [
    "--sql",
    "select generate_series(1, 2000)",
    "--max-rows",
    "5",
  ])
  assert.equal(narrow.data.results[0].rows.length, 5)
  assert.equal(narrow.data.truncated, true)
  const piped = await query(
    "member",
    ["--sql-stdin"],
    0,
    "select 'stdin' as via;\n",
  )
  assert.deepEqual(piped.data.results[0].rows, [["stdin"]])
  const sqlFile = join(privateDirectory, "query.sql")
  writeFileSync(sqlFile, "select 'file' as via;\n")
  const fromFile = await query("member", ["--sql-file", sqlFile])
  assert.deepEqual(fromFile.data.results[0].rows, [["file"]])
  const wideText = await execute(
    join(root, "bin/clavis"),
    [
      "query",
      "--connection",
      "smoke-postgres",
      "--sql",
      "select generate_series(1, 2000) as n, null::text as missing",
      "--output",
      "text",
      "--server",
      apiURL,
    ],
    "auth-member-query-text",
    { env: clientEnv("member") },
  )
  assert(wideText.includes("(1000 rows)"), "text output counts the kept rows")
  assert(wideText.includes("Truncated: true"))
  assert(wideText.includes("∅"), "NULL is rendered distinctly")
  const broken = await query(
    "member",
    ["--sql", "select 1; select no_such_column from smoke_missing;"],
    1,
  )
  assert.equal(broken.error.code, "SOURCE_ERROR")
  assert.equal(broken.error.source.sqlstate, "42P01")
  assert.equal(broken.error.source.statement, 1)
  assert(broken.error.source.message.includes("smoke_missing"))
  const syntax = await query("member", ["--sql", "selec 1"], 1)
  assert.equal(syntax.error.source.sqlstate, "42601")
  assert.equal(syntax.error.source.statement, 0)
  assert(syntax.error.source.position > 0)
  assert.equal(
    (await query("member", ["--sql", "select 1", "--sql-stdin"], 2)).error.code,
    "INVALID_ARGUMENT",
  )
  // A cap above the connection's is refused by the server and, like every
  // argument problem, exits 2 with the cap in the hint.
  const overCap = await query(
    "member",
    ["--sql", "select 1", "--max-rows", "5000"],
    2,
  )
  assert.equal(overCap.error.code, "INVALID_ARGUMENT")
  assert(overCap.error.hint.includes("1000"))
  // Authorization and provider refusals never contact a source.
  await cli("admin-one", [
    "connections",
    "create",
    "--name",
    "smoke-vm-query",
    "--provider",
    "victoriametrics",
    "--url",
    "http://127.0.0.1:9",
    "--auth",
    "none",
  ])
  // SQL on a metrics connection is an argument error, refused before any
  // credential is opened or source contacted.
  const mismatch = await cli(
    "admin-one",
    ["query", "--connection", "smoke-vm-query", "--sql", "select 1"],
    2,
  )
  assert.equal(mismatch.error.code, "INVALID_ARGUMENT")
  assert(mismatch.error.hint.includes("victoriametrics"))
  assert.equal(
    (
      await cli(
        "member",
        ["query", "--connection", "smoke-vm-query", "--sql", "select 1"],
        1,
      )
    ).error.code,
    "CONNECTION_NOT_FOUND",
  )
  await cli("admin-one", [
    "connections",
    "disable",
    "--connection",
    "smoke-postgres",
  ])
  assert.equal(
    (await query("member", ["--sql", "select 1"], 1)).error.code,
    "CONNECTION_DISABLED",
  )
  await cli("admin-one", [
    "connections",
    "enable",
    "--connection",
    "smoke-postgres",
  ])
  // The statement timeout is PostgreSQL's own; the platform never cancels.
  await cli("admin-one", [
    "connections",
    "update",
    "--connection",
    "smoke-postgres",
    "--statement-timeout",
    "1s",
  ])
  const slow = await query("member", ["--sql", "select pg_sleep(3)"], 1)
  assert.equal(slow.error.code, "SOURCE_TIMEOUT")
  assert(slow.error.hint)
  await cli("admin-one", [
    "connections",
    "update",
    "--connection",
    "smoke-postgres",
    "--statement-timeout",
    "45s",
  ])
  await cli("admin-one", [
    "connections",
    "disable",
    "--connection",
    "smoke-vm-query",
  ])
  await cli("admin-one", [
    "connections",
    "delete",
    "--connection",
    "smoke-vm-query",
  ])
  assert.equal(
    await platformRows("query-rows-after"),
    rowsBefore,
    "executions write nothing to the platform database",
  )
  summary.queryExecution = "passed"
  console.log(
    "[smoke] Real CLI query execution, bounds, failures and refusals passed",
  )

  // PromQL runs against the real single-node VictoriaMetrics from compose:
  // instant and range queries, discovery, the source's own errors, truncation,
  // the timeout backstop against a stalling source, and the provider mismatch.
  const vmURL = `http://127.0.0.1:${env.CLAVIS_VM_PORT}`
  await waitHTTP(`${vmURL}/health`, 200)
  const nowSeconds = Math.floor(Date.now() / 1000)
  const importLines = []
  for (const job of ["api", "web"])
    for (let back = 600; back >= 60; back -= 60)
      importLines.push(
        `smoke_requests_total{job="${job}",status="200"} ${(600 - back) / 60 + (job === "api" ? 10 : 20)} ${(nowSeconds - back) * 1000}`,
      )
  const imported = await fetch(`${vmURL}/api/v1/import/prometheus`, {
    method: "POST",
    body: importLines.join("\n") + "\n",
  })
  assert.equal(imported.status, 204)
  await fetch(`${vmURL}/internal/force_flush`)
  await cli("admin-one", [
    "connections",
    "create",
    "--name",
    "smoke-vm",
    "--provider",
    "victoriametrics",
    "--url",
    vmURL,
    "--auth",
    "none",
    "--label",
    "env=smoke",
  ])
  await check("smoke-vm", "reachable")
  const metricsQuery = (name, args, expected = 0) =>
    cli(name, ["query", "--connection", "smoke-vm", ...args], expected)
  const at = String(nowSeconds - 60)
  const instant = await metricsQuery("admin-one", [
    "--promql",
    "smoke_requests_total",
    "--at",
    at,
  ])
  assert.equal(instant.data.provider, "victoriametrics")
  assert.equal(instant.data.resultType, "vector")
  assert.equal(instant.data.result.length, 2)
  assert.deepEqual(
    instant.data.result.map((series) => series.metric.job).sort(),
    ["api", "web"],
  )
  assert.equal(typeof instant.data.result[0].value[1], "string")
  assert.equal(instant.data.truncated, false)
  const range = await metricsQuery("admin-one", [
    "--promql",
    "sum(smoke_requests_total) by (job)",
    "--start",
    String(nowSeconds - 660),
    "--end",
    String(nowSeconds),
    "--step",
    "60s",
  ])
  assert.equal(range.data.resultType, "matrix")
  assert.equal(range.data.result.length, 2)
  assert(
    range.data.result[0].values.length >= 5,
    "the range covers the imported samples",
  )
  const selector = await metricsQuery("admin-one", [
    "--promql",
    "smoke_requests_total[10m]",
    "--at",
    at,
  ])
  assert.equal(
    selector.data.resultType,
    "matrix",
    "an instant range selector answers a matrix",
  )
  const names = await metricsQuery("admin-one", ["--label-values", "__name__"])
  assert.equal(names.data.resultType, "labelValues")
  assert(names.data.result.includes("smoke_requests_total"))
  const labels = await metricsQuery("admin-one", [
    "--labels",
    "--match",
    "smoke_requests_total",
  ])
  assert.equal(labels.data.resultType, "labels")
  assert(
    labels.data.result.includes("job") && labels.data.result.includes("status"),
  )
  const series = await metricsQuery("admin-one", [
    "--series",
    'smoke_requests_total{job="api"}',
    "--start",
    String(nowSeconds - 660),
    "--end",
    String(nowSeconds),
  ])
  assert.equal(series.data.resultType, "series")
  assert.deepEqual(
    series.data.result.map((entry) => entry.job),
    ["api"],
  )
  const namesText = await execute(
    join(root, "bin/clavis"),
    [
      "query",
      "--connection",
      "smoke-vm",
      "--label-values",
      "__name__",
      "--output",
      "text",
      "--server",
      apiURL,
    ],
    "auth-admin-one-query-vm-text",
    { env: clientEnv("admin-one") },
  )
  assert(namesText.split("\n").includes("smoke_requests_total"))
  const badExpression = await metricsQuery(
    "admin-one",
    ["--promql", "sum(("],
    1,
  )
  assert.equal(badExpression.error.code, "SOURCE_ERROR")
  assert(
    badExpression.error.source.errorType,
    "the source's own error type is passed through",
  )
  assert.equal(badExpression.error.source.statement, undefined)
  assert(!JSON.stringify(badExpression).includes("sqlstate"))
  const capped = await metricsQuery("admin-one", [
    "--promql",
    "smoke_requests_total",
    "--start",
    String(nowSeconds - 660),
    "--end",
    String(nowSeconds),
    "--step",
    "60s",
    "--max-rows",
    "3",
  ])
  assert.equal(capped.data.truncated, true)
  assert(
    capped.data.result.some((entry) => entry.truncated === true),
    "a cut series is marked inside its object",
  )
  assert.equal(
    capped.data.result.reduce((sum, entry) => sum + entry.values.length, 0),
    3,
    "the sample cap bounds the whole response",
  )
  // Provider mismatch is refused before anything is sent, in both directions.
  assert.equal(
    (await metricsQuery("admin-one", ["--sql", "select 1"], 2)).error.code,
    "INVALID_ARGUMENT",
  )
  assert.equal(
    (await query("admin-one", ["--promql", "up"], 2)).error.code,
    "INVALID_ARGUMENT",
  )
  assert.equal(
    (
      await metricsQuery(
        "admin-one",
        ["--promql", "up", "--at", at, "--start", at],
        2,
      )
    ).error.code,
    "INVALID_ARGUMENT",
  )
  // Members need a grant, and the grant makes the same queries work.
  assert.equal(
    (await metricsQuery("member", ["--promql", "up"], 1)).error.code,
    "CONNECTION_NOT_FOUND",
  )
  await cli("admin-one", [
    "grants",
    "create",
    "--user",
    "smoke-member",
    "--connection",
    "smoke-vm",
  ])
  assert.equal(
    (
      await metricsQuery("member", [
        "--promql",
        "smoke_requests_total",
        "--at",
        at,
      ])
    ).data.result.length,
    2,
  )
  // A source that stops answering is cut at the timeout plus the grace.
  const stallPort = await freePort()
  const stall = createHTTPServer(() => {})
  await new Promise((resolve) => stall.listen(stallPort, "127.0.0.1", resolve))
  stall.unref()
  await cli("admin-one", [
    "connections",
    "create",
    "--name",
    "smoke-vm-stall",
    "--provider",
    "victoriametrics",
    "--url",
    `http://127.0.0.1:${stallPort}`,
    "--auth",
    "none",
    "--statement-timeout",
    "1s",
  ])
  const stalled = await cli(
    "admin-one",
    ["query", "--connection", "smoke-vm-stall", "--promql", "up"],
    1,
  )
  assert.equal(stalled.error.code, "SOURCE_TIMEOUT")
  stall.close()
  summary.metricsQueries = "passed"
  console.log(
    "[smoke] Real CLI PromQL queries, discovery, bounds and refusals passed",
  )

  // LogsQL runs against the real single-node VictoriaLogs from compose: an
  // ordered query under the source's own limit, the cut of the unbounded
  // stream at the platform's cap, an aggregate, every discovery endpoint, the
  // source's own error, the tenant headers, the provider mismatch and the
  // timeout backstop against a stalling source.
  const vlURL = `http://127.0.0.1:${env.CLAVIS_VL_PORT}`
  await waitHTTP(`${vlURL}/health`, 200)
  const logRows = []
  const rowTime = (back) => new Date(Date.now() - back * 1000).toISOString()
  for (const [app, base] of [
    ["api", 0],
    ["web", 3],
  ]) {
    logRows.push(
      {
        _time: rowTime(base + 120),
        _msg: "error: disk full",
        level: "error",
        app,
        n: "1",
      },
      {
        _time: rowTime(base + 60),
        _msg: "ok\nsecond line",
        level: "info",
        app,
        n: "2",
      },
      {
        _time: rowTime(base + 30),
        _msg: "error: timeout k=v",
        level: "error",
        app,
        n: "3",
      },
    )
  }
  const ingested = await fetch(`${vlURL}/insert/jsonline?_stream_fields=app`, {
    method: "POST",
    headers: { "content-type": "application/stream+json" },
    body: logRows.map((row) => JSON.stringify(row)).join("\n") + "\n",
  })
  assert.equal(ingested.status, 200)
  await cli("admin-one", [
    "connections",
    "create",
    "--name",
    "smoke-vl",
    "--provider",
    "victorialogs",
    "--url",
    vlURL,
    "--auth",
    "none",
    "--label",
    "env=smoke",
  ])
  await check("smoke-vl", "reachable")
  const logsQuery = (name, args, expected = 0) =>
    cli(name, ["query", "--connection", "smoke-vl", ...args], expected)
  // Ingested rows become visible within about a second; poll for them.
  let allRows
  for (let attempt = 0; attempt < 50; attempt++) {
    allRows = await logsQuery("admin-one", ["--logsql", "*"])
    if (allRows.data.result.length === logRows.length) break
    await delay(200)
  }
  assert.equal(allRows.data.provider, "victorialogs")
  assert.equal(allRows.data.resultType, "logs")
  assert.equal(allRows.data.result.length, logRows.length)
  assert.equal(allRows.data.truncated, false)
  assert.equal(
    typeof allRows.data.result[0]._stream,
    "string",
    "rows arrive as the source wrote them",
  )
  // The source's own limit with a sort pipe decides which rows come back and
  // in which order; the platform adds neither.
  const orderedRows = await logsQuery("admin-one", [
    "--logsql",
    "app:api | sort by (_time) desc",
    "--limit",
    "2",
  ])
  assert.equal(orderedRows.data.result.length, 2)
  assert(orderedRows.data.result[0]._time > orderedRows.data.result[1]._time)
  assert.equal(
    orderedRows.data.truncated,
    false,
    "the stream was read to its end",
  )
  // Without a limit the platform cuts the stream at its own cap and says so.
  const capped2 = await logsQuery("admin-one", [
    "--logsql",
    "*",
    "--max-rows",
    "2",
  ])
  assert.equal(capped2.data.truncated, true)
  assert.equal(capped2.data.result.length, 2)
  // An aggregate answers rows without the log fields.
  const levelCounts = await logsQuery("admin-one", [
    "--logsql",
    "* | stats by (level) count() as n",
  ])
  assert.deepEqual(
    levelCounts.data.result.map((row) => [row.level, row.n]).sort(),
    [
      ["error", "4"],
      ["info", "2"],
    ],
  )
  assert(levelCounts.data.result.every((row) => row._msg === undefined))
  // Discovery forwards the five metadata endpoints with the source's counts.
  const fieldNames = await logsQuery("admin-one", [
    "--field-names",
    "--match",
    "*",
  ])
  assert.equal(fieldNames.data.resultType, "fieldNames")
  assert(fieldNames.data.result.some((item) => item.value === "level"))
  const errorLevels = await logsQuery("admin-one", [
    "--field-values",
    "level",
    "--match",
    "*",
    "--filter",
    "err",
  ])
  assert.deepEqual(errorLevels.data.result, [{ value: "error", hits: 4 }])
  const logStreams = await logsQuery("admin-one", ["--streams", "--match", "*"])
  assert.equal(logStreams.data.result.length, 2)
  const streamFields = await logsQuery("admin-one", [
    "--stream-field-names",
    "--match",
    "*",
  ])
  assert.deepEqual(
    streamFields.data.result.map((item) => item.value),
    ["app"],
  )
  const appValues = await logsQuery("admin-one", [
    "--stream-field-values",
    "app",
    "--match",
    "*",
    "--start",
    "-1h",
  ])
  assert.deepEqual(appValues.data.result.map((item) => item.value).sort(), [
    "api",
    "web",
  ])
  // Text output keeps one physical line per row, the two-line message quoted.
  const rowsText = await execute(
    join(root, "bin/clavis"),
    [
      "query",
      "--connection",
      "smoke-vl",
      "--logsql",
      "app:web | sort by (_time)",
      "--limit",
      "3",
      "--output",
      "text",
      "--server",
      apiURL,
    ],
    "auth-admin-one-query-vl-text",
    { env: clientEnv("admin-one") },
  )
  const rowLines = rowsText
    .split("\n")
    .filter((line) => line.includes("app=web"))
  assert.equal(rowLines.length, 3)
  assert(rowLines.some((line) => line.includes('"ok\\nsecond line"')))
  // The source's rejection passes through with its own status and text.
  const badQuery = await logsQuery("admin-one", ["--logsql", "* | bogus("], 1)
  assert.equal(badQuery.error.code, "SOURCE_ERROR")
  assert.equal(badQuery.error.source.errorType, "http_400")
  assert.equal(badQuery.error.source.statement, undefined)
  assert(!JSON.stringify(badQuery).includes("sqlstate"))
  // A limit where the source takes none, and a discovery input without its
  // query, are refused before anything is sent.
  assert.equal(
    (
      await logsQuery(
        "admin-one",
        ["--field-names", "--match", "*", "--limit", "1"],
        2,
      )
    ).error.code,
    "INVALID_ARGUMENT",
  )
  assert.equal(
    (await logsQuery("admin-one", ["--field-values", "level"], 2)).error.code,
    "INVALID_ARGUMENT",
  )
  // Provider mismatch is refused before anything is sent, in every direction.
  assert.equal(
    (await logsQuery("admin-one", ["--sql", "select 1"], 2)).error.code,
    "INVALID_ARGUMENT",
  )
  assert.equal(
    (await logsQuery("admin-one", ["--promql", "up"], 2)).error.code,
    "INVALID_ARGUMENT",
  )
  assert.equal(
    (await query("admin-one", ["--logsql", "*"], 2)).error.code,
    "INVALID_ARGUMENT",
  )
  assert.equal(
    (await metricsQuery("admin-one", ["--logsql", "*"], 2)).error.code,
    "INVALID_ARGUMENT",
  )
  // Members need a grant, and the grant makes the same queries work.
  assert.equal(
    (await logsQuery("member", ["--logsql", "*"], 1)).error.code,
    "CONNECTION_NOT_FOUND",
  )
  await cli("admin-one", [
    "grants",
    "create",
    "--user",
    "smoke-member",
    "--connection",
    "smoke-vl",
  ])
  assert.equal(
    (await logsQuery("member", ["--logsql", "app:api", "--limit", "10"])).data
      .result.length,
    3,
  )
  // The stored credential and the tenant settings travel on every request.
  const logsToken = randomBytes(16).toString("hex")
  secrets.add(logsToken)
  const tenantPort = await freePort()
  const tenantHeaders = []
  const tenant = createHTTPServer((request, response) => {
    tenantHeaders.push({ url: request.url, headers: request.headers })
    response.writeHead(200, { "content-type": "application/stream+json" })
    response.end(
      request.url.startsWith("/health")
        ? "OK"
        : '{"_time":"2026-01-01T00:00:00Z","_msg":"tenant row"}\n',
    )
  })
  await new Promise((resolve) =>
    tenant.listen(tenantPort, "127.0.0.1", resolve),
  )
  tenant.unref()
  await cli(
    "admin-one",
    [
      "connections",
      "create",
      "--name",
      "smoke-vl-tenant",
      "--provider",
      "victorialogs",
      "--url",
      `http://127.0.0.1:${tenantPort}`,
      "--auth",
      "bearer",
      "--account-id",
      "12",
      "--project-id",
      "3",
      "--password-stdin",
    ],
    0,
    logsToken + "\n",
  )
  await check("smoke-vl-tenant", "reachable")
  const tenantRows = await cli("admin-one", [
    "query",
    "--connection",
    "smoke-vl-tenant",
    "--logsql",
    "*",
  ])
  assert.equal(tenantRows.data.result[0]._msg, "tenant row")
  for (const seen of tenantHeaders) {
    assert.equal(seen.headers.authorization, `Bearer ${logsToken}`)
    assert.equal(seen.headers.accountid, "12")
    assert.equal(seen.headers.projectid, "3")
  }
  assert(
    tenantHeaders.some((seen) => seen.url.startsWith("/select/logsql/query?")),
  )
  tenant.close()
  // A source that stops answering is cut at the timeout plus the grace.
  const logStallPort = await freePort()
  const logStall = createHTTPServer(() => {})
  await new Promise((resolve) =>
    logStall.listen(logStallPort, "127.0.0.1", resolve),
  )
  logStall.unref()
  await cli("admin-one", [
    "connections",
    "create",
    "--name",
    "smoke-vl-stall",
    "--provider",
    "victorialogs",
    "--url",
    `http://127.0.0.1:${logStallPort}`,
    "--auth",
    "none",
    "--statement-timeout",
    "1s",
  ])
  const logStalled = await cli(
    "admin-one",
    ["query", "--connection", "smoke-vl-stall", "--logsql", "*"],
    1,
  )
  assert.equal(logStalled.error.code, "SOURCE_TIMEOUT")
  logStall.close()
  summary.logQueries = "passed"
  console.log(
    "[smoke] Real CLI LogsQL queries, discovery, bounds and refusals passed",
  )

  // The embedded skill installs through the CLI into whichever agent
  // directories exist under the home, refuses a directory it did not write,
  // and prints its own document without touching anything.
  const skillHome = clientEnv("skill").HOME
  const skillInstall = (args, expected = 0) =>
    cli("skill", ["skill", "install", ...args], expected)
  const firstInstall = await skillInstall([])
  assert.deepEqual(
    firstInstall.data.targets.map((target) => [target.agent, target.outcome]),
    [["claude", "written"]],
    "with no agent directory present, Claude Code's is created",
  )
  const installedEntry = readFileSync(
    join(skillHome, ".claude", "skills", "clavis", "SKILL.md"),
    "utf8",
  )
  assert(installedEntry.startsWith("---\n"))
  assert(installedEntry.includes("\nx-clavis-skill: "))
  assert(
    existsSync(
      join(skillHome, ".claude", "skills", "clavis", "victorialogs.md"),
    ),
  )
  mkdirSync(join(skillHome, ".codex", "skills"), { recursive: true })
  const secondInstall = await skillInstall([])
  assert.deepEqual(
    secondInstall.data.targets
      .map((target) => [target.agent, target.outcome])
      .sort(),
    [
      ["claude", "unchanged"],
      ["codex", "written"],
    ],
  )
  const dryRun = await skillInstall(["--dry-run"])
  assert.equal(dryRun.data.dryRun, true)
  assert(dryRun.data.targets.every((target) => target.outcome === "unchanged"))
  // A skill somebody else wrote is never overwritten without --force.
  const foreign = join(skillHome, ".codex", "skills", "clavis", "SKILL.md")
  writeFileSync(foreign, "---\nname: clavis\ndescription: mine\n---\nkeep me\n")
  const refused = await skillInstall([], 2)
  assert.equal(refused.error.code, "INVALID_ARGUMENT")
  assert(refused.error.hint.includes("--force"))
  assert.equal(
    readFileSync(foreign, "utf8"),
    "---\nname: clavis\ndescription: mine\n---\nkeep me\n",
  )
  const forced = await skillInstall(["--force", "--agent", "codex"])
  assert.deepEqual(
    forced.data.targets.map((target) => [target.agent, target.outcome]),
    [["codex", "written"]],
  )
  assert(readFileSync(foreign, "utf8").includes("\nx-clavis-skill: "))
  const shown = await execute(
    join(root, "bin/clavis"),
    ["skill", "show", "--file", "victorialogs.md"],
    "skill-show",
    { env: clientEnv("skill") },
  )
  assert(shown.includes("unpack_json"), "show prints the embedded reference")
  summary.skill = "passed"
  console.log("[smoke] Embedded skill install, refusal, force and show passed")

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
