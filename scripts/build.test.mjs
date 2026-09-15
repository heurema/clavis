import assert from "node:assert/strict"
import { execFileSync, spawn, spawnSync } from "node:child_process"
import { createHash, randomBytes } from "node:crypto"
import {
  copyFileSync,
  cpSync,
  existsSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  readdirSync,
  rmSync,
  symlinkSync,
  writeFileSync,
} from "node:fs"
import { createServer } from "node:net"
import { join } from "node:path"
import { test } from "node:test"
import { setTimeout as delay } from "node:timers/promises"
import { fileURLToPath } from "node:url"

const root = fileURLToPath(new URL("../", import.meta.url))

function fixture(t, webTools = true) {
  mkdirSync(join(root, ".local"), { recursive: true })
  const directory = mkdtempSync(join(root, ".local/build-test-"))
  // The server requires a credential encryption key; the copied binary must
  // start with a throwaway one that never leaves the test directory.
  const keyFile = join(directory, "encryption-key")
  writeFileSync(keyFile, randomBytes(32).toString("hex") + "\n", {
    mode: 0o600,
  })
  t.after(() => rmSync(directory, { recursive: true, force: true }))
  for (const path of [
    "cmd",
    "internal",
    "scripts",
    "web/styles",
    "web/scripts",
  ]) {
    cpSync(join(root, path), join(directory, path), {
      recursive: true,
      filter: (source) =>
        source !== join(root, "internal/web/assets") &&
        !source.includes("/.assets-"),
    })
  }
  for (const path of [
    "Makefile",
    "go.mod",
    "go.sum",
    ...(webTools ? [".sqlc-version", "sqlc.yaml"] : []),
    "web/package.json",
  ])
    copyFileSync(join(root, path), join(directory, path))
  if (webTools) {
    symlinkSync(join(root, ".tools"), join(directory, ".tools"), "dir")
    symlinkSync(
      join(root, "web/node_modules"),
      join(directory, "web/node_modules"),
      "dir",
    )
  }
  return directory
}

function execute(directory, command, args, expected = 0) {
  const result = spawnSync(command, args, {
    cwd: directory,
    encoding: "utf8",
    timeout: 120_000,
  })
  assert.ifError(result.error)
  assert.equal(result.status, expected, result.stdout + result.stderr)
  return result.stdout + result.stderr
}

function digest(path) {
  return createHash("sha256").update(readFileSync(path)).digest("hex")
}

async function freePort() {
  const socket = createServer()
  await new Promise((resolve, reject) => {
    socket.once("error", reject)
    socket.listen(0, "127.0.0.1", resolve)
  })
  const port = socket.address().port
  await new Promise((resolve) => socket.close(resolve))
  return port
}

async function checkCopiedServer(directory) {
  const keyFile = join(directory, "encryption-key")
  const runtime = join(directory, "runtime")
  mkdirSync(runtime)
  const executable = join(runtime, "server")
  copyFileSync(join(directory, "bin/server"), executable)
  const port = await freePort()
  const databasePort = await freePort()
  const origin = `http://127.0.0.1:${port}`
  // No inherited development settings, source paths or frontend executables.
  const child = spawn(executable, [], {
    cwd: runtime,
    env: {
      PATH: "",
      CLAVIS_HTTP_ADDR: `127.0.0.1:${port}`,
      CLAVIS_DATABASE_URL: `postgres://unused:sentinel-private@127.0.0.1:${databasePort}/unused?sslmode=disable`,
      CLAVIS_ENCRYPTION_KEY_FILE: keyFile,
      CLAVIS_DB_CHECK_TIMEOUT: "100ms",
      CLAVIS_SHUTDOWN_TIMEOUT: "1s",
      CLAVIS_LOG_LEVEL: "info",
    },
  })
  let output = ""
  child.stdout.on("data", (chunk) => (output += chunk))
  child.stderr.on("data", (chunk) => (output += chunk))
  const finished = new Promise((resolve) => {
    child.once("error", (error) => resolve({ error }))
    child.once("close", (code) => resolve({ code }))
  })
  try {
    let running = false
    for (let attempt = 0; attempt < 50; attempt++) {
      try {
        const response = await fetch(`${origin}/livez`, {
          signal: AbortSignal.timeout(200),
        })
        assert.equal(response.status, 200)
        await response.arrayBuffer()
        running = true
        break
      } catch {
        if (child.exitCode !== null) break
        await delay(100)
      }
    }
    assert.ok(running, `Copied server did not start: ${output}`)
    for (const [path, status, type, text, location] of [
      ["/", 303, "text/html", "/admin/users", "/admin/users"],
      ["/assets/app.css", 200, "text/css", ".bg-card{"],
      ["/assets/appearance.js", 200, "text/javascript", "clavis.appearance"],
      ["/assets/notices.txt", 200, "text/plain", "Cole Bemis"],
      ["/ui/readiness", 404, "text/plain", "404 page not found"],
      ["/readyz", 503, "application/json", "DEPENDENCY_UNAVAILABLE"],
    ]) {
      const response = await fetch(`${origin}${path}`, {
        redirect: "manual",
        signal: AbortSignal.timeout(2_000),
      })
      assert.equal(response.status, status, path)
      assert.ok(response.headers.get("content-type").startsWith(type), path)
      if (location) assert.equal(response.headers.get("location"), location)
      const body = await response.text()
      assert.ok(body.includes(text), path)
      assert.ok(!body.includes("sentinel-private"), path)
    }
    assert.deepEqual(readdirSync(runtime), ["server"])
    assert.ok(!output.includes("sentinel-private"))
    // A build without the linker flags reports the local identity.
    assert.match(
      output,
      /"msg":"server_started","version":"dev","commit":"unknown","date":"unknown"/,
    )
  } finally {
    child.kill("SIGTERM")
    const timer = setTimeout(() => child.kill("SIGKILL"), 2_000)
    try {
      const result = await finished
      assert.ifError(result.error)
      assert.equal(result.code, 0, output)
    } finally {
      clearTimeout(timer)
    }
  }
}

// Starts the built server against an unreachable database only long enough to
// capture its structured startup entry, which carries the build identity.
async function startupLog(directory) {
  const port = await freePort()
  const databasePort = await freePort()
  const child = spawn(join(directory, "bin/server"), [], {
    cwd: directory,
    env: {
      PATH: "",
      CLAVIS_HTTP_ADDR: `127.0.0.1:${port}`,
      CLAVIS_DATABASE_URL: `postgres://unused:unused@127.0.0.1:${databasePort}/unused?sslmode=disable`,
      CLAVIS_ENCRYPTION_KEY_FILE: join(directory, "encryption-key"),
      CLAVIS_DB_CHECK_TIMEOUT: "100ms",
      CLAVIS_SHUTDOWN_TIMEOUT: "1s",
      CLAVIS_LOG_LEVEL: "info",
    },
  })
  let output = ""
  child.stdout.on("data", (chunk) => (output += chunk))
  child.stderr.on("data", (chunk) => (output += chunk))
  const finished = new Promise((resolve) => child.once("close", resolve))
  try {
    for (
      let attempt = 0;
      attempt < 50 && !output.includes("server_started");
      attempt++
    ) {
      if (child.exitCode !== null) break
      await delay(100)
    }
  } finally {
    child.kill("SIGTERM")
    const timer = setTimeout(() => child.kill("SIGKILL"), 2_000)
    try {
      await finished
    } finally {
      clearTimeout(timer)
    }
  }
  return output
}

function descendants(parent) {
  if (!parent) return []
  const processes = execFileSync("ps", ["-eo", "pid=,ppid="], {
    encoding: "utf8",
  })
    .trim()
    .split("\n")
    .map((line) => line.trim().split(/\s+/).map(Number))
  const found = [parent]
  for (const pid of found)
    for (const [child, ppid] of processes) if (ppid === pid) found.push(child)
  return found
}

function signalProcess(pid, signal) {
  try {
    process.kill(pid, signal)
  } catch (error) {
    if (error.code !== "ESRCH") throw error
  }
}

async function checkDevelopment(directory, target, signal) {
  const port = await freePort()
  const databasePort = await freePort()
  const keyFile = join(directory, "encryption-key")
  const origin = `http://127.0.0.1:${port}`
  const env = Object.fromEntries(
    Object.entries(process.env).filter(([key]) => !key.startsWith("CLAVIS_")),
  )
  const settings = {
    CLAVIS_HTTP_ADDR: `127.0.0.1:${port}`,
    CLAVIS_DATABASE_URL: `postgres://unused:unused@127.0.0.1:${databasePort}/unused?sslmode=disable`,
    CLAVIS_ENCRYPTION_KEY_FILE: keyFile,
    CLAVIS_DB_CHECK_TIMEOUT: "100ms",
    CLAVIS_SHUTDOWN_TIMEOUT: "1s",
    CLAVIS_LOG_LEVEL: "info",
  }
  if (target === "dev") {
    writeFileSync(
      join(directory, ".env"),
      [
        ...Object.entries(settings).map(([key, value]) => `${key}=${value}`),
        "CLAVIS_LOG_LEVEL=invalid-from-file",
        "CLAVIS_UNUSED=$(touch dotenv-executed)",
      ].join("\n"),
    )
    // Existing environment values must override .env; shell syntax is data.
    env.CLAVIS_LOG_LEVEL = "info"
  } else {
    Object.assign(env, settings)
  }
  const child = spawn("make", [target], {
    cwd: directory,
    env,
    detached: true,
  })
  let output = "",
    pids = []
  child.stdout.on("data", (chunk) => (output += chunk))
  child.stderr.on("data", (chunk) => (output += chunk))
  const finished = new Promise((resolve) => {
    child.once("error", (error) => resolve({ error }))
    child.once("close", (code) => resolve({ code }))
  })
  try {
    let running = false
    for (let attempt = 0; attempt < 150; attempt++) {
      try {
        const response = await fetch(`${origin}/livez`, {
          signal: AbortSignal.timeout(200),
        })
        assert.equal(response.status, 200)
        assert.deepEqual(await response.json(), { status: "alive" })
        running = true
        break
      } catch {
        if (child.exitCode !== null) break
        await delay(100)
      }
    }
    assert.ok(running, `make ${target} did not start: ${output}`)
    pids = descendants(child.pid)
    for (const [path, status, type, text] of [
      ["/", 303, "text/html", "/admin/users"],
      ["/login", 200, "text/html", "Sign in"],
      ["/readyz", 503, "application/json", "DEPENDENCY_UNAVAILABLE"],
    ]) {
      const response = await fetch(`${origin}${path}`, {
        redirect: "manual",
        signal: AbortSignal.timeout(2_000),
      })
      assert.equal(response.status, status)
      assert.ok(response.headers.get("content-type").startsWith(type))
      assert.ok((await response.text()).includes(text))
    }
    assert.equal(existsSync(join(directory, "dotenv-executed")), false)
    // Model Ctrl-C / terminal termination, including the Make and Node group.
    signalProcess(-child.pid, signal)
    let forced = false
    const timer = setTimeout(() => {
      forced = true
      for (const pid of pids) signalProcess(pid, "SIGKILL")
    }, 5_000)
    try {
      const result = await finished
      assert.ifError(result.error)
      assert.equal(forced, false, `make ${target} required forced cleanup`)
      assert.match(output, /"msg":"server_stopped"/)
      for (const pid of pids)
        assert.throws(() => process.kill(pid, 0), { code: "ESRCH" })
      await assert.rejects(
        fetch(`${origin}/livez`, {
          signal: AbortSignal.timeout(200),
        }),
      )
    } finally {
      clearTimeout(timer)
    }
  } finally {
    // Even a failed assertion must not leave the detached Go child behind.
    for (const pid of new Set([...pids, ...descendants(child.pid)].reverse()))
      signalProcess(pid, "SIGKILL")
    await finished
    rmSync(join(directory, ".env"), { force: true })
  }
}

test("server builds from clean assets and runs as a copied executable", async (t) => {
  const directory = fixture(t)
  assert.equal(existsSync(join(directory, "internal/web/assets")), false)
  const generated = join(directory, "internal/web/auth_templ.go")
  const before = digest(generated)
  execute(directory, "make", ["build-server"])
  assert.equal(digest(generated), before)
  assert.match(
    execute(directory, "go", ["version", "-m", "bin/server"]),
    /CGO_ENABLED=0/,
  )
  assert.deepEqual(readdirSync(join(directory, "bin")), ["server"])
  await checkCopiedServer(directory)

  for (const [target, signal] of [
    ["dev", "SIGINT"],
    ["dev-api", "SIGTERM"],
  ])
    await t.test(`${target} serves UI/API and cleans up on ${signal}`, () =>
      checkDevelopment(directory, target, signal),
    )
  await t.test("development fails without database configuration", () => {
    const result = spawnSync(process.execPath, ["scripts/dev.mjs", "api"], {
      cwd: directory,
      env: Object.fromEntries(
        Object.entries(process.env).filter(
          ([key]) => !key.startsWith("CLAVIS_"),
        ),
      ),
      encoding: "utf8",
      timeout: 5_000,
    })
    assert.ifError(result.error)
    assert.equal(result.status, 2)
    assert.match(result.stderr, /CLAVIS_DATABASE_URL is required/)
  })

  await t.test(
    "compile-server stamps the identity without the gates",
    async () => {
      const template = join(directory, "internal/web/auth.templ")
      const original = readFileSync(template, "utf8")
      writeFileSync(
        template,
        original.replace("Dark appearance", "Changed without generation."),
      )
      try {
        // The full build still refuses a stale generated source.
        execute(directory, "make", ["build-server"], 2)
        execute(directory, "make", [
          "compile-server",
          "VERSION=1.2.3",
          "COMMIT=abc",
          "DATE=2026-09-15",
        ])
        assert.deepEqual(readdirSync(join(directory, "bin")), ["server"])
        assert.match(
          await startupLog(directory),
          /"msg":"server_started","version":"1.2.3","commit":"abc","date":"2026-09-15"/,
        )
      } finally {
        writeFileSync(template, original)
      }
    },
  )

  const binary = digest(join(directory, "bin/server"))
  for (const [name, path, damaged] of [
    ["missing database generated source", "internal/database/sqlc/db.go", null],
    [
      "stale database generated source",
      "internal/database/sqlc/db.go",
      `${readFileSync(join(directory, "internal/database/sqlc/db.go"), "utf8")}\n// stale\n`,
    ],
    ["missing generated source", "internal/web/auth_templ.go", null],
    [
      "stale generated source",
      "internal/web/auth.templ",
      readFileSync(join(directory, "internal/web/auth.templ"), "utf8").replace(
        "Dark appearance",
        "Changed without generation.",
      ),
    ],
    ["missing stylesheet", "web/styles/app.css", null],
    [
      "Go compilation failure",
      "cmd/server/broken.go",
      "package main\nfunc broken(\n",
    ],
  ]) {
    await t.test(name, () => {
      const absolute = join(directory, path)
      const original = existsSync(absolute) ? readFileSync(absolute) : null
      if (damaged === null) rmSync(absolute)
      else writeFileSync(absolute, damaged)
      try {
        execute(directory, "make", ["build-server"], 2)
        assert.equal(digest(join(directory, "bin/server")), binary)
        assert.deepEqual(readdirSync(join(directory, "bin")), ["server"])
        if (damaged === null) assert.equal(existsSync(absolute), false)
        else assert.equal(readFileSync(absolute, "utf8"), damaged)
        if (name === "missing stylesheet")
          assert.equal(
            existsSync(join(directory, "internal/web/assets")),
            false,
          )
      } finally {
        if (original === null) rmSync(absolute, { force: true })
        else writeFileSync(absolute, original)
      }
    })
  }
})

test("CLI builds without web or SQL sources or tools and publishes only successful builds", (t) => {
  const directory = fixture(t, false)
  for (const path of [
    "web",
    "internal/web",
    "internal/database",
    "sqlc.yaml",
    ".sqlc-version",
    "scripts",
  ])
    rmSync(join(directory, path), { recursive: true, force: true })
  execute(directory, "make", ["build-cli", "NODE=false", "PNPM=false"])
  execute(directory, join(directory, "bin/clavis"), ["--help"])
  const binary = digest(join(directory, "bin/clavis"))
  writeFileSync(
    join(directory, "cmd/clavis/broken.go"),
    "package main\nfunc broken(\n",
  )
  execute(directory, "make", ["build-cli", "NODE=false", "PNPM=false"], 2)
  assert.equal(digest(join(directory, "bin/clavis")), binary)
  assert.deepEqual(readdirSync(join(directory, "bin")), ["clavis"])
})

test("Make propagates missing tool failures without implicit installation", (t) => {
  const directory = fixture(t, false)
  copyFileSync(join(root, "sqlc.yaml"), join(directory, "sqlc.yaml"))
  for (const target of [
    "check-web-generated",
    "lint-go",
    "check-db-generated",
  ]) {
    execute(directory, "make", [target, `NODE=${process.execPath}`], 2)
    assert.equal(existsSync(join(directory, ".tools")), false)
  }
})
