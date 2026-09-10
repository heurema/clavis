import assert from "node:assert/strict"
import { spawn, spawnSync } from "node:child_process"
import { createHash } from "node:crypto"
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
  t.after(() => rmSync(directory, { recursive: true, force: true }))
  for (const path of ["cmd", "internal", "scripts", "web/styles"]) {
    cpSync(join(root, path), join(directory, path), {
      recursive: true,
      filter: (source) =>
        source !== join(root, "internal/web/assets") &&
        !source.includes("/.assets-"),
    })
  }
  for (const path of ["Makefile", "go.mod", "go.sum", "web/package.json"])
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
        const response = await fetch(`${origin}/health/live`, {
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
    for (const [path, status, type, text] of [
      ["/", 200, "text/html", "Readiness has not been checked."],
      ["/assets/app.css", 200, "text/css", ".sr-only"],
      ["/assets/htmx.min.js", 200, "text/javascript", "htmx"],
      ["/assets/notices.txt", 200, "text/plain", "Cole Bemis"],
      ["/ui/readiness", 503, "text/html", "Database unavailable"],
      ["/health/ready", 503, "application/json", "DEPENDENCY_UNAVAILABLE"],
    ]) {
      const response = await fetch(`${origin}${path}`, {
        signal: AbortSignal.timeout(2_000),
      })
      assert.equal(response.status, status, path)
      assert.ok(response.headers.get("content-type").startsWith(type), path)
      const body = await response.text()
      assert.ok(body.includes(text), path)
      assert.ok(!body.includes("sentinel-private"), path)
    }
    assert.deepEqual(readdirSync(runtime), ["server"])
    assert.ok(!output.includes("sentinel-private"))
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

test("server builds from clean assets and runs as a copied executable", async (t) => {
  const directory = fixture(t)
  assert.equal(existsSync(join(directory, "internal/web/assets")), false)
  const generated = join(directory, "internal/web/page_templ.go")
  const before = digest(generated)
  execute(directory, "make", ["build-server"])
  assert.equal(digest(generated), before)
  assert.match(
    execute(directory, "go", ["version", "-m", "bin/server"]),
    /CGO_ENABLED=0/,
  )
  assert.deepEqual(readdirSync(join(directory, "bin")), ["server"])
  await checkCopiedServer(directory)

  const binary = digest(join(directory, "bin/server"))
  for (const [name, path, damaged] of [
    ["missing generated source", "internal/web/page_templ.go", null],
    [
      "stale generated source",
      "internal/web/page.templ",
      readFileSync(join(directory, "internal/web/page.templ"), "utf8").replace(
        "Readiness has not been checked.",
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

test("CLI builds without web sources or tools and publishes only successful builds", (t) => {
  const directory = fixture(t, false)
  for (const path of ["web", "internal/web", "scripts"])
    rmSync(join(directory, path), { recursive: true })
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
