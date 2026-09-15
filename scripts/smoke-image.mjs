import assert from "node:assert/strict"
import { spawn } from "node:child_process"
import { randomBytes } from "node:crypto"
import {
  chmodSync,
  existsSync,
  mkdirSync,
  mkdtempSync,
  rmSync,
  statSync,
  writeFileSync,
} from "node:fs"
import { createServer } from "node:net"
import { join } from "node:path"
import { setTimeout as delay } from "node:timers/promises"
import { fileURLToPath } from "node:url"

const root = fileURLToPath(new URL("../", import.meta.url))
const reports = join(root, "reports")

// The only argument is the image reference to smoke, so a release candidate can
// be checked without retagging it. Anything else is a mistake worth naming.
export function parseArguments(argv) {
  const options = { image: "clavis:local" }
  for (let index = 0; index < argv.length; index += 1) {
    if (argv[index] !== "--image")
      throw new Error(`Unknown argument ${argv[index]}; usage: [--image REF]`)
    const value = argv[index + 1]
    if (!value) throw new Error("--image needs an image reference")
    options.image = value
    index += 1
  }
  return options
}

// Only the assets the sign-in document itself references are fetched, so a
// renamed or removed asset shows up as a missing reference rather than a 404
// against a path this script hard-codes.
export function assetURLs(document) {
  const found = []
  for (const [, url] of document.matchAll(
    /(?:src|href)="(\/assets\/[^"]+)"/g,
  )) {
    if (!found.includes(url)) found.push(url)
  }
  return found
}

// `docker top <container> -o uid,pid,comm` prints a header row and one row per
// process, uid first. The explicit ps format is what keeps the uid numeric: the
// default format resolves it against the Docker host's own account database,
// which names 65532 after whatever unrelated account happens to hold it there.
export function processUIDs(output) {
  const lines = output.split("\n").map((line) => line.trim())
  const header = lines.findIndex((line) => /^UID(\s|$)/.test(line))
  if (header < 0) throw new Error("docker top printed no UID column")
  return lines
    .slice(header + 1)
    .filter(Boolean)
    .map((line) => line.split(/\s+/)[0])
}

// `docker compose port app 8080` prints the host binding; the smoke published
// the port itself, so a different one means compose reassigned it.
export function publishedPort(binding, expected) {
  const match = binding.trim().match(/^127\.0\.0\.1:(\d+)$/)
  if (!match)
    throw new Error(`Expected a loopback binding, not ${binding.trim()}`)
  assert.equal(Number(match[1]), expected, "compose republished the app port")
  return Number(match[1])
}

// Every check lands in the summary whatever its outcome, so a failed run still
// says which step stopped it.
export function record(summary, name, status) {
  summary.checks[name] = status
  return summary
}

export function finalize(summary) {
  const failed = Object.entries(summary.checks)
    .filter(([, status]) => status !== "passed")
    .map(([name]) => name)
  summary.status = failed.length || summary.message ? "failed" : "passed"
  if (failed.length) summary.failedChecks = failed
  return summary
}

export function composeEnvironment(base, settings) {
  return {
    ...base,
    CLAVIS_APP_IMAGE: settings.image,
    CLAVIS_APP_PORT: String(settings.appPort),
    CLAVIS_DB_PORT: String(settings.dbPort),
    CLAVIS_VM_PORT: String(settings.metricsPort),
    CLAVIS_VL_PORT: String(settings.logsPort),
    CLAVIS_APP_SECRETS_DIR: settings.secretsDirectory,
    CLAVIS_APP_SECRETS_GID: String(settings.secretsGID),
    CLAVIS_APP_BOOTSTRAP_USERNAME: settings.username,
  }
}

async function run() {
  const options = parseArguments(process.argv.slice(2))
  mkdirSync(reports, { recursive: true })
  const project = `clavis-smoke-image-${process.pid}-${randomBytes(4).toString("hex")}`
  const compose = [
    "compose",
    // The profile stays active for every call, including the teardown, so the
    // app container is created and removed by this project alone.
    "--profile",
    "app",
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
  // Longer than the API smoke: a container start, the first-run migrations and
  // the bootstrap happen on top of the database start, and the image may be
  // pulled on a machine that has not run compose before.
  const deadline = Date.now() + 240_000
  const summary = {
    project,
    scope: "image",
    image: options.image,
    status: "running",
    startedAt: new Date().toISOString(),
    checks: {},
  }
  let cleaning = false,
    composeStarted = false,
    stopped = false,
    before,
    container,
    secretsDirectory
  function persist() {
    writeFileSync(
      join(reports, "smoke-image-summary.json"),
      JSON.stringify(summary, null, 2) + "\n",
    )
  }
  persist()

  function start(command, args, name, options = {}) {
    if (!cleaning && (stopped || Date.now() >= deadline))
      throw new Error("Image smoke cancelled or exceeded 240 seconds")
    const log = join(reports, `smoke-image-${name}.log`)
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
    const collect = (chunk) => {
      output += chunk.toString()
    }
    child.stdout.on("data", collect)
    child.stderr.on("data", collect)
    child.finished = new Promise((resolve) => {
      child.on("error", (error) => {
        children.delete(child)
        resolve({ code: 1, output: error.message })
      })
      child.on("close", (code) => {
        children.delete(child)
        // Buffer before redaction so a secret split across output chunks
        // cannot be written partially into reports.
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
      cleaning ? 30_000 : Math.max(1, deadline - Date.now()),
    )
    try {
      const result = await child.finished
      assert.equal(
        result.code,
        expected,
        `${name} failed; see reports/smoke-image-${name}.log`,
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
  // A guard runs before each attempt and throws, so a container that died on
  // startup fails the check at once instead of after the whole deadline.
  async function poll(describe, accept, guard) {
    let last = "no response yet"
    while (Date.now() < deadline && !stopped) {
      if (guard) await guard()
      try {
        const outcome = await accept()
        if (outcome === true) return
        last = outcome
      } catch (error) {
        last = error.message
      }
      await delay(250)
    }
    throw new Error(`${describe} within the image smoke deadline: ${last}`)
  }
  // A container that exits never answers, so waiting out the deadline only
  // hides the reason; its logs are written to reports during cleanup.
  function stillRunning(container, service) {
    return async () => {
      const state = await execute(
        "docker",
        [
          "inspect",
          "--format",
          "{{.State.Status}} {{.State.ExitCode}}",
          container,
        ],
        `${service}-state`,
      )
      const [status, code = "unknown"] = state.split(/\s+/)
      if (status !== "running")
        throw new Error(
          `the ${service} container is ${status} (exit code ${code}); see reports/smoke-image-${service}.log`,
        )
    }
  }
  function cancel() {
    stopped = true
    for (const child of children) void stop(child)
  }
  for (const signal of ["SIGINT", "SIGTERM"]) process.on(signal, cancel)
  const watchdog = setTimeout(cancel, Math.max(1, deadline - Date.now()))
  // Every check lands in the summary under its own name, so a failed run says
  // which step stopped it without reading the logs.
  async function step(name, action) {
    record(summary, name, "running")
    try {
      const outcome = await action()
      record(summary, name, "passed")
      return outcome
    } catch (error) {
      record(summary, name, "failed")
      error.message = `${name}: ${error.message}`
      throw error
    }
  }

  try {
    console.log(
      `[smoke-image] Isolated project ${project}; image ${options.image}; 240 second bound`,
    )
    before = await snapshot()
    const appPort = await freePort()
    const origin = `http://127.0.0.1:${appPort}`
    summary.origin = origin
    const username = "smoke-admin"

    // The container reads both files as uid 65532, which owns neither on a
    // Linux host, so they are group-readable and the container joins the group
    // that owns them. Root-owned chown is not required and is not attempted.
    // On macOS Docker hosts the bind mount presents the files as owned by the
    // container user, so the group-read branch of the permission rule is
    // exercised on Linux hosts and by the kind verification; the refusal of a
    // world-readable file holds on every host, which is what
    // CLAVIS_SMOKE_IMAGE_SECRET_MODE=0444 exercises.
    const secretMode = Number.parseInt(
      process.env.CLAVIS_SMOKE_IMAGE_SECRET_MODE || "440",
      8,
    )
    mkdirSync(join(root, ".local"), { recursive: true })
    secretsDirectory = mkdtempSync(join(root, ".local/smoke-image-secrets-"))
    summary.secretsDirectory = secretsDirectory
    const password = randomBytes(24).toString("base64url")
    secrets.add(password)
    writeFileSync(
      join(secretsDirectory, "encryption-key"),
      randomBytes(32).toString("hex") + "\n",
      { mode: 0o440 },
    )
    writeFileSync(
      join(secretsDirectory, "bootstrap-password"),
      password + "\n",
      { mode: 0o440 },
    )
    // mkdtemp creates 0700; the container's group needs to traverse it.
    for (const [path, mode] of [
      [secretsDirectory, 0o750],
      [join(secretsDirectory, "encryption-key"), secretMode],
      [join(secretsDirectory, "bootstrap-password"), secretMode],
    ])
      chmodSync(path, mode)
    summary.secretMode = secretMode.toString(8).padStart(4, "0")
    const secretsGID = statSync(join(secretsDirectory, "encryption-key")).gid
    summary.secretsGID = secretsGID

    Object.assign(
      env,
      composeEnvironment(env, {
        image: options.image,
        appPort,
        dbPort: await freePort(),
        metricsPort: await freePort(),
        logsPort: await freePort(),
        secretsDirectory,
        secretsGID,
        username,
      }),
    )

    composeStarted = true
    // The database has a health check, so --wait is meaningful for it. The
    // distroless app has none by design; it is polled over HTTP below.
    await step("databaseStarted", () =>
      execute(
        "docker",
        [...compose, "up", "-d", "--wait", "--wait-timeout", "90", "db"],
        "database-start",
      ),
    )
    await step("appStarted", async () => {
      await execute("docker", [...compose, "up", "-d", "app"], "app-start")
      container = (
        await execute(
          "docker",
          [...compose, "ps", "--all", "-q", "app"],
          "app-container-id",
        )
      ).split("\n")[0]
      assert(container, "compose created no app container")
      // A container that refused its configuration is already gone; report the
      // exit rather than the port query that fails as a consequence.
      await stillRunning(container, "app")()
      publishedPort(
        await execute(
          "docker",
          [...compose, "port", "app", "8080"],
          "app-port",
        ),
        appPort,
      )
    })
    const running = stillRunning(container, "app")

    await step("livez", () =>
      poll(
        "Liveness did not reach HTTP 200",
        async () => {
          const response = await fetch(`${origin}/livez`, {
            signal: AbortSignal.timeout(2_000),
          })
          const body = await response.text()
          return response.status === 200 || `HTTP ${response.status} ${body}`
        },
        running,
      ),
    )

    // The first start applies the migrations and creates the administrator, so
    // readiness trails liveness.
    await step("readyz", () =>
      poll(
        "Readiness did not report ready",
        async () => {
          const response = await fetch(`${origin}/readyz`, {
            signal: AbortSignal.timeout(2_000),
          })
          const body = (await response.text()).trim()
          return (
            (response.status === 200 && body === '{"status":"ready"}') ||
            `HTTP ${response.status} ${body}`
          )
        },
        running,
      ),
    )

    await step("healthz", async () => {
      const response = await fetch(`${origin}/healthz`, {
        signal: AbortSignal.timeout(2_000),
      })
      assert.equal(response.status, 200, "/healthz is not 200")
      const health = await response.json()
      assert.equal(health.status, "ok")
      assert.equal(typeof health.version, "string")
      assert(health.version, "/healthz reports no build version")
      // The running executable must carry the identity the image advertises:
      // the label and the linker stamp come from the same build arguments.
      const labelled = await execute(
        "docker",
        [
          "image",
          "inspect",
          options.image,
          "--format",
          '{{index .Config.Labels "org.opencontainers.image.version"}}',
        ],
        "image-version-label",
      )
      assert.equal(
        health.version,
        labelled,
        "/healthz reports a different version than the image label",
      )
      summary.version = health.version
    })

    await step("loginDocumentAndAsset", async () => {
      const login = await fetch(`${origin}/login`, {
        redirect: "error",
        signal: AbortSignal.timeout(2_000),
      })
      assert.equal(login.status, 200, "/login is unavailable")
      assert.equal(
        login.headers.get("content-type")?.split(";")[0],
        "text/html",
      )
      const assets = assetURLs(await login.text())
      assert(assets.length, "The sign-in document references no embedded asset")
      const asset = await fetch(origin + assets[0], {
        redirect: "error",
        signal: AbortSignal.timeout(2_000),
      })
      assert.equal(asset.status, 200, `${assets[0]} is unavailable`)
      assert((await asset.text()).trim(), `${assets[0]} is empty`)
      summary.asset = assets[0]
    })

    await step("nonRootProcess", async () => {
      const uids = processUIDs(
        await execute(
          "docker",
          ["top", container, "-o", "uid,pid,comm"],
          "app-top",
        ),
      )
      assert(uids.length, "docker top listed no process")
      assert(
        uids.every((uid) => uid === "65532"),
        `The container runs as ${uids.join(", ")}, not 65532`,
      )
    })

    const inspected = JSON.parse(
      await execute("docker", ["inspect", container], "app-inspect"),
    )[0]
    await step("readOnlyRootFilesystem", () =>
      assert.equal(
        inspected.HostConfig.ReadonlyRootfs,
        true,
        "The root filesystem is writable",
      ),
    )
    await step("nonRootUserConfigured", () =>
      assert.equal(
        inspected.Config.User,
        "65532:65532",
        "The container does not run as the nonroot user",
      ),
    )

    // The CLI sends no Origin header, so it reaches the published loopback port
    // even though the container's public URL is HTTPS.
    if (!existsSync(join(root, "bin/clavis")))
      await execute("make", ["build-cli"], "build-cli")
    const home = join(secretsDirectory, "client-home")
    mkdirSync(home, { mode: 0o700 })
    const clientEnv = {
      ...env,
      HOME: home,
      XDG_CONFIG_HOME: join(home, ".config"),
    }
    async function cli(name, args, input) {
      const result = JSON.parse(
        await execute(
          join(root, "bin/clavis"),
          [...args, "--server", origin],
          `cli-${name}`,
          { env: clientEnv, input },
        ),
      )
      assert.equal(result.schemaVersion, 1)
      assert.equal(result.ok, true)
      for (const secret of secrets)
        assert(
          !JSON.stringify(result).includes(secret),
          "The CLI exposed a password",
        )
      return result
    }
    await step("cliDoctor", async () =>
      assert.equal((await cli("doctor", ["doctor"])).data.database, "ready"),
    )
    await step("cliSignIn", async () => {
      const signedIn = await cli(
        "login",
        ["login", "--username", username, "--password-stdin"],
        password + "\n",
      )
      assert.equal(signedIn.data.user.username, username)
      assert.equal(
        (await cli("whoami", ["whoami"])).data.user.id,
        signedIn.data.user.id,
      )
    })

    assert(
      !stopped && Date.now() < deadline,
      "The image smoke exceeded its deadline",
    )
    console.log("[smoke-image] Image health, documents and CLI sign-in passed")
  } catch (error) {
    summary.message = redact(error.message)
    console.error(`[smoke-image] ${summary.message}`)
  } finally {
    cleaning = true
    clearTimeout(watchdog)
    // Attempt every cleanup even when an earlier step failed. Only the unique
    // project and the temporary secrets directory belong to this run.
    const errors = []
    async function cleanup(label, action) {
      try {
        await action()
      } catch (error) {
        errors.push(`${label}: ${redact(error.message)}`)
      }
    }
    for (const child of children)
      await cleanup(`process ${child.pid}`, () => stop(child))
    // Capture the containers' own output before the teardown removes them:
    // a refused secret file or a failed migration is only visible there.
    // execute names the report, so these land in reports/smoke-image-<service>.log
    // with the password already redacted.
    if (composeStarted && summary.message !== undefined)
      for (const service of ["app", "db"])
        await cleanup(`${service} logs`, () =>
          execute(
            "docker",
            [...compose, "logs", "--no-color", service],
            service,
          ),
        )
    if (composeStarted)
      await cleanup("compose project", () =>
        execute(
          "docker",
          [
            ...compose,
            "down",
            "--volumes",
            "--remove-orphans",
            "--timeout",
            "10",
          ],
          "cleanup",
        ),
      )
    await cleanup("secrets", () => {
      if (secretsDirectory) {
        rmSync(secretsDirectory, { recursive: true, force: true })
        assert(
          !existsSync(secretsDirectory),
          "The temporary secrets directory was not removed",
        )
      }
      summary.secretsRemoved = true
    })
    await cleanup("Docker inventory", async () => {
      const after = await snapshot()
      if (before)
        for (const kind of ["containers", "volumes"])
          assert(
            before[kind].every((id) => after[kind].includes(id)),
            `Pre-existing ${kind} disappeared during the image smoke`,
          )
      assert(
        !after.volumes.some((name) => name.startsWith(project + "_")),
        "The temporary volume was not cleaned up",
      )
      for (const [what, args] of [
        [
          "container",
          [
            "ps",
            "-aq",
            "--filter",
            `label=com.docker.compose.project=${project}`,
          ],
        ],
        [
          "network",
          [
            "network",
            "ls",
            "-q",
            "--filter",
            `label=com.docker.compose.project=${project}`,
          ],
        ],
      ])
        assert.equal(
          await execute("docker", args, `cleanup-verify-${what}`),
          "",
          `The temporary ${what} was not cleaned up`,
        )
      summary.preExistingResourcesPreserved = true
    })
    summary.cleanup = errors.length ? "failed" : "passed"
    if (errors.length) {
      summary.cleanupErrors = errors
      record(summary, "cleanup", "failed")
      console.error(
        `[smoke-image] Cleanup verification failed: ${errors.join("; ")}`,
      )
    }
    finalize(summary)
    if (summary.status !== "passed") process.exitCode = 1
    summary.finishedAt = new Date().toISOString()
    persist()
    console.log(
      `[smoke-image] ${summary.status}; cleanup ${summary.cleanup}; reports/smoke-image-summary.json`,
    )
  }
}

if (import.meta.main) await run()
