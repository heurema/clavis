import assert from "node:assert/strict"
import { test } from "node:test"

// Pure helpers only: importing the module must not reach Docker, compose or the
// filesystem, so these tests run wherever the other script tests do.
import {
  assetURLs,
  composeEnvironment,
  finalize,
  parseArguments,
  processUIDs,
  publishedPort,
  record,
} from "./smoke-image.mjs"

test("parseArguments defaults to the local image tag", () => {
  assert.deepEqual(parseArguments([]), { image: "clavis:local" })
})

test("parseArguments accepts an image override", () => {
  assert.deepEqual(parseArguments(["--image", "clavis:multi"]), {
    image: "clavis:multi",
  })
})

test("parseArguments rejects unknown and incomplete arguments", () => {
  assert.throws(() => parseArguments(["--tag", "x"]), /Unknown argument --tag/)
  assert.throws(() => parseArguments(["clavis:local"]), /Unknown argument/)
  assert.throws(
    () => parseArguments(["--image"]),
    /--image needs an image reference/,
  )
})

test("assetURLs collects the document's own embedded asset paths once", () => {
  const document = `<!doctype html><html><head>
    <script src="/assets/appearance.js"></script>
    <link rel="stylesheet" href="/assets/app.css"/>
    <link rel="stylesheet" href="/assets/app.css"/>
    </head><body><a href="/login">Sign in</a>
    <img src="https://example.test/assets/remote.png"/></body></html>`
  assert.deepEqual(assetURLs(document), [
    "/assets/appearance.js",
    "/assets/app.css",
  ])
})

test("assetURLs returns nothing when the document references no asset", () => {
  assert.deepEqual(assetURLs("<html><body>Sign in</body></html>"), [])
})

test("processUIDs reads the uid column of every process row", () => {
  const output = [
    "UID                 PID                 COMMAND",
    "65532               40321               server",
    "65532               40355               server",
  ].join("\n")
  assert.deepEqual(processUIDs(output), ["65532", "65532"])
})

test("processUIDs accepts a resolved user name", () => {
  const output = "UID  PID  COMMAND\nnonroot  40321  server"
  assert.deepEqual(processUIDs(output), ["nonroot"])
})

test("processUIDs fails when no header is printed", () => {
  assert.throws(() => processUIDs("no such service\n"), /no UID column/)
})

test("publishedPort accepts the port the smoke published", () => {
  assert.equal(publishedPort("127.0.0.1:53124\n", 53124), 53124)
})

test("publishedPort rejects a reassigned or non-loopback binding", () => {
  assert.throws(
    () => publishedPort("127.0.0.1:53124", 53125),
    /republished the app port/,
  )
  assert.throws(() => publishedPort("0.0.0.0:8081", 8081), /loopback binding/)
  assert.throws(() => publishedPort("", 8081), /loopback binding/)
})

test("record keeps every outcome under its check name", () => {
  const summary = { checks: {} }
  record(summary, "livez", "running")
  record(summary, "livez", "passed")
  record(summary, "readyz", "failed")
  assert.deepEqual(summary.checks, { livez: "passed", readyz: "failed" })
})

test("finalize passes only when every check passed and nothing was reported", () => {
  const summary = finalize({ checks: { livez: "passed", readyz: "passed" } })
  assert.equal(summary.status, "passed")
  assert.equal(summary.failedChecks, undefined)
})

test("finalize names the failing checks", () => {
  const summary = finalize({
    checks: { livez: "passed", readyz: "failed", healthz: "running" },
    message: "readyz: timed out",
  })
  assert.equal(summary.status, "failed")
  assert.deepEqual(summary.failedChecks, ["readyz", "healthz"])
})

test("finalize fails a run that reported a message before any check", () => {
  assert.equal(
    finalize({ checks: {}, message: "docker is not running" }).status,
    "failed",
  )
})

test("composeEnvironment publishes the ports and the secrets group", () => {
  const environment = composeEnvironment(
    { PATH: "/usr/bin", CLAVIS_APP_PORT: "8081" },
    {
      image: "clavis:local",
      appPort: 53124,
      dbPort: 53125,
      metricsPort: 53126,
      logsPort: 53127,
      secretsDirectory: "/tmp/secrets",
      secretsGID: 20,
      username: "smoke-admin",
    },
  )
  assert.equal(environment.PATH, "/usr/bin")
  assert.deepEqual(
    {
      image: environment.CLAVIS_APP_IMAGE,
      app: environment.CLAVIS_APP_PORT,
      db: environment.CLAVIS_DB_PORT,
      metrics: environment.CLAVIS_VM_PORT,
      logs: environment.CLAVIS_VL_PORT,
      directory: environment.CLAVIS_APP_SECRETS_DIR,
      gid: environment.CLAVIS_APP_SECRETS_GID,
      username: environment.CLAVIS_APP_BOOTSTRAP_USERNAME,
    },
    {
      image: "clavis:local",
      app: "53124",
      db: "53125",
      metrics: "53126",
      logs: "53127",
      directory: "/tmp/secrets",
      gid: "20",
      username: "smoke-admin",
    },
  )
})
