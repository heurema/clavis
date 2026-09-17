import assert from "node:assert/strict"
import { spawn } from "node:child_process"
import { randomBytes } from "node:crypto"
import {
  cpSync,
  existsSync,
  mkdirSync,
  mkdtempSync,
  realpathSync,
  rmSync,
  writeFileSync,
} from "node:fs"
import { tmpdir } from "node:os"
import { join } from "node:path"
import { setTimeout as delay } from "node:timers/promises"
import { fileURLToPath } from "node:url"

// The chart check owns the kubeconform invocation; the same command shape
// validates the values this run actually installed.
import {
  chartPath,
  helmPath,
  kubeconformArguments,
  kubeconformPath,
  schemaLocations,
} from "./chart-lint.mjs"
import { browserSignIn } from "./browser-sign-in.mjs"

const root = fileURLToPath(new URL("../", import.meta.url))
const reports = join(root, "reports")
const kindPath = ".tools/kind/bin/kind"

// kind 0.31.0 boots this node image by default; it is pinned here by the digest
// of its multi-architecture index so the cluster this script verifies against is
// the one the pinned kind ships and stays reproducible after an upstream retag.
export const nodeImage =
  "kindest/node:v1.35.0@sha256:452d707d4862f52530247495d180205e029056831160e22870e37e3f6c1ac31f"
// The database image and digest compose.yaml pins, so the kind run and the
// compose run exercise the same PostgreSQL build.
export const databaseImage =
  "postgres:18.6@sha256:4ef4dbc939d61acea57712655ddb4b4ab27419c913f94cca0cd57cb3ea3c2280"
// The chart's own names for a release called clavis, and the container the
// Deployment declares; the ephemeral debug container targets it by name.
export const releaseName = "clavis"
// The release's public origin: the browser sign-in form and Approve check it.
const publicURL = "https://clavis.verify.test"
export const selector =
  "app.kubernetes.io/name=clavis,app.kubernetes.io/instance=clavis"
export const serverContainer = "server"
export const secretsDirectory = "/var/run/secrets/clavis"

// Two debugging escapes, both opt-in: the cluster and the two images are
// removed by default because this script created them.
export function parseArguments(argv) {
  const options = { keepCluster: false, keepImages: false }
  for (const argument of argv) {
    if (argument === "--keep-cluster") options.keepCluster = true
    else if (argument === "--keep-images") options.keepImages = true
    else
      throw new Error(
        `Unknown argument ${argument}; usage: [--keep-cluster] [--keep-images]`,
      )
  }
  return options
}

// A plain Deployment and Service rather than an operator: the chart owns no
// database, so the cluster only has to offer one reachable PostgreSQL endpoint.
// The data volume is an emptyDir because the cluster outlives nothing.
export function databaseManifest(password, image = databaseImage) {
  return `apiVersion: apps/v1
kind: Deployment
metadata:
  name: postgres
  labels:
    app: postgres
spec:
  replicas: 1
  selector:
    matchLabels:
      app: postgres
  template:
    metadata:
      labels:
        app: postgres
    spec:
      containers:
        - name: postgres
          image: ${JSON.stringify(image)}
          imagePullPolicy: IfNotPresent
          env:
            - name: POSTGRES_USER
              value: "clavis"
            - name: POSTGRES_PASSWORD
              value: ${JSON.stringify(password)}
            - name: POSTGRES_DB
              value: "clavis"
          ports:
            - name: postgres
              containerPort: 5432
          readinessProbe:
            exec:
              command: ["pg_isready", "-U", "clavis", "-d", "clavis"]
            initialDelaySeconds: 2
            periodSeconds: 2
          volumeMounts:
            # The image compose pins keeps its cluster under this directory
            # rather than a data subdirectory, and compose mounts the same path.
            - name: data
              mountPath: /var/lib/postgresql
      volumes:
        - name: data
          emptyDir: {}
---
apiVersion: v1
kind: Service
metadata:
  name: postgres
  labels:
    app: postgres
spec:
  selector:
    app: postgres
  ports:
    - name: postgres
      port: 5432
      targetPort: postgres
`
}

// The chart takes secrets by reference only, so the run creates them the way an
// operator would. The key and the password carry a terminal newline, which the
// readers strip, so the mounted files are the shape a secret manager writes.
export function secretManifests({
  databaseURL,
  encryptionKey,
  bootstrapPassword,
}) {
  return `apiVersion: v1
kind: Secret
metadata:
  name: clavis
type: Opaque
stringData:
  database-url: ${JSON.stringify(databaseURL)}
  encryption-key: ${JSON.stringify(encryptionKey + "\n")}
---
apiVersion: v1
kind: Secret
metadata:
  name: clavis-bootstrap
type: Opaque
stringData:
  password: ${JSON.stringify(bootstrapPassword + "\n")}
`
}

// kubectl port-forward with local port 0 picks a free port and prints it; the
// script reads it back rather than racing a port it picked itself.
export function forwardedPort(output) {
  const match = output.match(/Forwarding from 127\.0\.0\.1:(\d+)\s*->/)
  if (!match)
    throw new Error(
      `port-forward printed no local port: ${output.trim() || "(no output)"}`,
    )
  return Number(match[1])
}

// One readable state per pod: the Ready condition, not the phase, is what the
// Service and the rollout act on.
export function podStates(payload) {
  return (payload.items ?? []).map((pod) => ({
    name: pod.metadata?.name ?? "",
    image: pod.spec?.containers?.[0]?.image ?? "",
    ready: (pod.status?.conditions ?? []).some(
      (condition) => condition.type === "Ready" && condition.status === "True",
    ),
    terminating: Boolean(pod.metadata?.deletionTimestamp),
  }))
}

// The upgrade evidence. maxUnavailable 0 with maxSurge 1 means the new pod has
// to be ready before the old one is taken away, so the sequence to record is:
// both pods present at once, the new one ready, then the old one no longer
// ready, then gone. The ordering is reported rather than asserted because a
// sampler can miss a short-lived state; the overlap and the final state cannot
// be missed and are what the caller asserts.
export function analyzeRollout(samples, baseline) {
  const previous = new Set(baseline)
  const isNew = (pod) => !previous.has(pod.name)
  const analysis = {
    samples: samples.length,
    observedBothPods: false,
    newPods: [],
    newReadyAt: null,
    oldNotReadyAt: null,
    oldGoneAt: null,
    orderedReadinessHandover: false,
    sequence: [],
  }
  let last = ""
  for (const sample of samples) {
    for (const pod of sample.pods)
      if (isNew(pod) && !analysis.newPods.includes(pod.name))
        analysis.newPods.push(pod.name)
    const old = sample.pods.filter((pod) => !isNew(pod))
    const fresh = sample.pods.filter(isNew)
    if (old.length && fresh.length) analysis.observedBothPods = true
    if (analysis.newReadyAt === null && fresh.some((pod) => pod.ready))
      analysis.newReadyAt = sample.at
    if (
      analysis.newReadyAt !== null &&
      analysis.oldNotReadyAt === null &&
      old.every((pod) => !pod.ready)
    )
      analysis.oldNotReadyAt = sample.at
    if (analysis.oldGoneAt === null && old.length === 0 && fresh.length)
      analysis.oldGoneAt = sample.at
    const described = sample.pods
      .map(
        (pod) =>
          `${isNew(pod) ? "new" : "old"}=${pod.ready ? "Ready" : "NotReady"}${pod.terminating ? "/Terminating" : ""}`,
      )
      .sort()
      .join(" ")
    if (described !== last) {
      analysis.sequence.push(
        `${(sample.at / 1000).toFixed(1)}s ${described || "(no pods)"}`,
      )
      last = described
    }
  }
  analysis.orderedReadinessHandover =
    analysis.newReadyAt !== null &&
    analysis.oldNotReadyAt !== null &&
    analysis.oldNotReadyAt >= analysis.newReadyAt
  const final = samples.at(-1)
  analysis.oldPodGone = Boolean(final?.pods.length) && final.pods.every(isNew)
  return analysis
}

// `ls -ln` from inside the running pod: numeric owner and group, so the mode
// and the fsGroup the kubelet applied are read rather than inferred.
export function secretFileListing(output) {
  const entries = []
  for (const line of output.split("\n")) {
    const match = line
      .trim()
      .match(
        /^([-bcdlps][rwxsStT-]{9})[.+]?\s+\d+\s+(\d+)\s+(\d+)\s+\d+\s+.*?\s+(\S+)$/,
      )
    if (match)
      entries.push({
        mode: match[1],
        uid: Number(match[2]),
        gid: Number(match[3]),
        name: match[4],
      })
  }
  return entries
}

// `helm get values --all` prints a header line above the YAML in some output
// modes; the values alone are what `helm template -f -` can read back.
export function installedValues(output) {
  return output.replace(/^[A-Z][A-Z -]*VALUES:\s*\n/, "")
}

export function record(summary, name, status, seconds) {
  summary.checks[name] =
    seconds === undefined ? { status } : { status, seconds }
  return summary
}

// A skipped step is evidence that was not collected, never a failure: the
// summary names it so a reader does not mistake silence for proof.
export const skipped = Symbol("skipped")

export function finalize(summary) {
  const entries = Object.entries(summary.checks)
  const failed = entries
    .filter(
      ([, check]) => check.status !== "passed" && check.status !== "skipped",
    )
    .map(([name]) => name)
  const skippedChecks = entries
    .filter(([, check]) => check.status === "skipped")
    .map(([name]) => name)
  summary.status = failed.length || summary.message ? "failed" : "passed"
  if (failed.length) summary.failedChecks = failed
  if (skippedChecks.length) summary.skippedChecks = skippedChecks
  return summary
}

async function run() {
  const options = parseArguments(process.argv.slice(2))
  mkdirSync(reports, { recursive: true })
  const suffix = randomBytes(4).toString("hex")
  const cluster = `clavis-verify-${suffix}`
  const imageA = "clavis:kind-a"
  const imageB = "clavis:kind-b"
  const kind = join(root, kindPath)
  const helm = join(root, helmPath)
  const kubeconform = join(root, kubeconformPath)
  const chart = join(root, chartPath)
  const secrets = new Set()
  function redact(value) {
    for (const secret of secrets) value = value.replaceAll(secret, "[REDACTED]")
    return value
  }
  // Two image builds, a cluster, four rollouts and a migration: the bound is
  // generous because every step inside it has its own failure message.
  const budget = Number(process.env.CLAVIS_VERIFY_KIND_TIMEOUT_SECONDS ?? 2400)
  const deadline = Date.now() + budget * 1000
  const summary = {
    cluster,
    scope: "kind",
    nodeImage,
    databaseImage,
    images: { a: imageA, b: imageB },
    status: "running",
    startedAt: new Date().toISOString(),
    checks: {},
  }
  const children = new Set()
  let cleaning = false,
    stopped = false,
    clusterCreated = false,
    work,
    source,
    forward
  function persist() {
    writeFileSync(
      join(reports, "verify-kind.json"),
      JSON.stringify(summary, null, 2) + "\n",
    )
  }
  persist()

  const env = { ...process.env }

  function start(command, args, name, options = {}) {
    if (!cleaning && (stopped || Date.now() >= deadline))
      throw new Error(
        `Kind verification cancelled or exceeded ${budget} seconds`,
      )
    const { input, quiet, ...spawnOptions } = options
    const log = join(reports, `verify-kind-${name}.log`)
    if (!quiet) writeFileSync(log, "")
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
      child.text = output
    }
    child.text = ""
    child.stdout.on("data", collect)
    child.stderr.on("data", collect)
    child.finished = new Promise((resolve) => {
      child.on("error", (error) => {
        children.delete(child)
        resolve({ code: 1, output: error.message })
      })
      child.on("close", (code) => {
        children.delete(child)
        // Buffer before redaction so a secret split across output chunks is
        // never written partially into reports.
        if (!quiet) writeFileSync(log, redact(output))
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
  async function attempt(command, args, name, options = {}) {
    const child = start(command, args, name, options)
    const timer = setTimeout(
      () => {
        void stop(child)
      },
      cleaning ? 180_000 : Math.max(1, deadline - Date.now()),
    )
    try {
      return await child.finished
    } finally {
      clearTimeout(timer)
    }
  }
  async function execute(command, args, name, options = {}) {
    const result = await attempt(command, args, name, options)
    assert.equal(
      result.code,
      0,
      `${name} failed (exit ${result.code}); see reports/verify-kind-${name}.log`,
    )
    return result.output.trim()
  }
  // kubectl and helm never read the developer's kubeconfig: KUBECONFIG points
  // at a file inside this run's temporary directory, removed with it.
  const kubectl = (args, name, options) =>
    execute("kubectl", args, name, options)
  const capture = async (command, args) => {
    const result = await attempt(command, args, "sample", { quiet: true })
    assert.equal(result.code, 0, `${command} sample failed`)
    return result.output
  }
  async function poll(describe, accept, bound = deadline) {
    let last = "no response yet"
    while (Date.now() < Math.min(bound, deadline) && !stopped) {
      try {
        const outcome = await accept()
        if (outcome === true) return
        last = outcome
      } catch (error) {
        last = error.message
      }
      await delay(500)
    }
    throw new Error(`${describe}: ${last}`)
  }
  function cancel() {
    stopped = true
    for (const child of children) void stop(child)
  }
  for (const signal of ["SIGINT", "SIGTERM"]) process.on(signal, cancel)
  const watchdog = setTimeout(cancel, Math.max(1, deadline - Date.now()))
  async function step(name, action) {
    const started = Date.now()
    record(summary, name, "running")
    persist()
    try {
      const outcome = await action()
      const status = outcome === skipped ? "skipped" : "passed"
      record(
        summary,
        name,
        status,
        Number(((Date.now() - started) / 1000).toFixed(1)),
      )
      persist()
      console.log(`[verify-kind] ${name}: ${status}`)
      return outcome
    } catch (error) {
      record(
        summary,
        name,
        "failed",
        Number(((Date.now() - started) / 1000).toFixed(1)),
      )
      error.message = `${name}: ${error.message}`
      throw error
    }
  }

  try {
    console.log(
      `[verify-kind] Cluster ${cluster}; node image ${nodeImage}; ${budget} second bound`,
    )
    await step("preflight", async () => {
      // kind drives the cluster on its own, but every assertion this script
      // makes - rollouts, port-forward, pod state, the ephemeral container -
      // goes through kubectl, so a missing kubectl is a missing prerequisite.
      summary.tools = {
        kind: await execute(kind, ["version"], "preflight-kind"),
        helm: (
          await execute(helm, ["version", "--short"], "preflight-helm")
        ).trim(),
      }
      const client = await attempt(
        "kubectl",
        ["version", "--client", "-o", "json"],
        "preflight-kubectl",
      )
      assert.equal(
        client.code,
        0,
        "kubectl is not on PATH; install it (brew install kubectl) and rerun",
      )
      summary.tools.kubectl = JSON.parse(client.output).clientVersion.gitVersion
      await execute(
        "docker",
        ["version", "--format", "{{.Server.Version}}"],
        "preflight-docker",
      )
      assert(
        existsSync(join(root, ".tools/kube-schemas")),
        "Kubernetes schemas are missing from .tools/kube-schemas; run make setup once",
      )
    })

    // The real path, not the symlinked one: the CLI refuses a credential
    // directory whose ancestry it cannot open without following a symlink, and
    // on macOS the temporary root reached through /var is exactly that.
    work = mkdtempSync(join(realpathSync(tmpdir()), "clavis-verify-kind-"))
    summary.workDirectory = work
    // kubectl and helm never read the developer's kubeconfig: this one lives in
    // the run's own directory and goes away with it.
    env.KUBECONFIG = join(work, "kubeconfig")
    // The CLI sends no Origin header, so it reaches the forwarded loopback port
    // although the installation's public URL is HTTPS. Its state lives in a home
    // directory inside this run's temporary directory.
    if (!existsSync(join(root, "bin/clavis")))
      await execute("make", ["build-cli"], "build-cli")
    const home = join(work, "home")
    mkdirSync(home, { mode: 0o700 })
    // A Clavis home or profile exported by the developer would point the
    // client at another session store or server, so neither is inherited.
    const clientEnv = { ...env, HOME: home }
    delete clientEnv.CLAVIS_HOME
    delete clientEnv.CLAVIS_PROFILE
    const username = "verify-admin"
    // Generated once, registered for redaction before anything can print them.
    const databasePassword = randomBytes(18).toString("base64url")
    const bootstrapPassword = randomBytes(24).toString("base64url")
    const encryptionKey = randomBytes(32).toString("hex")
    for (const secret of [databasePassword, bootstrapPassword, encryptionKey])
      secrets.add(secret)

    async function imageVersion(image) {
      return await execute(
        "docker",
        [
          "image",
          "inspect",
          image,
          "--format",
          '{{index .Config.Labels "org.opencontainers.image.version"}}',
        ],
        `image-version-${image.split(":").pop()}`,
      )
    }
    async function pods() {
      return podStates(
        JSON.parse(
          await kubectl(["get", "pods", "-l", selector, "-o", "json"], "pods"),
        ),
      )
    }
    // One ready pod and nothing left terminating. A replaced pod lingers for
    // its grace period after a rollout reports complete, and a lingering pod
    // would be read as part of the next rollout.
    async function settled() {
      let current = []
      await poll(
        "The deployment never settled on one ready pod",
        async () => {
          current = await pods()
          return (
            (current.length === 1 &&
              current[0].ready &&
              !current[0].terminating) ||
            current
              .map(
                (pod) =>
                  `${pod.name} ${pod.terminating ? "terminating" : pod.ready ? "ready" : "not ready"}`,
              )
              .join("; ") ||
            "no pods"
          )
        },
        Date.now() + 120_000,
      )
      return current
    }
    // The port-forward follows one pod, so every rollout gets a fresh one.
    async function openForward() {
      await closeForward()
      const child = start(
        "kubectl",
        ["port-forward", `svc/${releaseName}`, "0:80"],
        "port-forward",
      )
      forward = child
      let port
      await poll(
        "port-forward never reported a local port",
        () => {
          if (child.text.includes("Forwarding from")) {
            port = forwardedPort(child.text)
            return true
          }
          return child.text.trim() || "starting"
        },
        Date.now() + 60_000,
      )
      const origin = `http://127.0.0.1:${port}`
      summary.origin = origin
      return origin
    }
    async function closeForward() {
      if (forward) await stop(forward)
      forward = undefined
    }
    async function readiness(origin) {
      await poll(
        "Readiness never reported ready",
        async () => {
          const response = await fetch(`${origin}/readyz`, {
            signal: AbortSignal.timeout(3_000),
          })
          const body = (await response.text()).trim()
          return (
            (response.status === 200 && body === '{"status":"ready"}') ||
            `HTTP ${response.status} ${body}`
          )
        },
        Date.now() + 240_000,
      )
    }
    async function health(origin, expected) {
      const response = await fetch(`${origin}/healthz`, {
        signal: AbortSignal.timeout(3_000),
      })
      assert.equal(response.status, 200, "/healthz is not 200")
      const body = await response.json()
      assert.equal(body.status, "ok")
      assert.equal(
        body.version,
        expected,
        `/healthz reports version ${body.version}, not the running image's ${expected}`,
      )
    }
    async function cli(origin, name, args, input) {
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
          "The CLI exposed a secret",
        )
      return result
    }
    // Sign-in runs `clavis login --no-browser` against the port-forward and
    // does the browser's part there, with the release's public origin, which
    // the sign-in form and Approve check.
    async function signIn(origin, label) {
      const child = start(
        join(root, "bin/clavis"),
        ["login", "--no-browser", "--server", origin],
        `cli-login-${label}`,
        { env: clientEnv },
      )
      const browser = await browserSignIn({
        child,
        baseURL: origin,
        origin: publicURL,
        username,
        password: bootstrapPassword,
      })
      assert(!browser.refused, `The sign-in form answered ${browser.status}`)
      assert.equal(browser.code, 0, `clavis login failed for ${label}`)
      const signedIn = browser.result
      assert.equal(signedIn.ok, true)
      for (const secret of secrets)
        assert(
          !JSON.stringify(signedIn).includes(secret),
          "The CLI exposed a secret",
        )
      assert.equal(signedIn.data.user.username, username)
      assert.equal(
        (await cli(origin, `whoami-${label}`, ["whoami"])).data.user.id,
        signedIn.data.user.id,
      )
      return signedIn.data.user.id
    }
    async function database(sql, name) {
      return await kubectl(
        [
          "exec",
          "deployment/postgres",
          "--",
          "psql",
          "-U",
          "clavis",
          "-d",
          "clavis",
          "-tAc",
          sql,
        ],
        name,
      )
    }

    await step("buildImageA", async () => {
      await execute("make", ["image", `IMAGE=${imageA}`], "image-a")
      summary.versions = { a: await imageVersion(imageA) }
    })

    await step("buildImageB", async () => {
      source = join(work, "source")
      mkdirSync(source)
      // The tracked files as the working tree has them, not as HEAD has them:
      // the second image must differ from the first by the extra migration
      // alone, including work that is not committed yet.
      const tracked = (await execute("git", ["ls-files", "-z"], "copy-list"))
        .split("\0")
        .filter(Boolean)
      assert(tracked.length > 100, "git ls-files listed almost nothing to copy")
      for (const name of tracked) {
        const destination = join(source, name)
        mkdirSync(join(destination, ".."), { recursive: true })
        cpSync(join(root, name), destination)
      }
      summary.copiedFiles = tracked.length
      writeFileSync(
        join(source, "internal/database/migrations/900_verify.sql"),
        "-- +goose Up\n" +
          "-- One empty table, so an upgrade to this image applies a migration the\n" +
          "-- running image has never seen and the ledger moves forward.\n" +
          "CREATE TABLE verify_kind (id integer PRIMARY KEY);\n",
      )
      // sqlc reads the migrations as its schema input. omit_unused_structs
      // means a table no query names generates nothing, so the checked-in tree
      // normally still matches; regenerate rather than assume it.
      const sqlc = `SQLC=${join(root, ".tools/sqlc/bin/sqlc")}`
      const checked = await attempt(
        "make",
        ["check-db-generated", sqlc],
        "copy-check-db-generated",
        { cwd: source },
      )
      summary.copyRegenerated = checked.code !== 0
      if (checked.code !== 0)
        await execute("make", ["generate-db", sqlc], "copy-generate-db", {
          cwd: source,
        })
      await execute(
        "make",
        ["image", `IMAGE=${imageB}`, "VERSION=kind-b"],
        "image-b",
        { cwd: source },
      )
      summary.versions.b = await imageVersion(imageB)
      assert.notEqual(
        summary.versions.a,
        summary.versions.b,
        "Both images stamp the same version; the upgrade would be unobservable",
      )
    })

    await step("createCluster", async () => {
      clusterCreated = true
      await execute(
        kind,
        [
          "create",
          "cluster",
          "--name",
          cluster,
          "--image",
          nodeImage,
          "--wait",
          "120s",
        ],
        "cluster-create",
      )
      summary.nodes = await kubectl(
        [
          "get",
          "nodes",
          "-o",
          "jsonpath={.items[*].status.nodeInfo.kubeletVersion}",
        ],
        "cluster-nodes",
      )
    })

    await step("loadImages", () =>
      execute(
        kind,
        ["load", "docker-image", imageA, imageB, "--name", cluster],
        "load-images",
      ),
    )

    await step("database", async () => {
      await kubectl(["apply", "-f", "-"], "database-apply", {
        input: databaseManifest(databasePassword),
      })
      await kubectl(
        ["rollout", "status", "deployment/postgres", "--timeout=5m"],
        "database-rollout",
      )
    })

    await step("secrets", () =>
      kubectl(["apply", "-f", "-"], "secrets-apply", {
        input: secretManifests({
          databaseURL: `postgres://clavis:${databasePassword}@postgres:5432/clavis?sslmode=disable`,
          encryptionKey,
          bootstrapPassword,
        }),
      }),
    )

    await step("install", () =>
      execute(
        helm,
        [
          "install",
          releaseName,
          chart,
          "--set",
          `publicURL=${publicURL}`,
          "--set",
          "image.repository=clavis",
          "--set",
          "image.tag=kind-a",
          "--set",
          "image.pullPolicy=Never",
          "--set",
          "secrets.database.secretName=clavis",
          "--set",
          "secrets.encryptionKey.secretName=clavis",
          "--set",
          "bootstrap.enabled=true",
          "--set",
          `bootstrap.username=${username}`,
          "--set",
          "bootstrap.password.secretName=clavis-bootstrap",
          "--wait",
          "--timeout",
          "3m",
        ],
        "helm-install",
      ),
    )

    let origin = await step("rollout", async () => {
      await kubectl(
        ["rollout", "status", `deployment/${releaseName}`, "--timeout=3m"],
        "rollout-install",
      )
      const opened = await openForward()
      await readiness(opened)
      await health(opened, summary.versions.a)
      return opened
    })

    const bootstrapped = await step("cliBootstrap", async () => {
      assert.equal(
        (await cli(origin, "doctor", ["doctor"])).data.database,
        "ready",
      )
      return await signIn(origin, "bootstrap")
    })

    const installedPod = (await pods())[0].name
    await step("podSecurityContext", async () => {
      const context = JSON.parse(
        await kubectl(
          [
            "get",
            "pod",
            installedPod,
            "-o",
            "jsonpath={.spec.securityContext}",
          ],
          "pod-security-context",
        ),
      )
      assert.equal(context.fsGroup, 65532, "The pod declares no fsGroup 65532")
      assert.equal(context.runAsUser, 65532)
      assert.equal(context.runAsNonRoot, true)
      summary.podSecurityContext = context
    })

    // The image is distroless, so there is no shell to exec into. An ephemeral
    // container in the server's process namespace reads the mounted files
    // through /proc instead; the pod's own security context applies to it, so
    // it looks at them as the same non-root user the server is.
    await step("secretFiles", async () => {
      const container = "verify-secrets"
      const script =
        `for p in /proc/[0-9]*; do ` +
        `if [ -d "$p/root${secretsDirectory}" ]; then ls -ln "$p/root${secretsDirectory}"; exit 0; fi; ` +
        `done; echo "no process mounts ${secretsDirectory}" >&2; exit 1`
      const created = await attempt(
        "kubectl",
        [
          "debug",
          installedPod,
          "--image",
          databaseImage,
          "--image-pull-policy",
          "IfNotPresent",
          "--target",
          serverContainer,
          "--container",
          container,
          "--quiet",
          "--",
          "sh",
          "-c",
          script,
        ],
        "debug-create",
      )
      if (created.code !== 0) {
        // Readiness already proves the reader accepted the files; record why
        // the direct listing is missing and mark the step skipped rather than
        // passed, so the summary never claims evidence it did not collect.
        summary.secretFiles = {
          captured: false,
          reason: redact(created.output.trim()).slice(0, 500),
        }
        return skipped
      }
      let listing = ""
      await poll(
        "The ephemeral container never produced a listing",
        async () => {
          const logs = await attempt(
            "kubectl",
            ["logs", installedPod, "-c", container],
            "debug-logs",
          )
          if (logs.code === 0 && secretFileListing(logs.output).length) {
            listing = logs.output
            return true
          }
          return logs.output.trim() || "no output yet"
        },
        Date.now() + 120_000,
      )
      const files = secretFileListing(listing)
      summary.secretFiles = { captured: true, files }
      for (const name of ["encryption-key", "bootstrap-password"]) {
        const file = files.find((entry) => entry.name === name)
        assert(file, `${name} is not mounted in ${secretsDirectory}`)
        assert.equal(file.mode, "-r--r-----", `${name} is not mode 0440`)
        assert.equal(file.gid, 65532, `${name} is not owned by group 65532`)
      }
    })

    await step("migrationAbsentBefore", async () => {
      const found = await database(
        "select count(*) from pg_class where relname = 'verify_kind'",
        "table-before",
      )
      assert.equal(found, "0", "verify_kind exists before the upgrade")
    })

    await step("bootstrapDisabled", async () => {
      await execute(
        helm,
        [
          "upgrade",
          releaseName,
          chart,
          "--reuse-values",
          "--set",
          "bootstrap.enabled=false",
          "--wait",
          "--timeout",
          "3m",
        ],
        "helm-upgrade-bootstrap-off",
      )
      await kubectl(
        ["delete", "secret", "clavis-bootstrap"],
        "delete-bootstrap-secret",
      )
      await kubectl(
        ["rollout", "restart", `deployment/${releaseName}`],
        "rollout-restart",
      )
      await kubectl(
        ["rollout", "status", `deployment/${releaseName}`, "--timeout=3m"],
        "rollout-restarted",
      )
      const rendered = await execute(
        helm,
        ["get", "manifest", releaseName],
        "manifest-bootstrap-off",
      )
      assert(
        !rendered.includes("CLAVIS_BOOTSTRAP") &&
          !rendered.includes("clavis-bootstrap"),
        "The release still references the bootstrap Secret",
      )
      origin = await openForward()
      await readiness(origin)
      // The replacement pod holds no session from before the restart.
      assert.equal(await signIn(origin, "afterRestart"), bootstrapped)
    })

    // The restart above can still have a pod inside its termination grace
    // period. The upgrade evidence is only readable from a settled state, so
    // the baseline is taken once exactly one ready pod remains.
    const baseline = (await settled()).map((pod) => pod.name)
    await step("migrationUpgrade", async () => {
      const previous = new Set(baseline)
      const started = Date.now()
      const samples = []
      let sampling = true
      const sampler = (async () => {
        while (sampling) {
          try {
            samples.push({
              at: Date.now() - started,
              pods: podStates(
                JSON.parse(
                  await capture("kubectl", [
                    "get",
                    "pods",
                    "-l",
                    selector,
                    "-o",
                    "json",
                  ]),
                ),
              ),
            })
          } catch {
            // A sampling gap is not a rollout failure; the analysis reports
            // what it saw and the assertions below say what it had to see.
          }
          await delay(250)
        }
      })()
      try {
        await execute(
          helm,
          [
            "upgrade",
            releaseName,
            chart,
            "--reuse-values",
            "--set",
            "image.tag=kind-b",
            "--wait",
            "--timeout",
            "3m",
          ],
          "helm-upgrade-kind-b",
        )
      } finally {
        sampling = false
        await sampler
      }
      // helm returns once the Deployment is complete, but the replaced pod is
      // still inside its termination grace period. Keep sampling until it is
      // gone, so the recorded sequence ends where the evidence does.
      const settleBy = Date.now() + 120_000
      for (;;) {
        const current = await pods()
        samples.push({ at: Date.now() - started, pods: current })
        if (
          current.every((pod) => !previous.has(pod.name)) ||
          Date.now() >= settleBy
        )
          break
        await delay(500)
      }
      const analysis = analyzeRollout(samples, baseline)
      summary.rollout = analysis
      assert(
        analysis.observedBothPods,
        "The old and the new pod were never seen together; maxSurge 1 with maxUnavailable 0 did not hold",
      )
      assert(
        analysis.oldPodGone,
        "The old pod is still present after the upgrade",
      )
      assert.equal(
        analysis.newPods.length,
        1,
        "More than one replacement pod appeared",
      )
    })

    await step("upgradedReadiness", async () => {
      origin = await openForward()
      await readiness(origin)
      await health(origin, summary.versions.b)
      assert.equal(await signIn(origin, "afterUpgrade"), bootstrapped)
    })

    await step("migrationApplied", async () => {
      const found = await database(
        "select count(*) from pg_class where relname = 'verify_kind'",
        "table-after",
      )
      assert.equal(
        found,
        "1",
        "The upgraded image did not apply 900_verify.sql",
      )
      summary.migrations = await database(
        "select max(version_id)::text from goose_db_version",
        "migration-ledger",
      )
    })

    await step("installedValuesValidate", async () => {
      const values = installedValues(
        await execute(
          helm,
          ["get", "values", releaseName, "--all", "-o", "yaml"],
          "helm-get-values",
        ),
      )
      const rendered = await execute(
        helm,
        ["template", releaseName, chart, "-f", "-"],
        "helm-template-installed",
        { input: values },
      )
      for (const secret of secrets)
        assert(
          !rendered.includes(secret),
          "The rendered manifests carry a secret value",
        )
      summary.kubeconform = await execute(
        kubeconform,
        kubeconformArguments(schemaLocations()),
        "kubeconform-installed",
        { input: rendered },
      )
    })

    await closeForward()
    assert(
      !stopped && Date.now() < deadline,
      "The kind verification exceeded its deadline",
    )
    console.log(
      "[verify-kind] Chart install, bootstrap lifecycle and migration upgrade passed",
    )
  } catch (error) {
    summary.message = redact(error.message)
    console.error(`[verify-kind] ${summary.message}`)
  } finally {
    cleaning = true
    clearTimeout(watchdog)
    // Everything this run created goes, whatever failed: the cluster, the two
    // images and the temporary copy. Nothing else is touched.
    const errors = []
    async function cleanup(label, action) {
      try {
        await action()
      } catch (error) {
        errors.push(`${label}: ${redact(error.message)}`)
      }
    }
    await cleanup("port-forward", async () => {
      if (forward) await stop(forward)
    })
    // stop removes the child from the set; a Set iterator tolerates deleting
    // the entry it has already visited.
    for (const child of children)
      await cleanup(`process ${child.pid}`, () => stop(child))
    if (clusterCreated && !options.keepCluster)
      await cleanup("cluster", async () => {
        await execute(
          kind,
          ["delete", "cluster", "--name", cluster],
          "cluster-delete",
        )
        const remaining = await execute(
          kind,
          ["get", "clusters"],
          "cluster-list",
        )
        assert(
          !remaining.split("\n").includes(cluster),
          "The cluster was not deleted",
        )
        summary.clusterDeleted = true
      })
    if (!options.keepImages)
      for (const image of [imageA, imageB])
        await cleanup(`image ${image}`, async () => {
          const removed = await attempt(
            "docker",
            ["image", "rm", "-f", image],
            `image-rm-${image.split(":").pop()}`,
          )
          // A run that stopped before its build never created the tag, which
          // is a clean state, not a cleanup failure.
          if (removed.code !== 0 && !/No such image/i.test(removed.output))
            throw new Error(removed.output.trim())
        })
    await cleanup("temporary copy", () => {
      if (work && !options.keepCluster) {
        rmSync(work, { recursive: true, force: true })
        assert(!existsSync(work), "The temporary directory was not removed")
        summary.workRemoved = true
      }
    })
    summary.cleanup = errors.length ? "failed" : "passed"
    if (errors.length) {
      summary.cleanupErrors = errors
      record(summary, "cleanup", "failed")
      console.error(`[verify-kind] Cleanup failed: ${errors.join("; ")}`)
    }
    if (options.keepCluster)
      console.log(
        `[verify-kind] Cluster ${cluster} kept; export KUBECONFIG=${join(work ?? "", "kubeconfig")}`,
      )
    finalize(summary)
    if (summary.status !== "passed") process.exitCode = 1
    summary.finishedAt = new Date().toISOString()
    summary.seconds = Number(
      (
        (Date.parse(summary.finishedAt) - Date.parse(summary.startedAt)) /
        1000
      ).toFixed(1),
    )
    persist()
    console.log(
      `[verify-kind] ${summary.status}; cleanup ${summary.cleanup}; ${summary.seconds}s; reports/verify-kind.json`,
    )
  }
}

if (import.meta.main) await run()
