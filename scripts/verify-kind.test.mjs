import assert from "node:assert/strict"
import { test } from "node:test"

// Pure helpers only: importing the module must not reach Docker, kind or a
// cluster, so these tests run wherever the other script tests do.
import {
  analyzeRollout,
  databaseImage,
  databaseManifest,
  finalize,
  forwardedPort,
  installedValues,
  nodeImage,
  parseArguments,
  podStates,
  record,
  secretFileListing,
  secretManifests,
} from "./verify-kind.mjs"

test("parseArguments keeps both cleanups on by default", () => {
  assert.deepEqual(parseArguments([]), {
    keepCluster: false,
    keepImages: false,
  })
})

test("parseArguments accepts the two debugging escapes", () => {
  assert.deepEqual(parseArguments(["--keep-cluster", "--keep-images"]), {
    keepCluster: true,
    keepImages: true,
  })
})

test("parseArguments rejects anything else", () => {
  assert.throws(() => parseArguments(["--keep"]), /Unknown argument --keep/)
  assert.throws(() => parseArguments(["clavis"]), /Unknown argument clavis/)
})

test("the node and database images are pinned by digest", () => {
  assert.match(nodeImage, /^kindest\/node:v[\d.]+@sha256:[0-9a-f]{64}$/)
  assert.match(databaseImage, /^postgres:[\d.]+@sha256:[0-9a-f]{64}$/)
})

test("databaseManifest renders a Deployment and a Service on the pinned image", () => {
  const manifest = databaseManifest('pa ss"word')
  assert(manifest.includes(`image: "${databaseImage}"`))
  // A password with a quote and a space survives as one YAML scalar.
  assert(manifest.includes('value: "pa ss\\"word"'))
  assert(manifest.includes("kind: Deployment"))
  assert(manifest.includes("kind: Service"))
  assert(manifest.includes("emptyDir: {}"))
  assert(manifest.includes("port: 5432"))
})

test("secretManifests carries the two references the chart expects", () => {
  const manifest = secretManifests({
    databaseURL: "postgres://clavis:pw@postgres:5432/clavis?sslmode=disable",
    encryptionKey: "a".repeat(64),
    bootstrapPassword: "initial-password",
  })
  assert(manifest.includes("name: clavis\n"))
  assert(manifest.includes("name: clavis-bootstrap\n"))
  assert(
    manifest.includes(
      'database-url: "postgres://clavis:pw@postgres:5432/clavis?sslmode=disable"',
    ),
  )
  // The readers strip one terminal newline, so the mounted files carry one.
  assert(manifest.includes(`encryption-key: "${"a".repeat(64)}\\n"`))
  assert(manifest.includes('password: "initial-password\\n"'))
})

test("forwardedPort reads the port kubectl picked", () => {
  assert.equal(
    forwardedPort("Forwarding from 127.0.0.1:53124 -> 8080\n"),
    53124,
  )
})

test("forwardedPort fails when no local port was printed", () => {
  assert.throws(() => forwardedPort(""), /printed no local port: \(no output\)/)
  assert.throws(
    () => forwardedPort("error: unable to forward"),
    /printed no local port: error: unable to forward/,
  )
})

function pod(name, ready, extra = {}) {
  return {
    metadata: {
      name,
      ...(extra.terminating ? { deletionTimestamp: "now" } : {}),
    },
    spec: { containers: [{ image: extra.image ?? "clavis:kind-a" }] },
    status: {
      conditions: [{ type: "Ready", status: ready ? "True" : "False" }],
    },
  }
}

test("podStates reads the Ready condition, not the phase", () => {
  assert.deepEqual(
    podStates({
      items: [
        pod("clavis-1", true),
        pod("clavis-2", false, { terminating: true }),
      ],
    }),
    [
      {
        name: "clavis-1",
        image: "clavis:kind-a",
        ready: true,
        terminating: false,
      },
      {
        name: "clavis-2",
        image: "clavis:kind-a",
        ready: false,
        terminating: true,
      },
    ],
  )
})

test("podStates tolerates an empty list and a pod without status", () => {
  assert.deepEqual(podStates({}), [])
  assert.deepEqual(podStates({ items: [{ metadata: { name: "x" } }] }), [
    { name: "x", image: "", ready: false, terminating: false },
  ])
})

const older = { name: "clavis-old", ready: true, terminating: false }
const newer = { name: "clavis-new", ready: false, terminating: false }

test("analyzeRollout records the handover it saw", () => {
  const analysis = analyzeRollout(
    [
      { at: 0, pods: [older] },
      { at: 1_000, pods: [older, newer] },
      { at: 4_000, pods: [older, { ...newer, ready: true }] },
      {
        at: 5_000,
        pods: [
          { ...older, ready: false, terminating: true },
          { ...newer, ready: true },
        ],
      },
      { at: 6_000, pods: [{ ...newer, ready: true }] },
    ],
    ["clavis-old"],
  )
  assert.equal(analysis.observedBothPods, true)
  assert.equal(analysis.oldPodGone, true)
  assert.deepEqual(analysis.newPods, ["clavis-new"])
  assert.equal(analysis.newReadyAt, 4_000)
  assert.equal(analysis.oldNotReadyAt, 5_000)
  assert.equal(analysis.oldGoneAt, 6_000)
  assert.equal(analysis.orderedReadinessHandover, true)
  assert.deepEqual(analysis.sequence, [
    "0.0s old=Ready",
    "1.0s new=NotReady old=Ready",
    "4.0s new=Ready old=Ready",
    "5.0s new=Ready old=NotReady/Terminating",
    "6.0s new=Ready",
  ])
})

test("analyzeRollout reports an unobserved overlap rather than inventing one", () => {
  const analysis = analyzeRollout(
    [
      { at: 0, pods: [older] },
      { at: 3_000, pods: [{ ...newer, ready: true }] },
    ],
    ["clavis-old"],
  )
  assert.equal(analysis.observedBothPods, false)
  assert.equal(analysis.oldPodGone, true)
  // The old pod vanished between samples, so the handover is only inferred.
  assert.equal(analysis.newReadyAt, 3_000)
  assert.equal(analysis.oldNotReadyAt, 3_000)
  assert.equal(analysis.orderedReadinessHandover, true)
})

test("analyzeRollout refuses a rollout that never replaced the pod", () => {
  const analysis = analyzeRollout(
    [
      { at: 0, pods: [older] },
      { at: 2_000, pods: [older] },
    ],
    ["clavis-old"],
  )
  assert.equal(analysis.observedBothPods, false)
  assert.equal(analysis.oldPodGone, false)
  assert.deepEqual(analysis.newPods, [])
  assert.equal(analysis.newReadyAt, null)
  assert.equal(analysis.orderedReadinessHandover, false)
})

test("analyzeRollout waits for the replaced pod to go, not just to stop being ready", () => {
  const terminating = [
    { at: 0, pods: [older] },
    {
      at: 4_000,
      pods: [
        { ...older, ready: false, terminating: true },
        { ...newer, ready: true },
      ],
    },
  ]
  // helm reports the rollout complete here, but the old pod is still inside
  // its grace period, so the evidence is not complete either.
  assert.equal(analyzeRollout(terminating, ["clavis-old"]).oldPodGone, false)
  assert.equal(
    analyzeRollout(
      [...terminating, { at: 9_000, pods: [{ ...newer, ready: true }] }],
      ["clavis-old"],
    ).oldPodGone,
    true,
  )
})

test("analyzeRollout treats an empty final sample as no evidence", () => {
  assert.equal(analyzeRollout([], ["clavis-old"]).oldPodGone, false)
  assert.equal(
    analyzeRollout([{ at: 0, pods: [] }], ["clavis-old"]).oldPodGone,
    false,
  )
})

test("secretFileListing reads the mode and the numeric owner of each file", () => {
  const listing = [
    "total 8",
    "-r--r----- 1 0 65532 65 Sep 15 11:02 encryption-key",
    "-r--r----- 1 0 65532 33 Sep 15 11:02 bootstrap-password",
  ].join("\n")
  assert.deepEqual(secretFileListing(listing), [
    { mode: "-r--r-----", uid: 0, gid: 65532, name: "encryption-key" },
    { mode: "-r--r-----", uid: 0, gid: 65532, name: "bootstrap-password" },
  ])
})

test("secretFileListing ignores rows that are not file entries", () => {
  assert.deepEqual(
    secretFileListing("ls: /var/run/secrets/clavis: not found"),
    [],
  )
  assert.deepEqual(secretFileListing(""), [])
})

test("installedValues drops the header helm prints above the values", () => {
  assert.equal(
    installedValues("COMPUTED VALUES:\npublicURL: https://clavis.test\n"),
    "publicURL: https://clavis.test\n",
  )
  assert.equal(
    installedValues("USER-SUPPLIED VALUES:\nreplicaCount: 1\n"),
    "replicaCount: 1\n",
  )
})

test("installedValues leaves plain YAML alone", () => {
  assert.equal(
    installedValues("publicURL: https://clavis.test\n"),
    "publicURL: https://clavis.test\n",
  )
})

test("record keeps a status and a duration under each step name", () => {
  const summary = { checks: {} }
  record(summary, "install", "running")
  record(summary, "install", "passed", 12.5)
  assert.deepEqual(summary.checks, {
    install: { status: "passed", seconds: 12.5 },
  })
})

test("finalize passes only when every step passed and nothing was reported", () => {
  const summary = finalize({
    checks: { install: { status: "passed" }, rollout: { status: "passed" } },
  })
  assert.equal(summary.status, "passed")
  assert.equal(summary.failedChecks, undefined)
})

test("finalize names the steps that stopped the run", () => {
  const summary = finalize({
    checks: {
      install: { status: "passed" },
      rollout: { status: "failed" },
      migrationUpgrade: { status: "running" },
    },
    message: "rollout: Readiness never reported ready",
  })
  assert.equal(summary.status, "failed")
  assert.deepEqual(summary.failedChecks, ["rollout", "migrationUpgrade"])
})

test("finalize keeps a skipped step out of the failures but names it", () => {
  const summary = finalize({
    checks: {
      install: { status: "passed" },
      secretFiles: { status: "skipped", seconds: 4 },
    },
  })
  assert.equal(summary.status, "passed")
  assert.equal(summary.failedChecks, undefined)
  assert.deepEqual(summary.skippedChecks, ["secretFiles"])
})

test("finalize fails a run that reported a message before any step", () => {
  assert.equal(
    finalize({ checks: {}, message: "docker is not running" }).status,
    "failed",
  )
})
