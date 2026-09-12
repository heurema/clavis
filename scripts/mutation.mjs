import { createHash, randomUUID } from "node:crypto"
import { spawn } from "node:child_process"
import {
  existsSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  renameSync,
  rmSync,
  writeFileSync,
} from "node:fs"
import { availableParallelism, tmpdir } from "node:os"
import { join, relative } from "node:path"
import { fileURLToPath } from "node:url"
import {
  changedSources,
  copyMutationInputs,
  goSources,
  isMutationTarget,
} from "./mutation-inputs.mjs"

const root = fileURLToPath(new URL("../", import.meta.url))
const reports = join(root, "reports")
mkdirSync(reports, { recursive: true })
const summaryPath = join(reports, "mutation-summary.json")
const reportPath = join(reports, "mutations.json")
const logPath = join(reports, "mutation.log")
const run = {
  runId: randomUUID(),
  startedAt: new Date().toISOString(),
  status: "running",
  tool: "Gremlins 0.6.0",
  sourceUnchanged: true,
}
const summary = () => {
  const temp = `${summaryPath}.tmp`
  writeFileSync(temp, JSON.stringify(run, null, 2) + "\n")
  renameSync(temp, summaryPath)
}
// A failed run must never leave an older report looking like its result.
rmSync(reportPath, { force: true })
writeFileSync(logPath, "")
summary()
// Each test run is pinned to one core, so the machine can carry almost as
// many workers as it has cores; two are left for the tool and the editor.
const workers = Number(
  process.env.CLAVIS_MUTATION_WORKERS ??
    Math.max(1, availableParallelism() - 2),
)
// The default scope is the files that differ from a base ref; an empty
// variable selects the full scope for archive and release verification.
const diffRef = process.env.CLAVIS_MUTATION_DIFF ?? "main"
const timeout =
  Number(process.env.CLAVIS_MUTATION_TIMEOUT_SECONDS ?? 600) * 1000
let temporaryRoot, workspace, active, timeoutTimer, forcedStop
const deadline = Date.now() + timeout
const appendLog = (chunk) => writeFileSync(logPath, chunk, { flag: "a" })

const source = goSources(root)
const hashes = new Map(
  source.map((path) => [
    path,
    createHash("sha256").update(readFileSync(path)).digest("hex"),
  ]),
)
const eligible = (path) => isMutationTarget(root, path)
const escapeRegex = (path) => path.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")

function stop(signal) {
  forcedStop = signal
  if (active) {
    try {
      process.kill(-active.pid, "SIGKILL")
    } catch (error) {
      if (error.code !== "ESRCH") throw error
    }
  }
}
for (const signal of ["SIGINT", "SIGTERM"])
  process.on(signal, () => stop(signal))

function execute(command, args, options = {}) {
  return new Promise((resolve, reject) => {
    if (Date.now() >= deadline || forcedStop) {
      reject(new Error(forcedStop || "OVERALL_TIMEOUT"))
      return
    }
    active = spawn(command, args, {
      cwd: workspace ?? root,
      detached: true,
      env: { ...process.env, TMPDIR: temporaryRoot ?? tmpdir() },
      ...options,
    })
    let output = ""
    const record = (chunk) => {
      const text = chunk.toString()
      output += text
      appendLog(text)
    }
    active.stdout.on("data", record)
    active.stderr.on("data", record)
    active.on("error", (error) => {
      active = undefined
      reject(error)
    })
    active.on("exit", (code, signal) => {
      active = undefined
      if (forcedStop || Date.now() >= deadline)
        reject(new Error(forcedStop || "OVERALL_TIMEOUT"))
      else if (code !== 0)
        reject(
          new Error(
            `${command} failed (${code ?? signal}); see reports/mutation.log`,
          ),
        )
      else resolve(output)
    })
  })
}

try {
  if (
    !Number.isInteger(workers) ||
    workers <= 0 ||
    !Number.isFinite(timeout) ||
    timeout <= 0
  )
    throw new Error(
      "Mutation workers must be a positive integer and timeout must be positive seconds",
    )
  timeoutTimer = setTimeout(() => stop("OVERALL_TIMEOUT"), timeout)
  // Selection happens in the repository root, which has the git history the
  // isolated copy lacks, and before anything expensive so an unknown ref
  // fails at once; the copy is then told to skip every other file.
  let targets = source.filter(eligible)
  if (diffRef === "") {
    run.scope = { mode: "full" }
  } else {
    const changed = new Set(changedSources(root, diffRef))
    targets = targets.filter((path) => changed.has(path))
    run.scope = { mode: "diff", ref: diffRef }
  }
  run.targets = targets.map((path) => relative(root, path))
  temporaryRoot = mkdtempSync(join(tmpdir(), "clavis-mutation-"))
  workspace = join(temporaryRoot, "source")
  mkdirSync(workspace)
  copyMutationInputs(root, workspace, source)
  console.log("[mutation] Running baseline tests in an isolated copy")
  await execute("go", ["test", "./..."])
  if (targets.length === 0) {
    run.status = "empty"
    run.message =
      diffRef === ""
        ? "No eligible handwritten Go files; no mutation effectiveness claimed."
        : `No eligible handwritten Go files differ from ${diffRef}; no mutation effectiveness claimed.`
    console.log(`[mutation] ${run.message}`)
  } else {
    const binary = join(root, ".tools", "bin", "gremlins")
    mkdirSync(join(root, ".tools", "bin"), { recursive: true })
    await execute(
      "go",
      ["install", "github.com/go-gremlins/gremlins/cmd/gremlins@v0.6.0"],
      { env: { ...process.env, GOBIN: join(root, ".tools", "bin") } },
    )
    // Gremlins 0.6.0 constructs a malformed single "-cpu 1" argument for
    // nonzero test-cpu. Keep it zero and bound Go via its own environment.
    const mutationEnv = {
      ...process.env,
      TMPDIR: temporaryRoot,
      GOMAXPROCS: "1",
    }
    const flags = [
      "--workers",
      String(workers),
      "--test-cpu",
      "0",
      "--timeout-coefficient",
      "3",
      "--threshold-efficacy",
      "0",
      "--threshold-mcover",
      "0",
    ]
    // A failing test command can be mislabeled KILLED by the tool. Require
    // a known surviving boundary mutation as well as a detected negation.
    const probe = join(temporaryRoot, "probe")
    mkdirSync(join(probe, "internal", "config"), { recursive: true })
    writeFileSync(
      join(probe, "go.mod"),
      "module clavis-mutation-probe\n\ngo 1.27.1\n",
    )
    writeFileSync(
      join(probe, "internal", "config", "probe.go"),
      "package config\nfunc Positive(n int) bool { return n > 0 }\n",
    )
    writeFileSync(
      join(probe, "internal", "config", "probe_test.go"),
      'package config\nimport "testing"\nfunc TestPositive(t *testing.T) { if !Positive(1) || Positive(-1) { t.Fatal("sign changed") } }\n',
    )
    console.log(
      "[mutation] Checking the tool can distinguish a detected mutation from a survivor",
    )
    await execute(
      binary,
      [
        "unleash",
        "--config",
        join(workspace, ".gremlins.yaml"),
        ...flags,
        "--output",
        join(probe, "probe.json"),
      ],
      { cwd: probe, env: mutationEnv },
    )
    const probeReport = JSON.parse(
      readFileSync(join(probe, "probe.json"), "utf8"),
    )
    if (probeReport.mutants_killed < 1 || probeReport.mutants_lived < 1)
      throw new Error(
        "Gremlins compatibility probe failed to distinguish detections and survivors",
      )
    run.compatibilityProbe = "passed"
    const args = [
      "unleash",
      "--config",
      join(workspace, ".gremlins.yaml"),
      ...flags,
      "--output",
      join(workspace, "mutations.json"),
    ]
    const selected = new Set(targets)
    for (const path of source.filter((path) => !selected.has(path)))
      args.push("--exclude-files", `(^|/)${escapeRegex(relative(root, path))}$`)
    console.log(
      `[mutation] Gremlins 0.6.0; ${workers} workers; ${timeout / 1000}s total bound; ` +
        (diffRef === ""
          ? "full scope"
          : `${targets.length} file(s) changed against ${diffRef}`),
    )
    const output = await execute(binary, args, { env: mutationEnv })
    const nativePath = join(workspace, "mutations.json")
    if (!existsSync(nativePath)) {
      if (!/No mutations found/i.test(output))
        throw new Error("Gremlins did not produce its report")
      run.status = "empty"
      run.message =
        diffRef === ""
          ? "No eligible mutations; no mutation effectiveness claimed."
          : `No eligible mutations in the files that differ from ${diffRef}; no mutation effectiveness claimed.`
    } else {
      const report = JSON.parse(readFileSync(nativePath, "utf8"))
      if (!Array.isArray(report.files))
        throw new Error("Invalid Gremlins report")
      const counts = {}
      for (const file of report.files) {
        for (const mutation of file.mutations)
          counts[mutation.status] = (counts[mutation.status] ?? 0) + 1
      }
      if (counts.RUNNABLE)
        throw new Error(
          "Incomplete mutation analysis contains unexecuted runnable mutations",
        )
      run.status = Object.keys(counts).some((status) => status !== "SKIPPED")
        ? "complete"
        : "empty"
      run.outcomes = counts
      const sanitized =
        JSON.stringify(report, null, 2).replaceAll(workspace + "/", "") + "\n"
      writeFileSync(`${reportPath}.tmp`, sanitized)
      renameSync(`${reportPath}.tmp`, reportPath)
      console.log(`[mutation] ${JSON.stringify(counts)}`)
    }
  }
} catch (error) {
  run.status =
    forcedStop === "OVERALL_TIMEOUT" || error.message === "OVERALL_TIMEOUT"
      ? "timeout"
      : "failed"
  run.message = error.message
  rmSync(reportPath, { force: true })
  console.error(`[mutation] ${run.message}`)
  process.exitCode = 1
} finally {
  clearTimeout(timeoutTimer)
  if (temporaryRoot) rmSync(temporaryRoot, { recursive: true, force: true })
  for (const [path, hash] of hashes) {
    if (
      !existsSync(path) ||
      createHash("sha256").update(readFileSync(path)).digest("hex") !== hash
    ) {
      run.sourceUnchanged = false
      run.status = "failed"
      run.message =
        "Source changed during the mutation run; no source was restored or overwritten."
      process.exitCode = 1
    }
  }
  run.finishedAt = new Date().toISOString()
  summary()
  console.log(`[mutation] ${run.status}; reports/mutation-summary.json`)
}
