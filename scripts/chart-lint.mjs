import { spawnSync } from "node:child_process"
import { existsSync, readdirSync } from "node:fs"
import { join } from "node:path"
import { fileURLToPath } from "node:url"

const projectRoot = fileURLToPath(new URL("../", import.meta.url))

export const chartPath = "deploy/charts/clavis"
export const helmPath = ".tools/helm/bin/helm"
export const kubeconformPath = ".tools/kubeconform/bin/kubeconform"
export const schemasPath = ".tools/kube-schemas"
// helm lint validates values.yaml against values.schema.json, and the chart's
// own defaults deliberately leave the required values empty. Lint the chart
// with the smallest installable set instead, so --strict still sees real values.
export const lintValueSet = "default.yaml"

// Value sets whose name starts with fail- must fail to render, and the message
// must be the one the chart promises. Anything else - a different message, or a
// successful render - is a chart regression, not a passing check.
export const expectedFailures = {
  // publicURL is caught by values.schema.json before rendering starts; the
  // fail rule in _helpers.tpl repeats it for renders that skip the schema.
  "fail-no-public-url.yaml": "publicURL",
  "fail-both-routes.yaml": "mutually exclusive",
  // Only the fail rule in _helpers.tpl can compare the two session durations.
  "fail-session-idle-above-max.yaml": "server.sessionIdleTimeout must be",
  // The strict schema refuses the removed fixed session lifetime by name.
  "fail-session-ttl.yaml": "sessionTTL",
}

export function missingSchemasMessage(path = schemasPath) {
  return `Kubernetes schemas are missing from ${path}; run make setup (or make install-kube-schemas) once, then chart-lint needs no network`
}

// The layout install-kube-schemas writes is the one kubeconform's own location
// templates produce, so the sets are addressed without rearranging files: the
// Kubernetes kinds by kind and group suffix, the Gateway API HTTPRoute by
// group and API version.
export function schemaLocations(root = projectRoot, path = schemasPath) {
  const schemas = join(root, path)
  return [
    join(
      schemas,
      "v1.34.0-standalone-strict/{{.ResourceKind}}{{.KindSuffix}}.json",
    ),
    join(
      schemas,
      "crds/{{.Group}}/{{.ResourceKind}}_{{.ResourceAPIVersion}}.json",
    ),
  ]
}

export function valueSets(root = projectRoot, chart = chartPath) {
  return readdirSync(join(root, chart, "ci"))
    .filter((name) => name.endsWith(".yaml"))
    .sort()
}

export function helmArguments(set, root = projectRoot, chart = chartPath) {
  return [
    "template",
    "clavis",
    join(root, chart),
    "--values",
    join(root, chart, "ci", set),
  ]
}

export function kubeconformArguments(locations) {
  return [
    "-strict",
    "-summary",
    ...locations.flatMap((location) => ["-schema-location", location]),
    "-",
  ]
}

function run(executable, args, input) {
  const result = spawnSync(executable, args, {
    cwd: projectRoot,
    encoding: "utf8",
    input,
    timeout: 120_000,
  })
  if (result.error) throw result.error
  return result
}

function lintChart() {
  const result = run(join(projectRoot, helmPath), [
    "lint",
    "--strict",
    join(projectRoot, chartPath),
    "--values",
    join(projectRoot, chartPath, "ci", lintValueSet),
  ])
  if (result.status !== 0)
    throw new Error(
      `helm lint --strict failed:\n${result.stdout}${result.stderr}`,
    )
  console.log(`[chart-lint] helm lint --strict ${chartPath}: passed`)
}

function checkFailureSet(set, expected) {
  const result = run(join(projectRoot, helmPath), helmArguments(set))
  if (result.status === 0)
    throw new Error(`${set} rendered successfully; it must fail to render`)
  if (!result.stderr.includes(expected))
    throw new Error(
      `${set} failed without the expected message ${JSON.stringify(expected)}:\n${result.stderr}`,
    )
  console.log(`[chart-lint] ${set}: rendering refused, naming "${expected}"`)
}

function checkRenderedSet(set, locations) {
  const rendered = run(join(projectRoot, helmPath), helmArguments(set))
  if (rendered.status !== 0)
    throw new Error(`${set} failed to render:\n${rendered.stderr}`)
  const validated = run(
    join(projectRoot, kubeconformPath),
    kubeconformArguments(locations),
    rendered.stdout,
  )
  if (validated.status !== 0)
    throw new Error(
      `${set} does not validate against the pinned schemas:\n${validated.stdout}${validated.stderr}`,
    )
  console.log(`[chart-lint] ${set}: ${validated.stdout.trim()}`)
}

export function chartLint() {
  if (!existsSync(join(projectRoot, schemasPath)))
    throw new Error(missingSchemasMessage())
  lintChart()
  const locations = schemaLocations()
  for (const set of valueSets()) {
    const expected = expectedFailures[set]
    if (expected) checkFailureSet(set, expected)
    else checkRenderedSet(set, locations)
  }
}

if (import.meta.main) {
  try {
    chartLint()
    console.log("[chart-lint] All value sets passed.")
  } catch (error) {
    console.error(`[chart-lint] ${error.message}`)
    process.exitCode = 1
  }
}
