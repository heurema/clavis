import assert from "node:assert/strict"
import { existsSync, readFileSync } from "node:fs"
import { join, relative } from "node:path"
import { test } from "node:test"
import { fileURLToPath } from "node:url"
import {
  chartPath,
  expectedFailures,
  helmArguments,
  kubeconformArguments,
  lintValueSet,
  missingSchemasMessage,
  schemaLocations,
  schemasPath,
  valueSets,
} from "./chart-lint.mjs"

const root = fileURLToPath(new URL("../", import.meta.url))

// The pinned download layout and the schema locations the check reads from are
// two halves of one decision; a Makefile edit that moves one must move both.
function pinnedSchemaPaths() {
  const makefile = readFileSync(join(root, "Makefile"), "utf8")
  const set = makefile.match(/^KUBE_SCHEMA_SET := (\S+)$/m)?.[1]
  const block = makefile.match(/^KUBE_SCHEMA_FILES :=((?:.*\\\n)*.*)$/m)?.[1]
  assert(set, "Makefile does not pin KUBE_SCHEMA_SET")
  assert(block, "Makefile does not pin KUBE_SCHEMA_FILES")
  const paths = block
    .split(/\s+/)
    .filter((entry) => entry.includes("@"))
    .map((entry) => entry.slice(0, entry.indexOf("@")))
    .map((path) => path.replace("$(KUBE_SCHEMA_SET)", set))
  assert(paths.length > 0, "Makefile pins no schema files")
  return paths
}

test("every ci value set is either rendered or an expected failure", () => {
  const sets = valueSets()
  assert.deepEqual(sets, [...sets].sort(), "value sets are listed in order")
  assert(sets.includes(lintValueSet), `${lintValueSet} is a value set`)
  for (const set of sets) {
    assert(
      existsSync(join(root, chartPath, "ci", set)),
      `${set} exists in the chart`,
    )
    assert.equal(
      set.startsWith("fail-"),
      Boolean(expectedFailures[set]),
      `${set} is expected to fail exactly when it is named fail-*`,
    )
  }
  for (const set of Object.keys(expectedFailures))
    assert(sets.includes(set), `${set} is still a value set`)
  // Every expectation names the value the chart refuses on, not a stack trace
  // or an exit status, so a reworded but still correct refusal is caught.
  for (const [set, message] of Object.entries(expectedFailures))
    assert(message.length >= 6, `${set} expects a specific message`)
})

test("both documented failure conditions are covered", () => {
  assert.deepEqual(Object.values(expectedFailures).sort(), [
    "mutually exclusive",
    "publicURL",
  ])
})

test("the missing schema message names the command that installs them", () => {
  const message = missingSchemasMessage()
  assert.match(message, /make setup/)
  assert(message.includes(schemasPath), "the message names the schema path")
  assert.match(missingSchemasMessage("elsewhere"), /elsewhere/)
})

test("schema locations address the layout the Makefile pins", () => {
  const locations = schemaLocations(root)
  assert.equal(locations.length, 2)
  for (const location of locations)
    assert(
      location.startsWith(join(root, schemasPath)),
      `${location} resolves inside ${schemasPath}`,
    )
  const prefixes = locations.map(
    (location) => relative(join(root, schemasPath), location).split("/")[0],
  )
  for (const path of pinnedSchemaPaths())
    assert(
      prefixes.includes(path.split("/")[0]),
      `no schema location reaches the pinned ${path}`,
    )
  const [kubernetes, crds] = locations
  assert.match(kubernetes, /\{\{\.ResourceKind\}\}\{\{\.KindSuffix\}\}\.json$/)
  assert.match(
    crds,
    /\{\{\.Group\}\}\/\{\{\.ResourceKind\}\}_\{\{\.ResourceAPIVersion\}\}\.json$/,
  )
})

test("kubeconform is called strictly, on stdin, with every location", () => {
  const locations = schemaLocations(root)
  const args = kubeconformArguments(locations)
  assert(args.includes("-strict"), "unknown fields must fail the check")
  assert(args.includes("-summary"))
  assert.equal(args.at(-1), "-", "the rendered manifests arrive on stdin")
  assert.equal(
    args.filter((argument) => argument === "-schema-location").length,
    locations.length,
  )
  for (const location of locations) assert(args.includes(location))
})

test("helm renders each set from the chart directory by an explicit path", () => {
  const args = helmArguments("full.yaml", root)
  assert.deepEqual(args.slice(0, 2), ["template", "clavis"])
  assert.equal(args[2], join(root, chartPath))
  assert.equal(args[3], "--values")
  assert.equal(args[4], join(root, chartPath, "ci", "full.yaml"))
  assert.notEqual(
    helmArguments("default.yaml", root)[4],
    args[4],
    "each set is rendered from its own file",
  )
})
