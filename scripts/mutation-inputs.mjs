import {
  cpSync,
  existsSync,
  mkdirSync,
  readFileSync,
  readdirSync,
} from "node:fs"
import { join, relative } from "node:path"
import { copySqlInputs } from "./sqlc.mjs"

export function goSources(root) {
  function walk(directory) {
    if (!existsSync(directory)) return []
    return readdirSync(directory, { withFileTypes: true }).flatMap((entry) => {
      const path = join(directory, entry.name)
      return entry.isDirectory()
        ? walk(path)
        : entry.isFile() && entry.name.endsWith(".go")
          ? [path]
          : []
    })
  }
  return [...walk(join(root, "cmd")), ...walk(join(root, "internal"))]
}

export function isMutationTarget(root, path) {
  const name = relative(root, path)
  return (
    /^internal\/(auth|database|platform|config|cli|server|web)\//.test(name) &&
    !/^internal\/web\/(ui|testdata)\//.test(name) &&
    !/(^|\/)testdata\//.test(name) &&
    !/(_test|_gen|_templ|\.gen)\.go$/.test(name) &&
    !/(^|\/)(generated|sqlc)\//.test(name) &&
    !/^\/\/ Code generated .* DO NOT EDIT\.$/m.test(readFileSync(path, "utf8"))
  )
}

export function copyMutationInputs(root, workspace, sources) {
  // Mutate only Go, but compile against the same embedded assets and schema.
  // Never copy .env, tools, reports or the developer's working directory.
  for (const path of [
    "go.mod",
    "go.sum",
    ".gremlins.yaml",
    "internal/web/assets",
  ])
    cpSync(join(root, path), join(workspace, path), { recursive: true })
  copySqlInputs(root, workspace)
  for (const path of sources) {
    const destination = join(workspace, relative(root, path))
    mkdirSync(join(destination, ".."), { recursive: true })
    cpSync(path, destination)
  }
}
