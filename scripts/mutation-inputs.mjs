import {
  cpSync,
  existsSync,
  mkdirSync,
  readFileSync,
  readdirSync,
} from "node:fs"
import { spawnSync } from "node:child_process"
import { join, relative, resolve } from "node:path"

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

// changedSources lists the Go files that differ from a git ref: committed and
// working-tree differences plus untracked files, as absolute paths. The ref is
// verified first so a typo cannot silently widen or narrow the scope.
export function changedSources(root, ref) {
  const git = (args) => {
    const result = spawnSync("git", args, { cwd: root, encoding: "utf8" })
    if (result.status !== 0)
      throw new Error(
        `git ${args[0]} failed: ${(result.stderr || "").trim() || result.status}`,
      )
    return result.stdout.split("\n").filter(Boolean)
  }
  const verify = spawnSync(
    "git",
    ["rev-parse", "--verify", "--quiet", `${ref}^{commit}`],
    {
      cwd: root,
      encoding: "utf8",
    },
  )
  if (verify.status !== 0)
    throw new Error(
      `CLAVIS_MUTATION_DIFF names an unknown git ref "${ref}"; fetch it, set another ref, or set CLAVIS_MUTATION_DIFF= for the full scope`,
    )
  const names = new Set([
    ...git(["diff", "--name-only", ref, "--", "*.go"]),
    ...git(["ls-files", "--others", "--exclude-standard", "--", "*.go"]),
  ])
  return [...names].map((name) => resolve(root, name)).sort()
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
    "sqlc.yaml",
    "internal/database/migrations",
    "internal/database/queries",
  ])
    cpSync(join(root, path), join(workspace, path), { recursive: true })
  for (const path of sources) {
    const destination = join(workspace, relative(root, path))
    mkdirSync(join(destination, ".."), { recursive: true })
    cpSync(path, destination)
  }
}
