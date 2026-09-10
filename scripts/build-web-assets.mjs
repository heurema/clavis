import { execFileSync } from "node:child_process"
import {
  copyFileSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  renameSync,
  rmSync,
  statSync,
  writeFileSync,
} from "node:fs"
import { join } from "node:path"
import { fileURLToPath } from "node:url"

const projectRoot = fileURLToPath(new URL("../", import.meta.url))

function readRequired(path) {
  const content = readFileSync(path, "utf8")
  if (!content.trim()) throw new Error(`Required asset input is empty: ${path}`)
  return content
}

function inlineNotices(path) {
  const source = readRequired(path)
  const block = source.match(
    /^\/\/ BEGIN THIRD-PARTY NOTICES\n([\s\S]+?)^\/\/ END THIRD-PARTY NOTICES$/m,
  )?.[1]
  if (!block) throw new Error(`Missing inline permission notices: ${path}`)
  return block.replace(/^\/\/ ?/gm, "").trim()
}

// A root argument lets tests exercise real builds in isolated project copies.
// The command itself always builds this checkout; no runtime asset override exists.
export function buildWebAssets(root = projectRoot) {
  const web = join(root, "internal/web")
  const destination = join(web, "assets")
  mkdirSync(web, { recursive: true })
  // A failed preparation must not leave an old directory available for embedding.
  rmSync(destination, { recursive: true, force: true })
  const staging = mkdtempSync(join(web, ".assets-"))
  try {
    const manifest = JSON.parse(readRequired(join(root, "web/package.json")))
    for (const name of ["htmx.org", "tailwindcss", "@tailwindcss/cli"]) {
      const expected = manifest.devDependencies[name]
      const installed = JSON.parse(
        readRequired(join(root, "web/node_modules", name, "package.json")),
      )
      if (!/^\d+\.\d+\.\d+$/.test(expected) || installed.version !== expected)
        throw new Error(
          `Expected ${name} ${expected}, found ${installed.version}`,
        )
    }
    if (
      manifest.devDependencies.tailwindcss !==
      manifest.devDependencies["@tailwindcss/cli"]
    )
      throw new Error("Tailwind CSS and CLI versions must match")

    const stylesheet = join(root, "web/styles/app.css")
    readRequired(stylesheet)
    const htmx = join(root, "web/node_modules/htmx.org/dist/htmx.min.js")
    readRequired(htmx)
    const notices = [
      [
        "templUI / tailwind-merge-go",
        inlineNotices(join(web, "ui/utils/templui.go")),
      ],
      ["Lucide", inlineNotices(join(web, "ui/icon/icon.templ"))],
      [
        `htmx ${manifest.devDependencies["htmx.org"]}`,
        readRequired(join(root, "web/node_modules/htmx.org/LICENSE")).trim(),
      ],
      [
        `Tailwind CSS ${manifest.devDependencies.tailwindcss}`,
        readRequired(join(root, "web/node_modules/tailwindcss/LICENSE")).trim(),
      ],
    ]
    const output = join(staging, "app.css")
    execFileSync(
      process.execPath,
      [
        join(root, "web/node_modules/@tailwindcss/cli/dist/index.mjs"),
        "--input",
        stylesheet,
        "--output",
        output,
        "--minify",
      ],
      { cwd: root, stdio: "pipe", timeout: 60_000 },
    )
    if (!statSync(output).isFile() || statSync(output).size === 0)
      throw new Error("Tailwind did not produce a stylesheet")
    copyFileSync(htmx, join(staging, "htmx.min.js"))
    writeFileSync(
      join(staging, "notices.txt"),
      notices.map(([name, text]) => `${name}\n\n${text}`).join("\n\n---\n\n") +
        "\n",
    )
    renameSync(staging, destination)
  } finally {
    rmSync(staging, { recursive: true, force: true })
  }
}

if (import.meta.main) {
  try {
    buildWebAssets()
    console.log("[build-web-assets] Prepared embedded public assets")
  } catch (error) {
    console.error(`[build-web-assets] ${error.message}`)
    process.exitCode = 1
  }
}
