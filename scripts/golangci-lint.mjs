import { createHash } from "node:crypto"
import {
  existsSync,
  mkdirSync,
  mkdtempSync,
  renameSync,
  rmSync,
  writeFileSync,
} from "node:fs"
import { execFileSync, spawnSync } from "node:child_process"
import { join } from "node:path"
import { fileURLToPath } from "node:url"

// Latest stable release verified on 2026-09-10. Upgrade version and hashes together.
const version = "2.13.2"
// From the release's golangci-lint-2.13.2-checksums.txt.
const checksums = {
  "darwin-amd64":
    "8a13aaf9cbbb1dee52824e862cf0d0720e5bb97c1f4260d1e51623a09492b57b",
  "darwin-arm64":
    "f4bf83f0b64f055c42b28fc9a38861839f69c096e61c788e72dfaae412011789",
  "linux-amd64":
    "2277d43b98ec0054280f2ac26b53268bae97682444678a59a657dd565da021d6",
  "linux-arm64":
    "a2a4e0065aa41be71f7c5ac90f271b61751331e5d04314e62afe4027855f0893",
}
const target = `${process.platform}-${process.arch === "x64" ? "amd64" : process.arch}`
const name = `golangci-lint-${version}-${target}`
const tools = fileURLToPath(new URL("../.tools/", import.meta.url))
const destination = join(tools, name)
const binary = join(destination, "golangci-lint")

try {
  if (!checksums[target])
    throw new Error(
      `Unsupported platform: ${target}; use macOS/Linux on amd64 or arm64`,
    )
  if (!existsSync(binary)) {
    mkdirSync(tools, { recursive: true })
    const temporary = mkdtempSync(join(tools, ".golangci-lint-"))
    try {
      console.log(`[golangci-lint] Installing v${version} into .tools`)
      const response = await fetch(
        `https://github.com/golangci/golangci-lint/releases/download/v${version}/${name}.tar.gz`,
        { signal: AbortSignal.timeout(60_000) },
      )
      if (!response.ok)
        throw new Error(`Download failed: HTTP ${response.status}`)
      const archive = Buffer.from(await response.arrayBuffer())
      if (
        createHash("sha256").update(archive).digest("hex") !== checksums[target]
      ) {
        throw new Error("Release archive checksum mismatch")
      }
      const path = join(temporary, "release.tar.gz")
      writeFileSync(path, archive)
      execFileSync("tar", ["-xzf", path, "-C", temporary])
      renameSync(join(temporary, name), destination)
    } finally {
      rmSync(temporary, { recursive: true, force: true })
    }
  }
  const args = process.argv.slice(2)
  const result = spawnSync(binary, args[0] === "install" ? ["version"] : args, {
    stdio: "inherit",
  })
  if (result.error) throw result.error
  process.exitCode = result.status ?? 1
} catch (error) {
  console.error(`[golangci-lint] ${error.message}`)
  process.exitCode = 1
}
