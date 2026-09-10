// The behavioral suite uses the production binary, not a frontend preview.
// Its database is deliberately unreachable; tests intercept only readiness.
import { execFileSync, spawn } from "node:child_process"
import { mkdirSync, writeFileSync } from "node:fs"
import { fileURLToPath } from "node:url"

const root = fileURLToPath(new URL("../../", import.meta.url))
mkdirSync(new URL("../../reports", import.meta.url), { recursive: true })
writeFileSync(
  new URL("../../reports/browser-fragments.json", import.meta.url),
  execFileSync("go", ["run", "./internal/web/testdata/browser"], {
    cwd: root,
    timeout: 30_000,
  }),
)
const child = spawn(
  fileURLToPath(new URL("../../bin/server", import.meta.url)),
  [],
  {
    stdio: "inherit",
    env: {
      ...process.env,
      CLAVIS_HTTP_ADDR: `127.0.0.1:${process.env.CLAVIS_TEST_PORT}`,
      CLAVIS_DATABASE_URL:
        "postgres://unused@127.0.0.1:1/unused?sslmode=disable",
      CLAVIS_DB_CHECK_TIMEOUT: "100ms",
      CLAVIS_SHUTDOWN_TIMEOUT: "1s",
      CLAVIS_LOG_LEVEL: "error",
    },
  },
)
for (const signal of ["SIGINT", "SIGTERM"])
  process.on(signal, () => child.kill(signal))
child.on("error", () => {
  process.exitCode = 1
})
child.on("exit", (code) => {
  process.exitCode = code ?? 1
})
