import { defineConfig } from "@playwright/test"
import { createServer } from "node:net"
import { fileURLToPath } from "node:url"

process.env.PLAYWRIGHT_BROWSERS_PATH = fileURLToPath(
  new URL("../.tools/playwright", import.meta.url),
)
// Workers re-import this config. Inherit the runner's port instead of allocating
// a different (unserved) origin in every worker.
if (!process.env.CLAVIS_TEST_PORT) {
  const socket = createServer()
  await new Promise((resolve, reject) => {
    socket.once("error", reject)
    socket.listen(0, "127.0.0.1", resolve)
  })
  process.env.CLAVIS_TEST_PORT = String(socket.address().port)
  await new Promise((resolve) => socket.close(resolve))
}
const port = process.env.CLAVIS_TEST_PORT
const baseURL = `http://127.0.0.1:${port}`

export default defineConfig({
  testDir: "./tests",
  testMatch: "**/*.spec.mjs",
  outputDir: "../reports/browser-results",
  fullyParallel: true,
  workers: 4,
  retries: 0,
  timeout: 20_000,
  reporter: [
    ["list"],
    ["json", { outputFile: "../reports/browser-summary.json" }],
  ],
  use: {
    baseURL,
    browserName: "chromium",
    viewport: { width: 1280, height: 900 },
    colorScheme: "light",
    trace: "retain-on-failure",
  },
  webServer: {
    command: "node tests/server.mjs",
    url: `${baseURL}/health/live`,
    env: { CLAVIS_TEST_PORT: String(port) },
    reuseExistingServer: false,
    timeout: 15_000,
  },
})
