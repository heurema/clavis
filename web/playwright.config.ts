import { defineConfig } from "@playwright/test"

export default defineConfig({
  testDir: "./tests",
  workers: 1,
  retries: 0,
  timeout: 30_000,
  use: {
    baseURL: process.env.CLAVIS_SMOKE_WEB_URL ?? "http://127.0.0.1:5173",
    browserName: "chromium",
    trace: "retain-on-failure",
  },
})
