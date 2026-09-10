import { test, expect } from "@playwright/test"
import { execFile } from "node:child_process"
import { promisify } from "node:util"
import { join } from "node:path"

const execute = promisify(execFile)
const phase = process.env.CLAVIS_SMOKE_PHASE

test("real database outage, recovery, keyboard controls and appearance", async ({
  page,
  request,
}) => {
  test.skip(
    phase !== "recovery",
    "Run through make smoke for isolated resources",
  )
  test.setTimeout(90_000)
  const project = process.env.CLAVIS_SMOKE_PROJECT!
  const composeFile = process.env.CLAVIS_SMOKE_COMPOSE!
  const apiURL = process.env.CLAVIS_SMOKE_API_URL!
  const reports = process.env.CLAVIS_SMOKE_REPORTS!
  expect(project).toMatch(/^clavis-smoke-\d+-[a-f0-9]+$/)
  const compose = [
    "compose",
    "--env-file",
    "/dev/null",
    "--file",
    composeFile,
    "--project-name",
    project,
  ]
  const failures: string[] = []
  page.on("pageerror", (error) => failures.push(error.message))
  await page.emulateMedia({ colorScheme: "dark" })
  await page.goto("/")
  await expect(page.getByText("Your environment is ready")).toBeVisible()
  await expect(page.locator("html")).toHaveClass("dark")
  expect(await page.evaluate(() => localStorage.length)).toBe(0)
  await page.emulateMedia({ colorScheme: "light" })
  await expect(page.locator("html")).not.toHaveClass("dark")
  await page.reload()
  await expect(page.getByText("Your environment is ready")).toBeVisible()

  await page.keyboard.press("Tab")
  await expect(page.getByRole("link", { name: "Clavis home" })).toBeFocused()
  await page.keyboard.press("Tab")
  const appearance = page.getByRole("switch", { name: "Dark appearance" })
  await expect(appearance).toBeFocused()
  await expect(appearance).toHaveCSS("outline-style", "solid")
  await expect(appearance).toHaveCSS("outline-width", "2px")
  await page.keyboard.press("Space")
  await expect(appearance).toBeChecked()
  await page.reload()
  await expect(appearance).toBeChecked()
  await expect(page.getByText("Your environment is ready")).toBeVisible()
  await page.screenshot({
    path: join(reports, "clavis-dark.png"),
    fullPage: true,
  })
  await appearance.click()
  await page.reload()
  await expect(appearance).not.toBeChecked()
  await expect(page.getByText("Your environment is ready")).toBeVisible()
  await page.screenshot({
    path: join(reports, "clavis-light.png"),
    fullPage: true,
  })
  expect(await page.evaluate(() => Object.keys(localStorage))).toEqual([
    "clavis.appearance",
  ])

  const { stdout: databaseBinding } = await execute(
    "docker",
    [...compose, "port", "db", "5432"],
    { timeout: 15_000 },
  )
  await execute("docker", [...compose, "stop", "db"], { timeout: 15_000 })
  expect((await request.get(`${apiURL}/health/live`)).status()).toBe(200)
  expect((await request.get(`${apiURL}/health/ready`)).status()).toBe(503)
  try {
    await execute(process.env.CLAVIS_SMOKE_CLI!, ["doctor", "--server", apiURL])
    throw new Error("Doctor incorrectly succeeded with a stopped database")
  } catch (error) {
    const result = error as Error & { code: number; stdout: string }
    expect(result.code).toBe(1)
    expect(JSON.parse(result.stdout).data).toEqual({
      api: "reachable",
      database: "unavailable",
    })
  }
  await page.keyboard.press("Tab")
  await page.keyboard.press("Tab")
  await page.keyboard.press("Tab")
  const check = page.getByRole("button", { name: "Check again" })
  await expect(check).toBeFocused()
  await expect(check).toHaveCSS("outline-width", "2px")
  await expect(check).toHaveCSS("outline-style", "solid")
  await page.keyboard.press("Enter")
  await expect(
    page.getByText("Database unavailable", { exact: true }),
  ).toBeVisible()
  await expect(page.getByRole("status")).toContainText("Database unavailable")
  await page.screenshot({
    path: join(reports, "clavis-database-unavailable.png"),
    fullPage: true,
  })
  await execute(
    "docker",
    [...compose, "up", "-d", "--wait", "--wait-timeout", "45"],
    { timeout: 55_000 },
  )
  const { stdout: restartedBinding } = await execute(
    "docker",
    [...compose, "port", "db", "5432"],
    { timeout: 15_000 },
  )
  expect(restartedBinding).toBe(databaseBinding)
  // No reload: a manual check must recover the current mounted page.
  await page.getByRole("button", { name: "Retry" }).press("Enter")
  await expect(page.getByText("Your environment is ready")).toBeVisible()
  expect(failures).toEqual([])
})

test("a stopped API is explained safely in the browser", async ({ page }) => {
  test.skip(
    phase !== "unreachable",
    "Run through make smoke for isolated resources",
  )
  await page.goto("/")
  await expect(
    page.getByText("Server unavailable", { exact: true }),
  ).toBeVisible()
  await expect(page.getByText("Not checked", { exact: true })).toBeVisible()
  await expect(page.getByRole("button", { name: "Retry" })).toBeEnabled()
})
