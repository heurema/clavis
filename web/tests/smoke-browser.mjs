import assert from "node:assert/strict"
import { join } from "node:path"
import { fileURLToPath } from "node:url"

// The Node runner owns Docker/processes; this helper owns one real browser.
// It never mocks a response or starts a frontend/proxy server.
export async function launchSmokeBrowser(origin, reports) {
  process.env.PLAYWRIGHT_BROWSERS_PATH = fileURLToPath(
    new URL("../../.tools/playwright", import.meta.url),
  )
  const { chromium, expect: baseExpect } = await import("@playwright/test")
  const expect = baseExpect.configure({ timeout: 7_000 })
  const browser = await chromium.launch({ timeout: 10_000 })
  let context, closing
  const evidence = {
    origin,
    assets: {},
    states: [],
    readinessResponses: [],
    thirdPartyRequests: [],
    pageErrors: [],
    recoveryNavigations: 0,
    closed: false,
  }
  function close() {
    // Cancellation and finally may both request cleanup.
    closing ??= (async () => {
      try {
        await context?.tracing.stop({
          path: join(reports, "smoke-browser.zip"),
        })
      } finally {
        try {
          await context?.close()
        } finally {
          await browser.close()
          evidence.closed = true
        }
      }
    })()
    return closing
  }
  try {
    context = await browser.newContext({
      viewport: { width: 1280, height: 900 },
      colorScheme: "light",
      serviceWorkers: "block",
    })
    await context.tracing.start({ screenshots: true, snapshots: true })
    await context.route("**/*", (route) => {
      if (new URL(route.request().url()).origin !== origin) {
        evidence.thirdPartyRequests.push(route.request().url())
        return route.abort()
      }
      return route.continue()
    })
    const page = await context.newPage()
    page.setDefaultTimeout(7_000)
    page.setDefaultNavigationTimeout(10_000)
    page.on("pageerror", (error) => evidence.pageErrors.push(error.message))
    page.on("response", (response) => {
      const { pathname } = new URL(response.url())
      if (pathname.startsWith("/assets/"))
        evidence.assets[pathname] = response.status()
      if (pathname === "/ui/readiness")
        evidence.readinessResponses.push({
          status: response.status(),
          marker: response.headers()["x-clavis-fragment"],
        })
    })
    const region = page.getByRole("status")
    const appearance = page.getByRole("switch", { name: "Dark appearance" })
    const retry = page.locator("#readiness-check")
    let recoveryStarted = false
    page.on("framenavigated", (frame) => {
      if (recoveryStarted && frame === page.mainFrame())
        evidence.recoveryNavigations++
    })
    function assertNetwork() {
      assert.deepEqual(
        evidence.thirdPartyRequests,
        [],
        "UI requested a third-party resource",
      )
      assert.deepEqual(evidence.pageErrors, [], "Browser JavaScript failed")
    }
    async function state(expected) {
      await expect(region.locator("> [data-readiness-state]")).toHaveAttribute(
        "data-readiness-state",
        expected,
      )
      await expect(region).toHaveAttribute("aria-live", "polite")
      await expect(region).toHaveAttribute("aria-atomic", "true")
      await expect(retry).toBeEnabled()
      evidence.states.push(expected)
      assertNetwork()
    }
    return {
      evidence,
      close,
      async open() {
        await page.goto(origin)
        await expect(
          page.getByRole("heading", { name: "Environment setup" }),
        ).toBeVisible()
        await state("ready")
        await expect(page.locator("header").first()).toHaveCSS(
          "border-bottom-width",
          "1px",
        )
        await expect(
          page.getByRole("link", { name: "Clavis home" }).locator("svg"),
        ).toBeVisible()
        assert(
          (await page.locator("svg path").count()) > 3,
          "Embedded icons are missing",
        )
        for (const file of [
          "app.css",
          "appearance.js",
          "readiness.js",
          "htmx.min.js",
        ])
          assert.equal(
            evidence.assets[`/assets/${file}`],
            200,
            `Asset ${file} did not load`,
          )
        assert.equal(await page.evaluate(() => htmx.version), "4.0.0")
        const notices = await page.evaluate(async () => {
          const response = await fetch("/assets/notices.txt")
          return { status: response.status, text: await response.text() }
        })
        assert.equal(notices.status, 200)
        for (const name of [
          "Axel Adrian",
          "Oudwin",
          "Cole Bemis",
          "htmx 4.0.0",
          "Tailwind CSS 4.3.3",
        ])
          assert(
            notices.text.includes(name),
            `Missing embedded notice: ${name}`,
          )

        await expect(appearance).not.toBeChecked()
        await page.keyboard.press("Tab")
        await expect(
          page.getByRole("link", { name: "Clavis home" }),
        ).toBeFocused()
        await page.keyboard.press("Tab")
        await expect(appearance).toBeFocused()
        await page.keyboard.press("Space")
        await expect(appearance).toBeChecked()
        await expect(page.locator("html")).toHaveClass("dark")
        // This is the only deliberate reload; recovery must keep this document.
        await page.reload()
        await state("ready")
        await expect(appearance).toBeChecked()
        await expect(page.locator("html")).toHaveClass("dark")
        await page.evaluate(() => {
          window.smokeDocument = true
        })
        recoveryStarted = true
        await page.screenshot({
          path: join(reports, "smoke-ready.png"),
          fullPage: true,
        })
      },
      async retry(expected) {
        const responseCount = evidence.readinessResponses.length
        await retry.press("Enter")
        // A ready-to-ready retry must prove a new response arrived, not merely
        // observe the previous ready DOM before the request starts.
        if (expected !== "server-unavailable")
          await expect
            .poll(() => evidence.readinessResponses.length)
            .toBe(responseCount + 1)
        await state(expected)
        await expect(retry).toBeFocused()
        await expect(appearance).toBeChecked()
        await expect(page.locator("html")).toHaveClass("dark")
        assert.equal(
          await page.evaluate(() => window.smokeDocument),
          true,
          "Document was replaced",
        )
        assert.equal(
          evidence.recoveryNavigations,
          0,
          "Recovery navigated away from the loaded page",
        )
        await expect(region).not.toContainText(
          /postgres:\/\/|clavis-local-only|ECONNREFUSED/,
        )
        if (expected === "server-unavailable") {
          await expect(
            region.getByRole("heading", { name: "Server unavailable" }),
          ).toBeVisible()
          assert.equal(evidence.readinessResponses.length, responseCount)
        } else {
          assert.deepEqual(evidence.readinessResponses.slice(responseCount), [
            {
              status: expected === "ready" ? 200 : 503,
              marker: "readiness",
            },
          ])
        }
        await page.screenshot({
          path: join(
            reports,
            `smoke-${evidence.states.length}-${expected}.png`,
          ),
          fullPage: true,
        })
      },
    }
  } catch (error) {
    await close()
    throw error
  }
}
