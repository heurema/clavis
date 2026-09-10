import { test, expect, state } from "./fixtures.mjs"

for (const [width, colorScheme] of [
  [1280, "light"],
  [1280, "dark"],
  [375, "light"],
  [320, "dark"],
]) {
  test(`setup layout at ${width}px in ${colorScheme}`, async ({
    page,
    wire,
  }, testInfo) => {
    const external = []
    await page.route("**/*", (route) => {
      if (new URL(route.request().url()).origin !== wire.url) {
        external.push(route.request().url())
        return route.abort()
      }
      return route.continue()
    })
    await page.setViewportSize({ width, height: 900 })
    await page.emulateMedia({ colorScheme })
    await page.goto(wire.url)
    await state(page, "ready")
    for (const name of [
      "Environment setup",
      "Service readiness",
      "Continue in your terminal",
      "A foundation, ready to grow",
    ])
      await expect(page.getByRole("heading", { name })).toBeVisible()
    await expect(
      page.getByText("./bin/clavis doctor", { exact: false }),
    ).toBeVisible()
    await expect(
      page.getByRole("switch", { name: "Dark appearance" }),
    ).toBeVisible()
    await expect(
      page.getByRole("button", { name: "Check again" }),
    ).toBeVisible()
    expect(
      await page.evaluate(
        () => document.documentElement.scrollWidth <= innerWidth,
      ),
    ).toBe(true)
    await expect(page.locator("header").first()).toHaveCSS(
      "border-bottom-width",
      "1px",
    )
    expect(await page.locator("svg").count()).toBeGreaterThan(3)
    await page.screenshot({
      path: testInfo.outputPath("setup.png"),
      fullPage: true,
    })
    expect(external).toEqual([])
  })
}
