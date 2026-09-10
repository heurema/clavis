import { test, expect, state } from "./fixtures.mjs"

test("stored appearance is applied before the stylesheet finishes loading", async ({
  page,
  wire,
}) => {
  await page.emulateMedia({ colorScheme: "light" })
  await page.addInitScript(() =>
    localStorage.setItem("clavis.appearance", "dark"),
  )
  let stylesheet
  await page.route("**/assets/app.css", (route) => {
    stylesheet = route
  })
  await page.goto(wire.url, { waitUntil: "commit" })
  try {
    await expect.poll(() => Boolean(stylesheet)).toBe(true)
    await expect(page.locator("html")).toHaveClass("dark")
    expect(
      await page.evaluate(
        () => document.querySelector('link[rel="stylesheet"]').sheet,
      ),
    ).toBeNull()
  } finally {
    await stylesheet?.continue()
  }
  await state(page, "ready")
  await expect(
    page.getByRole("switch", { name: "Dark appearance" }),
  ).toBeChecked()
})

test("system appearance, keyboard choice, persistence and reload", async ({
  page,
  wire,
}) => {
  await page.emulateMedia({ colorScheme: "dark" })
  await page.goto(wire.url)
  const appearance = page.getByRole("switch", { name: "Dark appearance" })
  await expect(page.locator("html")).toHaveClass("dark")
  await expect(appearance).toBeChecked()
  expect(await page.evaluate(() => localStorage.length)).toBe(0)
  await page.emulateMedia({ colorScheme: "light" })
  await expect(page.locator("html")).not.toHaveClass("dark")
  await page.keyboard.press("Tab")
  await expect(page.getByRole("link", { name: "Clavis home" })).toBeFocused()
  await page.keyboard.press("Tab")
  await expect(appearance).toBeFocused()
  await expect(appearance.locator("..").locator("div")).not.toHaveCSS(
    "box-shadow",
    "none",
  )
  await page.keyboard.press("Space")
  await expect(appearance).toBeChecked()
  await page.reload()
  await expect(appearance).toBeChecked()
  await expect(page.locator("html")).toHaveClass("dark")
  await appearance.press("Space")
  await page.emulateMedia({ colorScheme: "dark" })
  await expect(page.locator("html")).not.toHaveClass("dark")
  await page.reload()
  await expect(appearance).not.toBeChecked()
  await state(page, "ready")
  expect(await page.evaluate(() => ({ ...localStorage }))).toEqual({
    "clavis.appearance": "light",
  })
})

test("blocked storage keeps an in-memory choice without disrupting readiness", async ({
  page,
  wire,
}) => {
  await page.addInitScript(() => {
    Object.defineProperty(window, "localStorage", {
      get() {
        throw new DOMException("Blocked", "SecurityError")
      },
    })
  })
  await page.goto(wire.url)
  await state(page, "ready")
  const appearance = page.getByRole("switch", { name: "Dark appearance" })
  await appearance.press("Space")
  await expect(page.locator("html")).toHaveClass("dark")
  await page.emulateMedia({ colorScheme: "dark" })
  await page.emulateMedia({ colorScheme: "light" })
  await expect(appearance).toBeChecked()
  await page.getByRole("button", { name: "Check again" }).click()
  await state(page, "ready")
  await expect(page.locator("html")).toHaveClass("dark")
  await page.reload()
  await expect(appearance).not.toBeChecked()
})

test("inserted templUI switch and repeated initialization attach no duplicate handlers", async ({
  page,
  wire,
  fragments,
}) => {
  await page.goto(wire.url)
  await state(page, "ready")
  await page.evaluate((html) => {
    const fixture = document.createElement("div")
    fixture.id = "component-fixture"
    fixture.innerHTML = html
    document.body.append(fixture)
    window.appearanceWrites = 0
    const original = Storage.prototype.setItem
    Storage.prototype.setItem = function (...args) {
      window.appearanceWrites++
      return original.apply(this, args)
    }
    for (let i = 0; i < 3; i++) window.htmx.process(fixture)
  }, fragments.switch)
  for (let i = 0; i < 3; i++) {
    await page.addScriptTag({ url: `${wire.url}/assets/appearance.js` })
    await page.addScriptTag({ url: `${wire.url}/assets/readiness.js` })
  }
  const inserted = page.getByRole("switch", { name: "Inserted appearance" })
  await inserted.press("Space")
  await expect(inserted).toBeChecked()
  await expect(
    page.getByRole("switch", { name: "Dark appearance" }),
  ).toBeChecked()
  expect(await page.evaluate(() => window.appearanceWrites)).toBe(1)
  for (let i = 0; i < 3; i++) {
    await page.getByRole("button", { name: "Check again" }).press("Enter")
    await state(page, "ready")
    await expect(
      page.getByRole("button", { name: "Check again" }),
    ).toBeFocused()
  }
  expect(wire.calls).toHaveLength(4)
  expect(await page.evaluate(() => window.appearanceWrites)).toBe(1)
})
