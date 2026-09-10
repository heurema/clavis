import { test, expect, signIn } from "./auth-fixtures.mjs"

test("ordinary keyboard form login/logout and appearance continuity", async ({
  page,
  context,
  authWire,
}) => {
  await page.goto(`${authWire.url}/admin`)
  await expect(page).toHaveURL(`${authWire.url}/login`)
  await page.getByLabel("Dark appearance").focus()
  await page.keyboard.press("Space")
  await page.getByLabel("Username", { exact: true }).focus()
  await page.keyboard.type("fixture.admin")
  await page.keyboard.press("Tab")
  await expect(page.getByLabel("Password", { exact: true })).toBeFocused()
  await page.keyboard.type("SENTINEL_PASSWORD_123")
  await page.keyboard.press("Tab")
  await expect(page.getByRole("button", { name: "Sign in" })).toBeFocused()
  await page.keyboard.press("Enter")
  await expect(page).toHaveURL(`${authWire.url}/admin`)
  await expect(page.getByRole("heading", { level: 1 })).toHaveText(
    "Administration",
  )
  await expect(page.getByText("fixture.admin", { exact: true })).toBeVisible()
  await expect(page.locator("html")).toHaveClass("dark")
  await expect(page.locator("form")).toHaveCount(1)
  await expect(page.locator("body")).not.toContainText("SENTINEL_PASSWORD")
  expect(authWire.calls.find((call) => call.method === "POST")).toEqual({
    method: "POST",
    path: "/login",
    fields: ["password", "username"],
  })
  const cookies = await context.cookies()
  expect(cookies).toHaveLength(1)
  expect(cookies[0]).toMatchObject({
    name: authWire.cookieName,
    httpOnly: true,
    sameSite: "Lax",
    path: "/",
    secure: false,
  })
  expect(await page.content()).not.toContain(cookies[0].value)
  await page.getByRole("button", { name: "Sign out" }).click()
  await expect(page).toHaveURL(`${authWire.url}/login`)
  expect(await context.cookies()).toHaveLength(0)
  await expect(page.locator("html")).toHaveClass("dark")
  await page.reload()
  await expect(page.getByLabel("Dark appearance")).toBeChecked()
})

for (const [code, status] of [
  ["INVALID_ARGUMENT", 400],
  ["INVALID_CREDENTIALS", 401],
  ["FORBIDDEN", 403],
  ["RATE_LIMITED", 429],
  ["SERVICE_UNAVAILABLE", 503],
  ["DEPENDENCY_UNAVAILABLE", 503],
  ["INITIALIZING", 503],
  ["SETUP_REQUIRED", 503],
  ["BOOTSTRAP_FAILED", 503],
  ["SCHEMA_ERROR", 503],
]) {
  test(`login ${code} is a complete safe, focused document`, async ({
    page,
    context,
    authWire,
  }) => {
    authWire.configure({ login: code })
    const result = page.waitForResponse(
      (response) =>
        response.url() === `${authWire.url}/login` &&
        response.request().method() === "POST",
    )
    await signIn(page, authWire)
    const response = await result
    expect(response.status()).toBe(status)
    expect(response.headers()["cache-control"]).toBe("no-store")
    expect(response.headers()["content-security-policy"]).toBe(
      "frame-ancestors 'none'",
    )
    if (status === 429) {
      expect(response.headers()["retry-after"]).toBe("30")
      await expect(page.getByRole("alert")).toContainText("30 seconds")
    }
    await expect(page.getByRole("heading", { level: 1 })).toHaveText("Sign in")
    await expect(page.getByRole("alert")).toBeFocused()
    await expect(page.getByLabel("Username", { exact: true })).toHaveValue(
      "fixture.admin",
    )
    await expect(page.getByLabel("Password", { exact: true })).toHaveValue("")
    expect(await response.text()).not.toContain("SENTINEL_PASSWORD")
    expect(await page.content()).not.toContain("SENTINEL_PASSWORD")
    expect(await context.cookies()).toHaveLength(0)
    await page.keyboard.press("Tab")
    await expect(page.getByLabel("Username", { exact: true })).toBeFocused()
  })
}

for (const [admin, status] of [
  ["member", 403],
  ["unavailable", 503],
]) {
  test(`${admin} never displays administrator content`, async ({
    page,
    authWire,
  }) => {
    authWire.configure({ admin })
    const result = page.waitForResponse(`${authWire.url}/admin`)
    await signIn(page, authWire)
    expect((await result).status()).toBe(status)
    await expect(page.getByRole("heading", { level: 1 })).toHaveText(
      "Access unavailable",
    )
    await expect(page.getByRole("alert")).toBeFocused()
    await expect(page.getByText("fixture.admin", { exact: true })).toHaveCount(
      0,
    )
    if (admin === "member") {
      await page.getByRole("button", { name: "Sign out" }).click()
      await expect(page).toHaveURL(`${authWire.url}/login`)
    }
  })
}

test("unconfirmed remote logout clears local fixture cookie without claiming remote success", async ({
  page,
  context,
  authWire,
}) => {
  authWire.configure({ logout: "logout-unavailable" })
  await signIn(page, authWire)
  const result = page.waitForResponse(`${authWire.url}/logout`)
  await page.getByRole("button", { name: "Sign out" }).click()
  expect((await result).status()).toBe(503)
  await expect(page.getByRole("alert")).toContainText("signed out locally")
  await expect(page.getByRole("alert")).toContainText(
    "remote session revocation could not be confirmed",
  )
  expect(await context.cookies()).toHaveLength(0)
  await expect(page.getByRole("alert")).toBeFocused()
})

test("fixture rejects missing or cross-site Origin without clearing cookie", async ({
  page,
  context,
  authWire,
}) => {
  await signIn(page, authWire)
  const before = await context.cookies()
  for (const headers of [
    {},
    { origin: "null" },
    { origin: "https://other.invalid" },
    { origin: authWire.url, "sec-fetch-site": "cross-site" },
  ]) {
    const response = await context.request.post(`${authWire.url}/logout`, {
      headers,
    })
    expect(response.status()).toBe(403)
    expect(await response.text()).toContain("Access unavailable")
    expect(await context.cookies()).toEqual(before)
  }
})

test("public documents ignore malformed fixture cookies and unavailable state", async ({
  page,
  context,
  authWire,
}) => {
  authWire.configure({ admin: "unavailable" })
  await context.addCookies([
    { name: authWire.cookieName, value: "malformed", url: authWire.url },
  ])
  for (const path of ["/", "/login"]) {
    const response = await page.goto(authWire.url + path)
    expect(response.status()).toBe(200)
    await expect(page.locator("body")).not.toContainText("malformed")
  }
})

for (const [width, colorScheme] of [
  [1280, "light"],
  [1280, "dark"],
  [390, "light"],
  [390, "dark"],
  [320, "light"],
  [320, "dark"],
]) {
  test(`auth documents fit ${width}px in ${colorScheme} and escape identity`, async ({
    page,
    authWire,
  }, testInfo) => {
    await page.setViewportSize({ width, height: 844 })
    await page.emulateMedia({ colorScheme })
    authWire.configure({ admin: "escaped" })
    await signIn(page, authWire)
    await expect(
      page.getByText('<script>alert("identity")</script>', { exact: true }),
    ).toBeVisible()
    for (const path of ["/admin", "/login"]) {
      await page.goto(authWire.url + path)
      expect(
        await page.evaluate(
          () => document.documentElement.scrollWidth <= window.innerWidth,
        ),
      ).toBe(true)
      await expect(page.getByRole("button")).toBeVisible()
      await page.screenshot({
        path: testInfo.outputPath(`${path.slice(1)}.png`),
        fullPage: true,
      })
    }
    authWire.configure({ admin: "member" })
    await page.goto(`${authWire.url}/admin`)
    expect(
      await page.evaluate(
        () => document.documentElement.scrollWidth <= window.innerWidth,
      ),
    ).toBe(true)
  })
}

test("initialization fragments are distinct, explicit-retry only, without setup forms", async ({
  page,
  authWire,
}) => {
  for (const state of [
    "initializing",
    "setup-required",
    "bootstrap-failed",
    "schema-error",
  ]) {
    authWire.configure({ readiness: state })
    await page.goto(authWire.url)
    await expect(page.locator("#readiness > div")).toHaveAttribute(
      "data-readiness-state",
      state,
    )
    await expect(page.locator("form")).toHaveCount(0)
    await expect(page.locator("#readiness")).not.toContainText(
      "Database unavailable",
    )
    const count = authWire.calls.length
    await page.waitForTimeout(350)
    expect(authWire.calls).toHaveLength(count)
    await page.getByRole("button", { name: "Retry", exact: true }).click()
    await expect(page.locator("#readiness > div")).toHaveAttribute(
      "data-readiness-state",
      state,
    )
  }
})

test("sign-in uses ordinary forms even without JavaScript", async ({
  browser,
  authWire,
}) => {
  const context = await browser.newContext({ javaScriptEnabled: false })
  try {
    const page = await context.newPage()
    await signIn(page, authWire)
    await expect(page).toHaveURL(`${authWire.url}/admin`)
    await page.getByRole("button", { name: "Sign out" }).click()
    await expect(page).toHaveURL(`${authWire.url}/login`)
  } finally {
    await context.close()
  }
})
