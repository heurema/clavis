import assert from "node:assert/strict"
import { fileURLToPath } from "node:url"

// Real authentication uses a separate, untraced context. Playwright traces can
// retain fill arguments, request bodies and cookies, so they are not auth logs.
export async function launchAuthSmokeBrowser(
  origin,
  { selfSignedFixture = false } = {},
) {
  const secure = new URL(origin).protocol === "https:"
  if (
    selfSignedFixture &&
    (!secure || new URL(origin).hostname !== "127.0.0.1")
  )
    throw new Error(
      "Self-signed browser trust is restricted to the local HTTPS fixture",
    )
  const cookieName = secure ? "__Host-clavis-session" : "clavis-dev-session"
  process.env.PLAYWRIGHT_BROWSERS_PATH = fileURLToPath(
    new URL("../../.tools/playwright", import.meta.url),
  )
  const { chromium, expect: baseExpect } = await import("@playwright/test")
  const expect = baseExpect.configure({ timeout: 7_000 })
  const browser = await chromium.launch({ timeout: 10_000 })
  let context, closing
  const evidence = {
    steps: [],
    closed: false,
    traced: false,
    secure,
    selfSignedFixture,
  }
  async function close() {
    closing ??= (async () => {
      try {
        await context?.close()
      } finally {
        await browser.close()
        evidence.closed = true
      }
    })()
    return closing
  }
  try {
    context = await browser.newContext({
      viewport: { width: 1280, height: 900 },
      serviceWorkers: "block",
      // Trust only within this disposable browser fixture, never globally.
      ignoreHTTPSErrors: selfSignedFixture,
    })
    let thirdParty = false,
      pageError = false
    await context.route("**/*", (route) => {
      if (new URL(route.request().url()).origin !== origin) {
        thirdParty = true
        return route.abort()
      }
      return route.continue()
    })
    const page = await context.newPage()
    page.setDefaultTimeout(7_000)
    page.setDefaultNavigationTimeout(10_000)
    page.on("pageerror", () => {
      pageError = true
    })
    async function step(name, action) {
      try {
        await action()
        assert(!thirdParty && !pageError)
        evidence.steps.push(name)
      } catch {
        // In particular, never persist a Playwright fill/cookie error containing
        // credentials in the outer runner's diagnostic summary.
        throw new Error(`Authentication browser smoke failed: ${name}`)
      }
    }
    async function sessionCookie() {
      const cookies = await context.cookies(origin)
      return cookies.find((cookie) => cookie.name === cookieName)
    }
    return {
      evidence,
      close,
      login(username, password, admin = true) {
        return step(
          admin ? "admin-login" : "member-login-denied-admin",
          async () => {
            await page.goto(`${origin}/login`)
            await page.getByLabel("Username", { exact: true }).fill(username)
            await page.getByLabel("Password", { exact: true }).fill(password)
            const [result] = await Promise.all([
              page.waitForResponse(
                (response) =>
                  response.url() === `${origin}/admin` &&
                  response.request().method() === "GET",
              ),
              page
                .getByRole("button", { name: "Sign in", exact: true })
                .click(),
            ])
            assert.equal(result.status(), admin ? 200 : 403)
            await expect(page).toHaveURL(`${origin}/admin`)
            const cookie = await sessionCookie()
            assert(cookie, "Expected a browser session")
            assert.equal(cookie.httpOnly, true)
            assert.equal(cookie.secure, secure)
            assert.equal(cookie.sameSite, "Lax")
            assert.equal(cookie.path, "/")
            const body = await page.locator("body").innerText()
            assert(!body.includes(password) && !body.includes(cookie.value))
            if (admin) {
              await expect(
                page.getByRole("heading", {
                  name: "Administration",
                  exact: true,
                }),
              ).toBeVisible()
              await expect(
                page.getByText(username, { exact: true }),
              ).toBeVisible()
            } else {
              await expect(
                page.getByRole("heading", {
                  name: "Access unavailable",
                  exact: true,
                }),
              ).toBeVisible()
              await expect(
                page.getByRole("heading", {
                  name: "Administration",
                  exact: true,
                }),
              ).toHaveCount(0)
            }
          },
        )
      },
      rejectCrossOriginLogout() {
        return step("cross-origin-logout-denied", async () => {
          const before = await sessionCookie()
          assert(before)
          const response = await context.request.post(`${origin}/logout`, {
            headers: { Origin: "https://untrusted.invalid" },
            maxRedirects: 0,
            timeout: 7_000,
          })
          assert.equal(response.status(), 403)
          const after = await sessionCookie()
          assert(
            after && after.value === before.value,
            "Rejected logout changed the session",
          )
          const admin = await page.goto(`${origin}/admin`)
          assert.equal(admin.status(), 200)
        })
      },
      expectRevoked() {
        return step("revoked-browser-session-denied", async () => {
          await page.goto(`${origin}/admin`)
          await expect(page).toHaveURL(`${origin}/login`)
          await expect(
            page.getByRole("heading", { name: "Sign in", exact: true }),
          ).toBeVisible()
        })
      },
      expectForbidden() {
        return step("current-member-role-denied-admin", async () => {
          const response = await page.goto(`${origin}/admin`)
          assert.equal(response.status(), 403)
          await expect(
            page.getByRole("heading", {
              name: "Access unavailable",
              exact: true,
            }),
          ).toBeVisible()
        })
      },
      logout() {
        return step("browser-logout", async () => {
          await page
            .getByRole("button", { name: "Sign out", exact: true })
            .click()
          await expect(page).toHaveURL(`${origin}/login`)
          assert.equal(await sessionCookie(), undefined)
          await page.goto(`${origin}/admin`)
          await expect(page).toHaveURL(`${origin}/login`)
        })
      },
    }
  } catch {
    await close()
    throw new Error("Unable to start authentication smoke browser")
  }
}
