// Isolated presentation fixture. It is NOT backend/session integration evidence.
// Documents and status/redirect/clearing decisions come from Go's frozen contracts.
import { test as base, expect } from "@playwright/test"
import { execFileSync } from "node:child_process"
import { createServer } from "node:http"
import { randomBytes } from "node:crypto"
import { fileURLToPath } from "node:url"

export { expect }
export const test = base.extend({
  authViews: [
    // eslint-disable-next-line no-empty-pattern -- Playwright fixture signature.
    async ({}, use) => {
      await use(
        JSON.parse(
          execFileSync("go", ["run", "./internal/web/testdata/auth"], {
            cwd: fileURLToPath(new URL("../../", import.meta.url)),
            encoding: "utf8",
            timeout: 30_000,
          }),
        ),
      )
    },
    { scope: "worker" },
  ],
  authWire: async ({ baseURL, authViews }, use) => {
    let origin
    let login = "login-success"
    let admin = "admin"
    let logout = "logout"
    let readiness = "ready"
    let token = null
    const calls = []
    // Deliberately fixture-specific, never a production cookie contract name.
    const cookieName = "clavis_view_fixture"
    function send(response, key, headers = {}) {
      const view = authViews[key]
      response.writeHead(view.Status, {
        "content-type": "text/html; charset=utf-8",
        "cache-control": "no-store",
        "content-security-policy": "frame-ancestors 'none'",
        ...(view.Location ? { location: view.Location } : {}),
        ...(view.ClearCookie
          ? {
              "set-cookie": `${cookieName}=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0`,
            }
          : {}),
        ...headers,
      })
      response.end(view.Body)
    }
    const server = createServer(async (request, response) => {
      const path = request.url
      if (path.startsWith("/assets/")) {
        try {
          const upstream = await fetch(new URL(path, baseURL), {
            signal: AbortSignal.timeout(5_000),
          })
          response.writeHead(
            upstream.status,
            Object.fromEntries(upstream.headers),
          )
          response.end(Buffer.from(await upstream.arrayBuffer()))
        } catch {
          response.writeHead(502).end()
        }
        return
      }
      // Record only structural evidence: no password, cookie or token payloads.
      calls.push({ method: request.method, path })
      if (request.method === "POST") {
        const allowed =
          request.headers.origin === origin &&
          request.headers["sec-fetch-site"] !== "cross-site"
        if (!allowed) {
          send(response, path === "/logout" ? "logout-denied" : "FORBIDDEN")
          request.resume()
          return
        }
        if (path === "/login") {
          const chunks = []
          for await (const chunk of request) chunks.push(chunk)
          const fields = new URLSearchParams(Buffer.concat(chunks).toString())
          calls.at(-1).fields = [...fields.keys()].sort()
          if (login === "login-success") {
            token = randomBytes(32).toString("base64url")
            send(response, login, {
              "set-cookie": `${cookieName}=${token}; Path=/; HttpOnly; SameSite=Lax; Max-Age=28800`,
            })
          } else {
            send(
              response,
              login,
              login === "RATE_LIMITED" ? { "retry-after": "30" } : {},
            )
          }
          return
        }
        if (path === "/logout") {
          request.resume()
          if (authViews[logout].ClearCookie) token = null
          send(response, logout)
          return
        }
      }
      if (request.method === "GET") {
        if (path === "/login") return send(response, "login")
        if (path === "/") return send(response, "setup")
        if (path === "/ui/readiness")
          return send(response, readiness, { "x-clavis-fragment": "readiness" })
        if (path === "/admin") {
          const valid =
            token && request.headers.cookie === `${cookieName}=${token}`
          return send(response, valid ? admin : "anonymous")
        }
      }
      response.writeHead(404).end()
    })
    await new Promise((resolve, reject) => {
      server.once("error", reject)
      server.listen(0, "127.0.0.1", resolve)
    })
    origin = `http://127.0.0.1:${server.address().port}`
    try {
      await use({
        url: origin,
        calls,
        cookieName,
        configure(options) {
          login = options.login ?? login
          admin = options.admin ?? admin
          logout = options.logout ?? logout
          readiness = options.readiness ?? readiness
        },
      })
    } finally {
      server.closeAllConnections()
      await new Promise((resolve) => server.close(resolve))
    }
  },
})

export async function signIn(page, wire) {
  await page.goto(`${wire.url}/login`)
  await page.getByLabel("Username", { exact: true }).fill("fixture.admin")
  await page
    .getByLabel("Password", { exact: true })
    .fill("SENTINEL_PASSWORD_123")
  await page.getByRole("button", { name: "Sign in", exact: true }).click()
}
