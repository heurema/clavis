import { test as base, expect } from "@playwright/test"
import { readFileSync } from "node:fs"
import { createServer } from "node:http"

export { expect }
export const fragmentHeaders = {
  "content-type": "text/html; charset=utf-8",
  "x-clavis-fragment": "readiness",
  "cache-control": "no-store",
}

export const test = base.extend({
  // eslint-disable-next-line no-empty-pattern -- Playwright requires destructured fixture dependencies.
  fragments: async ({}, use) => {
    await use(
      JSON.parse(
        readFileSync(
          new URL("../../reports/browser-fragments.json", import.meta.url),
        ),
      ),
    )
  },
  // Fault-injecting same-origin proxy: all documents/assets are served by the
  // built Go server. Tests can stall actual HTTP bodies, not just mock a promise.
  wire: async ({ baseURL, fragments }, use) => {
    const calls = []
    let respond = (_request, response) => {
      response.writeHead(200, fragmentHeaders)
      response.end(fragments.ready)
    }
    const server = createServer(async (request, response) => {
      if (request.url === "/ui/readiness") {
        calls.push(request)
        respond(request, response)
        return
      }
      try {
        const upstream = await fetch(new URL(request.url, baseURL), {
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
    })
    await new Promise((resolve, reject) => {
      server.once("error", reject)
      server.listen(0, "127.0.0.1", resolve)
    })
    try {
      await use({
        url: `http://127.0.0.1:${server.address().port}`,
        calls,
        respond(handler) {
          respond = handler
        },
      })
    } finally {
      server.closeAllConnections()
      await new Promise((resolve) => server.close(resolve))
    }
  },
})

export async function state(page, expected) {
  await expect(
    page.locator("#readiness > [data-readiness-state]"),
  ).toHaveAttribute("data-readiness-state", expected)
}
