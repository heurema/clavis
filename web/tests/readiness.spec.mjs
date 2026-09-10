import { test, expect, fragmentHeaders, state } from "./fixtures.mjs"

test("initial ready check, explicit retry, announcements and no automatic refetch", async ({
  page,
  wire,
  fragments,
}) => {
  const errors = []
  page.on("pageerror", (error) => errors.push(error.message))
  await page.goto(wire.url)
  await state(page, "ready")
  expect(wire.calls).toHaveLength(1)
  expect(wire.calls[0].headers["hx-request"]).toBe("true")
  const status = page.getByRole("status")
  await expect(status).toHaveAttribute("aria-live", "polite")
  await expect(status).toHaveAttribute("aria-atomic", "true")
  await expect(status).toContainText("Your environment is ready")
  await expect(page.getByRole("alert")).toHaveCount(0)
  const retry = page.getByRole("button", { name: "Check again" })
  const region = await status.elementHandle()
  const control = await retry.elementHandle()
  // Hold a fresh check: a prior success must not remain current evidence.
  let pending
  wire.respond((_request, response) => {
    pending = response
  })
  await retry.press("Enter")
  await state(page, "checking")
  await expect(status).not.toContainText("Your environment is ready")
  await expect.poll(() => Boolean(pending)).toBe(true)
  pending.writeHead(503, fragmentHeaders).end(fragments.unavailable)
  await state(page, "database-unavailable")
  await expect(status).toContainText("Database unavailable")
  await expect(page.getByRole("button", { name: "Retry" })).toBeFocused()
  expect(
    await region.evaluate(
      (node) => node === document.getElementById("readiness"),
    ),
  ).toBe(true)
  expect(
    await control.evaluate(
      (node) => node === document.getElementById("readiness-check"),
    ),
  ).toBe(true)
  wire.respond((_request, response) =>
    response.writeHead(200, fragmentHeaders).end(fragments.ready),
  )
  await page.getByRole("button", { name: "Retry" }).press("Space")
  await state(page, "ready")
  expect(wire.calls).toHaveLength(3)
  await page.clock.install()
  await page.evaluate(() => {
    window.dispatchEvent(new Event("online"))
    window.dispatchEvent(new Event("focus"))
    document.dispatchEvent(new Event("visibilitychange"))
  })
  await page.clock.fastForward(60_000)
  expect(wire.calls).toHaveLength(3)
  expect(errors).toEqual([])
})

for (const mode of ["headers", "body"]) {
  test(`five-second deadline includes stalled ${mode} and permits recovery`, async ({
    page,
    wire,
    fragments,
  }) => {
    let connectionClosed = false
    wire.respond((_request, response) => {
      response.on("close", () => {
        connectionClosed = true
      })
      if (mode === "body") {
        response.writeHead(200, fragmentHeaders)
        response.write("<div>PRIVATE_STALLED_BODY")
      }
    })
    // Virtual browser time gives an exact boundary rather than a flaky wall-clock assertion.
    await page.clock.install({ time: new Date("2026-01-01T00:00:00Z") })
    await page.clock.pauseAt(new Date("2026-01-01T00:00:01Z"))
    await page.goto(wire.url)
    await page.clock.runFor(0)
    await expect.poll(() => wire.calls.length).toBe(1)
    await state(page, "checking")
    await page.clock.runFor(4_999)
    await state(page, "checking")
    await page.clock.runFor(1)
    await state(page, "timeout")
    await expect(page.getByRole("status")).toContainText("five seconds")
    await expect(page.locator("body")).not.toContainText("PRIVATE_STALLED_BODY")
    await expect.poll(() => connectionClosed).toBe(true)
    wire.respond((_request, response) =>
      response.writeHead(200, fragmentHeaders).end(fragments.ready),
    )
    await page.getByRole("button", { name: "Retry" }).click()
    await state(page, "ready")
  })
}

test("rapid retries cancel all superseded requests, including a slow body", async ({
  page,
  wire,
  fragments,
}) => {
  const responses = []
  const closed = []
  wire.respond((_request, response) => {
    const index = responses.length
    responses.push(response)
    response.on("close", () => {
      closed[index] = true
    })
    response.writeHead(200, fragmentHeaders)
    response.flushHeaders()
  })
  await page.goto(wire.url)
  await expect.poll(() => responses.length).toBe(1)
  for (const count of [2, 3]) {
    await page.getByRole("button", { name: "Retry" }).click()
    await expect.poll(() => responses.length).toBe(count)
    await state(page, "checking")
  }
  await expect.poll(() => closed.slice(0, 2)).toEqual([true, true])
  responses[2].end(fragments.ready)
  await state(page, "ready")
  responses[0].end("PRIVATE_STALE_RESPONSE")
  responses[1].end(fragments.unavailable)
  await expect(page.getByRole("status")).toContainText(
    "Your environment is ready",
  )
  await expect(page.locator("body")).not.toContainText("PRIVATE_STALE_RESPONSE")
})

test("a superseded result that ignores transport cancellation cannot overwrite a newer state", async ({
  page,
  wire,
}) => {
  await page.addInitScript(() => {
    const original = window.fetch
    let calls = 0
    window.fetch = async (input, options) => {
      if (input !== "/ui/readiness" || ++calls !== 1)
        return original(input, options)
      const response = await original(input, options)
      // Simulate an already-buffered transport finishing after cancellation.
      response.text = () =>
        new Promise((resolve) => {
          window.releaseStale = () => resolve("<p>PRIVATE_STALE_RESPONSE</p>")
        })
      return response
    }
  })
  await page.goto(wire.url)
  await expect
    .poll(() => page.evaluate(() => typeof window.releaseStale))
    .toBe("function")
  await page.getByRole("button", { name: "Retry" }).click()
  await state(page, "ready")
  await page.evaluate(() => {
    window.staleFinished = new Promise((resolve) =>
      document
        .getElementById("readiness-check")
        .addEventListener("htmx:finally:request", resolve, { once: true }),
    )
    window.releaseStale()
  })
  await page.evaluate(() => window.staleFinished.then(() => null))
  await state(page, "ready")
  await expect(page.locator("body")).not.toContainText("PRIVATE_STALE_RESPONSE")
})

for (const [name, status, headers] of [
  ["missing marker", 200, { "content-type": "text/html" }],
  ["wrong marker", 503, { ...fragmentHeaders, "x-clavis-fragment": "login" }],
  [
    "wrong content type",
    200,
    { ...fragmentHeaders, "content-type": "application/json" },
  ],
  ["unexpected status", 500, fragmentHeaders],
  ["redirect", 302, { location: "/unexpected?PRIVATE_REDIRECT" }],
  [
    "htmx directives",
    500,
    {
      ...fragmentHeaders,
      "hx-redirect": "/unexpected?PRIVATE_REDIRECT",
      "hx-trigger": "private-event",
    },
  ],
]) {
  test(`rejects ${name} without inserting private response text`, async ({
    page,
    wire,
    fragments,
  }) => {
    wire.respond((_request, response) =>
      response.writeHead(status, headers).end("PRIVATE_UNEXPECTED_BODY"),
    )
    await page.addInitScript(() => {
      window.privateEvent = false
      document.addEventListener("private-event", () => {
        window.privateEvent = true
      })
    })
    await page.goto(wire.url)
    await expect(page.getByRole("status")).toContainText("Server unavailable")
    await expect(page.locator("body")).not.toContainText("PRIVATE_")
    expect(page.url()).toBe(`${wire.url}/`)
    expect(await page.evaluate(() => window.privateEvent)).toBe(false)
    wire.respond((_request, response) =>
      response.writeHead(200, fragmentHeaders).end(fragments.ready),
    )
    await page.getByRole("button", { name: "Retry" }).click()
    await state(page, "ready")
  })
}

test("focus in replaced content moves to the stable retry control", async ({
  page,
  wire,
}) => {
  await page.goto(wire.url)
  await state(page, "ready")
  await page.evaluate(() => {
    const temporary = document.createElement("button")
    temporary.textContent = "Fixture control"
    document.getElementById("readiness").append(temporary)
    temporary.focus()
    window.htmx.trigger(document.getElementById("readiness-check"), "click")
  })
  await state(page, "ready")
  await expect(page.getByRole("button", { name: "Check again" })).toBeFocused()
  await expect(
    page.getByRole("button", { name: "Fixture control" }),
  ).toHaveCount(0)
})

test("transport failure stays safe and explicit retry recovers", async ({
  page,
  wire,
  fragments,
}) => {
  wire.respond((request) => request.socket.destroy())
  await page.goto(wire.url)
  await state(page, "server-unavailable")
  await expect(page.getByRole("status")).toContainText("Not checked")
  wire.respond((_request, response) =>
    response.writeHead(200, fragmentHeaders).end(fragments.ready),
  )
  await page.getByRole("button", { name: "Retry" }).click()
  await state(page, "ready")
})

test("the real Go readiness response works with an unavailable database", async ({
  page,
}) => {
  await page.goto("/")
  await state(page, "database-unavailable")
  await expect(page.getByRole("status")).toContainText("Reachable")
})
