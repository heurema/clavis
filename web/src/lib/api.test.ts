import { describe, expect, it, vi } from "vitest"
import { createReadinessAPI } from "./api"

const url = "http://127.0.0.1:8080"
const unavailable = {
  status: "not_ready",
  error: { code: "DEPENDENCY_UNAVAILABLE", message: "SECRET" },
}

describe("readiness API", () => {
  it.each([
    [200, { status: "ready" }, "ready"],
    [503, unavailable, "not_ready"],
  ])(
    "validates HTTP %s without treating 503 as a transport failure",
    async (status, body, expected) => {
      const fetcher = vi
        .fn<typeof fetch>()
        .mockResolvedValue(Response.json(body, { status }))
      const get = createReadinessAPI({ baseURL: url, fetch: fetcher })
      const result = await get(new AbortController().signal)
      expect(result.status).toBe(expected)
      expect(JSON.stringify(result)).not.toContain("SECRET")
      expect(fetcher).toHaveBeenCalledTimes(1)
    },
  )

  it.each([
    [200, "SECRET"],
    [500, '{"status":"ready"}'],
    [503, '{"status":"ready"}'],
    [200, '{"status":"not_ready"}'],
    [200, '{"status":"ready","secret":"SECRET"}'],
    [503, '{"status":"not_ready","error":{"code":"SECRET"}}'],
  ])("rejects malformed or mismatched HTTP %s safely", async (status, body) => {
    const fetcher = vi
      .fn<typeof fetch>()
      .mockResolvedValue(new Response(body, { status }))
    const get = createReadinessAPI({ baseURL: url, fetch: fetcher })
    await expect(get(new AbortController().signal)).rejects.toMatchObject({
      code: "INVALID_RESPONSE",
    })
    expect(fetcher).toHaveBeenCalledTimes(1)
  })

  it("does not retry network failures or echo their details", async () => {
    const fetcher = vi.fn<typeof fetch>().mockRejectedValue(new Error("SECRET"))
    const get = createReadinessAPI({ baseURL: url, fetch: fetcher })
    await expect(get(new AbortController().signal)).rejects.toMatchObject({
      code: "SERVER_UNREACHABLE",
      message: "Clavis could not reach the server. Start it, then retry.",
    })
    expect(fetcher).toHaveBeenCalledTimes(1)
  })

  it("bounds response reading, including a body that never completes", async () => {
    const fetcher = vi
      .fn<typeof fetch>()
      .mockResolvedValue(new Response(new ReadableStream()))
    const get = createReadinessAPI({
      baseURL: url,
      timeoutMs: 20,
      fetch: fetcher,
    })
    await expect(get(new AbortController().signal)).rejects.toMatchObject({
      code: "TIMEOUT",
    })
    const request = fetcher.mock.calls[0][0] as Request
    expect(request.signal.aborted).toBe(true)
  })

  it("forwards cancellation to the request", async () => {
    const fetcher = vi
      .fn<typeof fetch>()
      .mockImplementation(() => new Promise(() => {}))
    const controller = new AbortController()
    const pending = createReadinessAPI({ baseURL: url, fetch: fetcher })(
      controller.signal,
    )
    const outcome = expect(pending).rejects.toMatchObject({ code: "CANCELED" })
    await vi.waitFor(() => expect(fetcher).toHaveBeenCalledOnce())
    controller.abort()
    await outcome
    expect((fetcher.mock.calls[0][0] as Request).signal.aborted).toBe(true)
  })

  it("uses one deadline for the request and response body together", async () => {
    const fetcher = vi.fn<typeof fetch>().mockImplementation(async () => {
      await new Promise((resolve) => setTimeout(resolve, 40))
      return new Response(
        new ReadableStream({
          start(controller) {
            setTimeout(() => {
              controller.enqueue(new TextEncoder().encode('{"status":"ready"}'))
              controller.close()
            }, 40)
          },
        }),
      )
    })
    const get = createReadinessAPI({
      baseURL: url,
      timeoutMs: 60,
      fetch: fetcher,
    })
    await expect(get(new AbortController().signal)).rejects.toMatchObject({
      code: "TIMEOUT",
    })
    expect(fetcher).toHaveBeenCalledOnce()
    expect((fetcher.mock.calls[0][0] as Request).signal.aborted).toBe(true)
  })
})
