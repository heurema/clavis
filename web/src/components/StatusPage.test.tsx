import { afterEach, describe, expect, it, vi } from "vitest"
import { act, render, screen, waitFor } from "@testing-library/react"
import userEvent from "@testing-library/user-event"
import { onlineManager, QueryClientProvider } from "@tanstack/react-query"
import { RouterProvider, createMemoryHistory } from "@tanstack/react-router"
import { createAppRouter } from "../app/router"
import { createQueryClient } from "../app/query"
import { AppearanceProvider } from "../app/appearance"

const clients: ReturnType<typeof createQueryClient>[] = []
afterEach(() => {
  for (const client of clients) client.clear()
  clients.length = 0
  onlineManager.setOnline(true)
})

function mount(client = createQueryClient()) {
  clients.push(client)
  const router = createAppRouter()
  router.update({ history: createMemoryHistory({ initialEntries: ["/"] }) })
  const rendered = render(
    <QueryClientProvider client={client}>
      <AppearanceProvider>
        <RouterProvider router={router} />
      </AppearanceProvider>
    </QueryClientProvider>,
  )
  return { ...rendered, client, router }
}

describe("setup screen", () => {
  it("checks and retries even when the browser reports being offline", async () => {
    onlineManager.setOnline(false)
    const fetcher = vi
      .fn<typeof fetch>()
      .mockRejectedValueOnce(new TypeError("Failed to fetch"))
      .mockImplementation(async () => Response.json({ status: "ready" }))
    vi.stubGlobal("fetch", fetcher)
    mount()
    await screen.findByText("Server unavailable")
    expect(fetcher).toHaveBeenCalledOnce()
    await userEvent.click(screen.getByRole("button", { name: "Retry" }))
    await screen.findByText("Your environment is ready")
    expect(fetcher).toHaveBeenCalledTimes(2)
  })

  it("checks again on page entry without presenting cached readiness as fresh", async () => {
    let respond: (value: Response) => void = () => {}
    const fetcher = vi
      .fn<typeof fetch>()
      .mockResolvedValueOnce(Response.json({ status: "ready" }))
      .mockImplementationOnce(
        () =>
          new Promise((resolve) => {
            respond = resolve
          }),
      )
    vi.stubGlobal("fetch", fetcher)
    const first = mount()
    await screen.findByText("Your environment is ready")
    first.unmount()
    mount(first.client)
    await screen.findByText("Checking your environment")
    expect(
      screen.queryByText("Your environment is ready"),
    ).not.toBeInTheDocument()
    await waitFor(() => expect(fetcher).toHaveBeenCalledTimes(2))
    await act(async () => {
      respond(Response.json({ status: "ready" }))
    })
    await screen.findByText("Your environment is ready")
  })

  it("shows checking and then real readiness through the client", async () => {
    let respond: (value: Response) => void = () => {}
    const fetcher = vi.fn<typeof fetch>().mockImplementation(
      () =>
        new Promise((resolve) => {
          respond = resolve
        }),
    )
    vi.stubGlobal("fetch", fetcher)
    mount()
    expect(
      await screen.findByText("Checking your environment"),
    ).toBeInTheDocument()
    await waitFor(() => expect(fetcher).toHaveBeenCalledOnce())
    await act(async () => {
      respond(Response.json({ status: "ready" }))
    })
    expect(
      await screen.findByText("Your environment is ready"),
    ).toBeInTheDocument()
    expect(screen.getByText("Reachable")).toBeInTheDocument()
    expect(fetcher).toHaveBeenCalledOnce()
  })

  it.each(["database", "network", "malformed"])(
    "handles %s failure and manual recovery without background retries",
    async (failure) => {
      const fetcher = vi.fn<typeof fetch>()
      if (failure === "network")
        fetcher.mockRejectedValueOnce(new Error("SECRET"))
      else
        fetcher.mockResolvedValueOnce(
          failure === "database"
            ? Response.json(
                {
                  status: "not_ready",
                  error: { code: "DEPENDENCY_UNAVAILABLE", message: "SECRET" },
                },
                { status: 503 },
              )
            : new Response("SECRET"),
        )
      fetcher.mockImplementation(async () => Response.json({ status: "ready" }))
      vi.stubGlobal("fetch", fetcher)
      mount()
      expect(
        await screen.findByText(
          failure === "database"
            ? "Database unavailable"
            : "Server unavailable",
        ),
      ).toBeInTheDocument()
      expect(document.body.textContent).not.toContain("SECRET")
      await act(async () => {
        window.dispatchEvent(new Event("focus"))
        window.dispatchEvent(new Event("online"))
        document.dispatchEvent(new Event("visibilitychange"))
        await new Promise((resolve) => setTimeout(resolve, 80))
      })
      expect(fetcher).toHaveBeenCalledOnce()
      await userEvent.click(screen.getByRole("button", { name: "Retry" }))
      expect(
        await screen.findByText("Your environment is ready"),
      ).toBeInTheDocument()
      expect(fetcher).toHaveBeenCalledTimes(2)
    },
  )

  it("ignores a superseded check that completes after Retry", async () => {
    let stale: (value: Response) => void = () => {}
    const fetcher = vi
      .fn<typeof fetch>()
      .mockImplementationOnce(
        () =>
          new Promise((resolve) => {
            stale = resolve
          }),
      )
      .mockImplementation(async () => Response.json({ status: "ready" }))
    vi.stubGlobal("fetch", fetcher)
    mount()
    await waitFor(() => expect(fetcher).toHaveBeenCalledOnce())
    await userEvent.click(screen.getByRole("button", { name: "Retry" }))
    expect(
      await screen.findByText("Your environment is ready"),
    ).toBeInTheDocument()
    await act(async () => {
      stale(
        Response.json(
          {
            status: "not_ready",
            error: { code: "DEPENDENCY_UNAVAILABLE", message: "SECRET" },
          },
          { status: 503 },
        ),
      )
    })
    expect(screen.getByText("Your environment is ready")).toBeInTheDocument()
    expect(fetcher).toHaveBeenCalledTimes(2)
  })

  it("persists explicit appearance and restores it on remount", async () => {
    vi.stubGlobal(
      "fetch",
      vi
        .fn<typeof fetch>()
        .mockImplementation(async () => Response.json({ status: "ready" })),
    )
    const rendered = mount()
    const control = await screen.findByRole("switch", {
      name: "Dark appearance",
    })
    expect(localStorage.length).toBe(0)
    await userEvent.click(control)
    expect(document.documentElement).toHaveClass("dark")
    expect(localStorage.getItem("clavis.appearance")).toBe("dark")
    expect(localStorage.length).toBe(1)
    rendered.unmount()
    mount()
    expect(
      await screen.findByRole("switch", { name: "Dark appearance" }),
    ).toBeChecked()
    expect(document.documentElement).toHaveClass("dark")
  })
})
