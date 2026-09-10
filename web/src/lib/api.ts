import ky, { TimeoutError } from "ky"
import { z } from "zod"

const readySchema = z.object({ status: z.literal("ready") }).strict()
const unavailableSchema = z
  .object({
    status: z.literal("not_ready"),
    error: z
      .object({
        code: z.literal("DEPENDENCY_UNAVAILABLE"),
        message: z.string(),
      })
      .strict(),
  })
  .strict()
export type Readiness = { status: "ready" | "not_ready" }
export type ReadinessCode =
  "SERVER_UNREACHABLE" | "INVALID_RESPONSE" | "TIMEOUT" | "CANCELED"

export class ReadinessError extends Error {
  constructor(public readonly code: ReadinessCode) {
    super(
      code === "TIMEOUT"
        ? "The readiness check timed out."
        : code === "INVALID_RESPONSE"
          ? "The server returned an unexpected response."
          : code === "CANCELED"
            ? "The check was canceled."
            : "Clavis could not reach the server. Start it, then retry.",
    )
  }
}

export function createReadinessAPI(
  options: { baseURL?: string; timeoutMs?: number; fetch?: typeof fetch } = {},
) {
  const client = ky.create({
    retry: 0,
    timeout: false,
    totalTimeout: options.timeoutMs ?? 5_000,
    throwHttpErrors: false,
    redirect: "error",
    cache: "no-store",
    ...(options.fetch ? { fetch: options.fetch } : {}),
  })
  const endpoint = `${(options.baseURL ?? "/api").replace(/\/$/, "")}/health/ready`
  return async (signal: AbortSignal): Promise<Readiness> => {
    // Settle cancellation even when an injected transport ignores its signal.
    let rejectAbort: () => void = () => {}
    const aborted = new Promise<never>((_, reject) => {
      rejectAbort = () => reject(new ReadinessError("CANCELED"))
      signal.addEventListener("abort", rejectAbort, { once: true })
      if (signal.aborted) rejectAbort()
    })
    try {
      // Node's Request in component tests needs an absolute URL.
      const request = client.get(new URL(endpoint, globalThis.location?.href), {
        signal,
      })
      const response = await Promise.race([request, aborted])
      // Ky's shortcut shares totalTimeout with the request and bounds body reads.
      const body = await Promise.race([request.json<unknown>(), aborted])
      const parsed =
        response.status === 200
          ? readySchema.safeParse(body)
          : response.status === 503
            ? unavailableSchema.safeParse(body)
            : null
      if (!parsed?.success) throw new ReadinessError("INVALID_RESPONSE")
      // The page needs only status; discard server-provided error details.
      return { status: parsed.data.status }
    } catch (error) {
      if (signal.aborted) throw new ReadinessError("CANCELED")
      if (error instanceof TimeoutError) throw new ReadinessError("TIMEOUT")
      if (error instanceof SyntaxError)
        throw new ReadinessError("INVALID_RESPONSE")
      if (error instanceof ReadinessError) throw error
      throw new ReadinessError("SERVER_UNREACHABLE")
    } finally {
      signal.removeEventListener("abort", rejectAbort)
    }
  }
}
export const getReadiness = createReadinessAPI()
