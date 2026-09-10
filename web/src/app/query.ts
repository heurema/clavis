import { QueryClient, queryOptions } from "@tanstack/react-query"
import { getReadiness } from "../lib/api"

export function createQueryClient() {
  return new QueryClient({
    defaultOptions: {
      queries: {
        retry: false,
        refetchOnWindowFocus: false,
        refetchOnReconnect: false,
      },
      mutations: { retry: false },
    },
  })
}
export const readinessQuery = queryOptions({
  queryKey: ["readiness"],
  queryFn: ({ signal }) => getReadiness(signal),
  // Browser connectivity hints do not tell us whether the local server works.
  networkMode: "always",
  refetchOnMount: "always",
})
