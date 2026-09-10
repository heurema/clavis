import { useQuery, useQueryClient } from "@tanstack/react-query"
import {
  RiArrowRightLine,
  RiDatabase2Line,
  RiKey2Line,
  RiRefreshLine,
  RiServerLine,
  RiTerminalBoxLine,
} from "@remixicon/react"
import { readinessQuery } from "../app/query"
import { useAppearance } from "../app/appearance"
import { ReadinessError } from "../lib/api"
import { Button } from "./ui/Button"
import { Card } from "./ui/Card"
import { Badge } from "./ui/Badge"
import { Callout } from "./ui/Callout"
import { Switch } from "./ui/Switch"

export function StatusPage() {
  const query = useQuery(readinessQuery)
  const queryClient = useQueryClient()
  const { dark, setDark } = useAppearance()
  const checking = query.isPending || query.isFetching
  const state = checking
    ? "checking"
    : query.isError
      ? "server-unavailable"
      : query.data.status === "ready"
        ? "ready"
        : "database-unavailable"
  const title =
    state === "checking"
      ? "Checking your environment"
      : state === "ready"
        ? "Your environment is ready"
        : state === "database-unavailable"
          ? "Database unavailable"
          : "Server unavailable"
  const description =
    state === "checking"
      ? "Contacting the server and checking its database connection."
      : state === "ready"
        ? "The Clavis server is reachable and its platform database is responding."
        : state === "database-unavailable"
          ? "The server is reachable, but its platform database is not responding. Start the database, then retry."
          : query.error instanceof ReadinessError
            ? query.error.message
            : "Clavis could not reach the server. Start it, then retry."
  const variant =
    state === "ready" ? "success" : state === "checking" ? "neutral" : "warning"
  async function retry() {
    await queryClient.cancelQueries({ queryKey: readinessQuery.queryKey })
    await query.refetch()
  }
  return (
    <div className="min-h-screen">
      <header className="border-b border-slate-200 bg-white dark:border-slate-800 dark:bg-[#090e1a]">
        <div className="mx-auto flex h-20 max-w-6xl items-center justify-between px-6 sm:px-10">
          <a
            href="/"
            className="flex items-center gap-3 rounded-md focus-visible:outline-2 focus-visible:outline-offset-4 focus-visible:outline-blue-500"
            aria-label="Clavis home"
          >
            <span className="flex size-9 items-center justify-center rounded-lg bg-slate-900 text-white dark:bg-slate-100 dark:text-slate-900">
              <RiKey2Line className="size-5" aria-hidden="true" />
            </span>
            <span className="text-xl font-semibold tracking-tight">Clavis</span>
            <span className="hidden border-l border-slate-200 pl-3 text-xs text-slate-500 sm:block dark:border-slate-700 dark:text-slate-400">
              by heurema
            </span>
          </a>
          <div className="flex items-center gap-3">
            <label
              htmlFor="appearance"
              className="text-sm text-slate-600 dark:text-slate-400"
            >
              Dark appearance
            </label>
            <Switch id="appearance" checked={dark} onCheckedChange={setDark} />
          </div>
        </div>
      </header>
      <main className="mx-auto max-w-6xl px-6 py-10 sm:px-10 sm:py-14">
        <div className="mb-8 flex items-center gap-2 text-xs font-medium uppercase tracking-widest text-slate-500 dark:text-slate-400">
          <span>Workspace</span>
          <RiArrowRightLine className="size-3" aria-hidden="true" />
          <span className="text-slate-800 dark:text-slate-300">Setup</span>
        </div>
        <div className="mb-9 flex flex-wrap items-start justify-between gap-4">
          <div>
            <h1 className="text-3xl font-semibold tracking-tight sm:text-4xl">
              Environment setup
            </h1>
            <p className="mt-3 max-w-xl text-base leading-7 text-slate-500 dark:text-slate-400">
              A working foundation for controlled access. Check your local
              services, then explore Clavis from the command line.
            </p>
          </div>
          <Badge variant="neutral" className="mt-2">
            Local development
          </Badge>
        </div>
        <div className="grid items-start gap-6 lg:grid-cols-[1.55fr_1fr]">
          <Card className="overflow-hidden p-0">
            <div className="flex items-center justify-between border-b border-slate-100 px-6 py-5 dark:border-slate-800">
              <h2 className="font-semibold">Service readiness</h2>
              <Badge variant={variant}>
                {checking
                  ? "Checking"
                  : state === "ready"
                    ? "Ready"
                    : "Needs attention"}
              </Badge>
            </div>
            <div className="space-y-6 p-6">
              <output className="block" aria-live="polite" aria-atomic="true">
                <Callout title={title} variant={variant}>
                  {description}
                </Callout>
              </output>
              <dl className="divide-y divide-slate-100 dark:divide-slate-800">
                <div className="flex items-center justify-between gap-4 pb-5">
                  <dt className="flex items-center gap-3">
                    <RiServerLine
                      aria-hidden="true"
                      className="size-5 text-slate-400"
                    />
                    <span className="text-sm font-medium">Clavis server</span>
                  </dt>
                  <dd className="text-sm text-slate-500 dark:text-slate-400">
                    {checking
                      ? "Checking…"
                      : state === "server-unavailable"
                        ? "Unavailable"
                        : "Reachable"}
                  </dd>
                </div>
                <div className="flex items-center justify-between gap-4 pt-5">
                  <dt className="flex items-center gap-3">
                    <RiDatabase2Line
                      aria-hidden="true"
                      className="size-5 text-slate-400"
                    />
                    <span className="text-sm font-medium">
                      Platform database
                    </span>
                  </dt>
                  <dd className="text-sm text-slate-500 dark:text-slate-400">
                    {checking
                      ? "Checking…"
                      : state === "ready"
                        ? "Ready"
                        : state === "database-unavailable"
                          ? "Unavailable"
                          : "Not checked"}
                  </dd>
                </div>
              </dl>
              <div className="flex items-center justify-between gap-4 border-t border-slate-100 pt-5 dark:border-slate-800">
                <span className="text-xs text-slate-500 dark:text-slate-400">
                  Checks run when you open this page or retry.
                </span>
                <Button
                  variant="secondary"
                  onClick={() => {
                    void retry()
                  }}
                >
                  <RiRefreshLine
                    aria-hidden="true"
                    className={`mr-2 size-4 ${checking ? "animate-spin" : ""}`}
                  />
                  {state === "ready" ? "Check again" : "Retry"}
                </Button>
              </div>
            </div>
          </Card>
          <div className="space-y-6">
            <Card>
              <RiTerminalBoxLine
                className="mb-4 size-6 text-slate-400"
                aria-hidden="true"
              />
              <h2 className="font-semibold">Continue in your terminal</h2>
              <p className="mt-2 text-sm leading-6 text-slate-500 dark:text-slate-400">
                Run the same readiness check from the project directory. The CLI
                returns structured results for you and your agents.
              </p>
              <pre className="mt-5 overflow-x-auto rounded-lg border border-slate-800 bg-slate-950 px-4 py-4 text-sm text-slate-100">
                <code>
                  <span
                    className="select-none text-slate-500"
                    aria-hidden="true"
                  >
                    ${" "}
                  </span>
                  ./bin/clavis doctor
                </code>
              </pre>
              <p className="mt-4 text-xs leading-5 text-slate-500 dark:text-slate-400">
                Use{" "}
                <code className="text-slate-700 dark:text-slate-300">
                  ./bin/clavis help
                </code>{" "}
                to see available commands.
              </p>
            </Card>
            <div className="px-1">
              <h2 className="text-xs font-semibold uppercase tracking-wider text-slate-500 dark:text-slate-400">
                A foundation, ready to grow
              </h2>
              <p className="mt-3 text-sm leading-6 text-slate-500 dark:text-slate-400">
                Sign-in, permissions, external connections, and auditing will
                follow. This page checks the local platform services.
              </p>
            </div>
          </div>
        </div>
        <footer className="mt-12 border-t border-slate-200 pt-6 text-xs text-slate-500 dark:border-slate-800 dark:text-slate-400">
          Clavis · Controlled access for your agents.
        </footer>
      </main>
    </div>
  )
}
