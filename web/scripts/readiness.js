// htmx 4 events carry a request context, not the htmx 2 XHR detail.
;(() => {
  const button = document.getElementById("readiness-check")
  if (!button || button.dataset.readinessInitialized) return
  button.dataset.readinessInitialized = "true"
  const region = document.getElementById("readiness")
  const action = document.getElementById("readiness-action")
  const deadline = 5_000
  let active = null

  function clear() {
    if (active) clearTimeout(active.timer)
    active = null
  }
  function local(state) {
    if (region.contains(document.activeElement)) button.focus()
    region.replaceChildren(
      document.getElementById(`readiness-${state}`).content.cloneNode(true),
    )
    action.textContent = "Retry"
  }
  function fail(ctx, state) {
    if (!active || active.ctx !== ctx) return
    clear()
    ctx.request.abort()
    local(state)
  }
  function current(event) {
    const ctx = event.detail.ctx
    if (
      active &&
      active.ctx === ctx &&
      performance.now() - active.started >= deadline
    )
      fail(ctx, "timeout")
    if (active && active.ctx === ctx) return true
    event.preventDefault()
    return false
  }

  button.addEventListener("htmx:before:request", ({ detail: { ctx } }) => {
    const previous = active?.ctx
    clear()
    // Keep explicit identity/cancellation as well as hx-sync: a cancelled
    // request may still finish its body or lifecycle after its replacement.
    previous?.request.abort()
    active = { ctx, started: performance.now() }
    active.timer = setTimeout(() => fail(ctx, "timeout"), deadline)
    ctx.request.redirect = "error"
    ctx.request.cache = "no-store"
    local("checking")
  })
  button.addEventListener("htmx:before:response", (event) => {
    const ctx = event.detail.ctx
    // This endpoint never instructs navigation, OOB targeting or extra events.
    // Clear directives even on a rejected response: HX-Trigger runs in finally.
    ctx.hx = {}
    if (!current(event)) return
    const { status, headers, raw } = ctx.response
    const type = headers.get("Content-Type")?.split(";")[0].trim().toLowerCase()
    if (
      ![200, 503].includes(status) ||
      type !== "text/html" ||
      headers.get("X-Clavis-Fragment") !== "readiness" ||
      raw.redirected ||
      raw.url !== new URL("/ui/readiness", location.href).href
    ) {
      event.preventDefault()
      fail(ctx, "unexpected")
    }
  })
  // The first gate runs before reading a body; these also reject stale results
  // after a slow body and immediately before any DOM insertion.
  button.addEventListener("htmx:after:request", current)
  button.addEventListener("htmx:before:swap", (event) => {
    if (!current(event)) return
    if (region.contains(document.activeElement)) button.focus()
  })
  button.addEventListener("htmx:after:swap", (event) => {
    if (!current(event)) return
    action.textContent =
      event.detail.ctx.response.status === 200 ? "Check again" : "Retry"
    clear()
  })
  button.addEventListener("htmx:error", (event) => {
    fail(event.detail.ctx, "server-unavailable")
  })
  button.addEventListener("htmx:finally:request", (event) => {
    // Successful swaps already settled; never leave an incomplete check spinning.
    fail(event.detail.ctx, "server-unavailable")
  })
  window.addEventListener("pagehide", () => {
    const ctx = active?.ctx
    clear()
    ctx?.request.abort()
  })
})()
