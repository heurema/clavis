// Runs in the head before styles paint. No readiness state is persisted.
;(() => {
  const root = document.documentElement
  if (root.dataset.appearanceInitialized) return
  root.dataset.appearanceInitialized = "true"
  const key = "clavis.appearance"
  const system = matchMedia("(prefers-color-scheme: dark)")
  let selected = null
  try {
    const stored = localStorage.getItem(key)
    if (stored === "light" || stored === "dark") selected = stored
  } catch {
    // Storage may be blocked; subsequent choices still work in memory.
  }
  function apply() {
    const dark = selected ? selected === "dark" : system.matches
    root.classList.toggle("dark", dark)
    root.style.colorScheme = dark ? "dark" : "light"
    for (const control of document.querySelectorAll("input[data-appearance]"))
      control.checked = dark
  }
  apply()
  system.addEventListener("change", apply)
  document.addEventListener("DOMContentLoaded", apply)
  document.addEventListener("htmx:after:process", apply)
  // Delegation also covers a templUI switch inserted by a later partial update.
  document.addEventListener("change", (event) => {
    if (!event.target.matches("input[data-appearance]")) return
    selected = event.target.checked ? "dark" : "light"
    try {
      localStorage.setItem(key, selected)
    } catch {
      // Keep the in-memory choice, even across system appearance changes.
    }
    apply()
  })
})()
