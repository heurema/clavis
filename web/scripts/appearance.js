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
    for (const control of document.querySelectorAll("button[data-appearance]"))
      control.setAttribute("aria-pressed", String(dark))
  }
  apply()
  system.addEventListener("change", apply)
  document.addEventListener("DOMContentLoaded", apply)
  // Delegation covers every appearance button in the document, whichever
  // page rendered it.
  document.addEventListener("click", (event) => {
    const control = event.target.closest("button[data-appearance]")
    if (!control) return
    selected = root.classList.contains("dark") ? "light" : "dark"
    try {
      localStorage.setItem(key, selected)
    } catch {
      // Keep the in-memory choice, even across system appearance changes.
    }
    apply()
  })
})()
