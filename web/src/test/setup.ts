import "@testing-library/jest-dom/vitest"
import { afterEach, vi } from "vitest"
import { cleanup } from "@testing-library/react"

window.scrollTo = vi.fn()

Object.defineProperty(window, "matchMedia", {
  writable: true,
  value: vi.fn().mockImplementation((query: string) => ({
    matches: false,
    media: query,
    addEventListener: vi.fn(),
    removeEventListener: vi.fn(),
  })),
})
afterEach(() => {
  cleanup()
  localStorage.clear()
  document.documentElement.classList.remove("dark")
  vi.unstubAllGlobals()
})
