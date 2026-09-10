import {
  createContext,
  useContext,
  useEffect,
  useState,
  type ReactNode,
} from "react"

const key = "clavis.appearance"
type Appearance = "light" | "dark"
const AppearanceContext = createContext<{
  dark: boolean
  setDark: (dark: boolean) => void
} | null>(null)
function preference(): Appearance | null {
  try {
    const value = localStorage.getItem(key)
    return value === "light" || value === "dark" ? value : null
  } catch {
    return null
  }
}
export function AppearanceProvider({ children }: { children: ReactNode }) {
  const [selected, setSelected] = useState(preference)
  const [systemDark, setSystemDark] = useState(
    () => window.matchMedia("(prefers-color-scheme: dark)").matches,
  )
  const dark = selected ? selected === "dark" : systemDark
  useEffect(() => {
    const media = window.matchMedia("(prefers-color-scheme: dark)")
    const change = () => setSystemDark(media.matches)
    media.addEventListener("change", change)
    return () => media.removeEventListener("change", change)
  }, [])
  useEffect(() => {
    document.documentElement.classList.toggle("dark", dark)
    document.documentElement.style.colorScheme = dark ? "dark" : "light"
  }, [dark])
  function setDark(value: boolean) {
    const mode = value ? "dark" : "light"
    setSelected(mode)
    try {
      localStorage.setItem(key, mode)
    } catch {
      /* Keep the in-memory preference. */
    }
  }
  return (
    <AppearanceContext value={{ dark, setDark }}>{children}</AppearanceContext>
  )
}
export function useAppearance() {
  const value = useContext(AppearanceContext)
  if (!value) throw new Error("Appearance provider is missing")
  return value
}
