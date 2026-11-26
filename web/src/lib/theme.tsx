import * as React from "react"

export type Theme = "light" | "dark" | "system"
const STORAGE_KEY = "leazone-theme"

type ThemeContextValue = {
  theme: Theme
  resolved: "light" | "dark"
  setTheme: (t: Theme) => void
  cycle: () => void
}

const ThemeContext = React.createContext<ThemeContextValue | null>(null)

function readTheme(): Theme {
  try {
    const t = localStorage.getItem(STORAGE_KEY)
    if (t === "light" || t === "dark" || t === "system") return t
  } catch {
    // storage unavailable
  }
  return "system"
}

const media = () => window.matchMedia("(prefers-color-scheme: dark)")

export function ThemeProvider({ children }: { children: React.ReactNode }) {
  const [theme, setThemeState] = React.useState<Theme>(readTheme)
  const [systemDark, setSystemDark] = React.useState(() => media().matches)

  React.useEffect(() => {
    const m = media()
    const onChange = () => setSystemDark(m.matches)
    m.addEventListener("change", onChange)
    return () => m.removeEventListener("change", onChange)
  }, [])

  const resolved: "light" | "dark" = theme === "system" ? (systemDark ? "dark" : "light") : theme

  React.useEffect(() => {
    document.documentElement.classList.toggle("dark", resolved === "dark")
  }, [resolved])

  const setTheme = React.useCallback((t: Theme) => {
    try {
      localStorage.setItem(STORAGE_KEY, t)
    } catch {
      // storage unavailable
    }
    setThemeState(t)
  }, [])

  const cycle = React.useCallback(() => {
    setTheme(resolved === "dark" ? "light" : "dark")
  }, [resolved, setTheme])

  const value = React.useMemo(() => ({ theme, resolved, setTheme, cycle }), [theme, resolved, setTheme, cycle])
  return <ThemeContext.Provider value={value}>{children}</ThemeContext.Provider>
}

export function useTheme() {
  const ctx = React.useContext(ThemeContext)
  if (!ctx) throw new Error("useTheme outside ThemeProvider")
  return ctx
}
