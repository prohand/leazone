import * as React from "react"

/** Countdown in seconds, used for rate-limit (429) messages. */
export function useCooldown() {
  const [until, setUntil] = React.useState(0)
  const [now, setNow] = React.useState(() => Date.now())

  React.useEffect(() => {
    if (until <= Date.now()) return
    const id = window.setInterval(() => {
      const t = Date.now()
      setNow(t)
      if (t >= until) window.clearInterval(id)
    }, 250)
    return () => window.clearInterval(id)
  }, [until])

  const remaining = Math.max(0, Math.ceil((until - now) / 1000))
  const start = React.useCallback((seconds: number) => {
    const t = Date.now()
    setNow(t)
    setUntil(t + seconds * 1000)
  }, [])
  return { remaining, start }
}
