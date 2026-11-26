import * as React from "react"

export function useDebounced<T>(value: T, delay = 300): T {
  const [v, setV] = React.useState(value)
  React.useEffect(() => {
    const id = window.setTimeout(() => setV(value), delay)
    return () => window.clearTimeout(id)
  }, [value, delay])
  return v
}
