const dateTime = new Intl.DateTimeFormat("fr-FR", { dateStyle: "medium", timeStyle: "short" })
const dateOnly = new Intl.DateTimeFormat("fr-FR", { dateStyle: "medium" })
const rtf = new Intl.RelativeTimeFormat("fr-FR", { numeric: "auto" })

export function formatDateTime(value?: string | null): string {
  if (!value) return "—"
  const d = new Date(value)
  return Number.isNaN(d.getTime()) ? "—" : dateTime.format(d)
}

export function formatDate(value?: string | null): string {
  if (!value) return "—"
  const d = new Date(value)
  return Number.isNaN(d.getTime()) ? "—" : dateOnly.format(d)
}

export function formatRelative(value?: string | null): string {
  if (!value) return "jamais"
  const d = new Date(value)
  if (Number.isNaN(d.getTime())) return "—"
  const diff = (d.getTime() - Date.now()) / 1000
  const abs = Math.abs(diff)
  if (abs < 60) return "à l'instant"
  if (abs < 3600) return rtf.format(Math.round(diff / 60), "minute")
  if (abs < 86400) return rtf.format(Math.round(diff / 3600), "hour")
  if (abs < 86400 * 30) return rtf.format(Math.round(diff / 86400), "day")
  return dateOnly.format(d)
}

/** Short, readable label for a browser user agent string. */
export function describeUserAgent(ua?: string): string {
  if (!ua) return "Inconnu"
  const browser = /Edg\//.test(ua)
    ? "Edge"
    : /Firefox\//.test(ua)
      ? "Firefox"
      : /Chrome\//.test(ua)
        ? "Chrome"
        : /Safari\//.test(ua)
          ? "Safari"
          : /curl|Go-http|python|wget/i.test(ua)
            ? "Script"
            : "Navigateur"
  const os = /Windows/.test(ua)
    ? "Windows"
    : /Android/.test(ua)
      ? "Android"
      : /iPhone|iPad/.test(ua)
        ? "iOS"
        : /Mac OS X/.test(ua)
          ? "macOS"
          : /Linux/.test(ua)
            ? "Linux"
            : ""
  return os ? `${browser} · ${os}` : browser
}
