const dateTime = new Intl.DateTimeFormat("fr-FR", { dateStyle: "medium", timeStyle: "short" })
const dateOnly = new Intl.DateTimeFormat("fr-FR", { dateStyle: "medium" })
const rtf = new Intl.RelativeTimeFormat("fr-FR", { numeric: "auto" })
const rtfShort = new Intl.RelativeTimeFormat("fr-FR", { numeric: "always", style: "short" })

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

/** Compact relative time: "dans 3 h", "il y a 12 min", "dans 2 j". */
export function formatRelativeShort(value?: string | null): string {
  if (!value) return "—"
  const d = new Date(value)
  if (Number.isNaN(d.getTime())) return "—"
  const diff = (d.getTime() - Date.now()) / 1000
  const abs = Math.abs(diff)
  if (abs < 60) return diff >= 0 ? "dans moins d'1 min" : "à l'instant"
  if (abs < 3600) return rtfShort.format(Math.round(diff / 60), "minute")
  if (abs < 86400) return rtfShort.format(Math.round(diff / 3600), "hour")
  return rtfShort.format(Math.round(diff / 86400), "day")
}

/** Past time with second precision for live views: "il y a 3 s", then like formatRelative. */
export function formatAgo(value?: string | null): string {
  if (!value) return "jamais"
  const d = new Date(value)
  if (Number.isNaN(d.getTime())) return "—"
  const s = Math.round((Date.now() - d.getTime()) / 1000)
  if (s < 2) return "à l'instant"
  if (s < 60) return `il y a ${s} s`
  return formatRelative(value)
}

/** Duration in seconds as a short French text: 300 -> "5 min", 90 -> "1 min 30 s", 3600 -> "1 h". */
export function formatDuration(sec: number): string {
  if (!Number.isFinite(sec) || sec < 0) return "—"
  if (sec < 60) return `${sec} s`
  const h = Math.floor(sec / 3600)
  const m = Math.floor((sec % 3600) / 60)
  const s = sec % 60
  return [h && `${h} h`, m && `${m} min`, s && `${s} s`].filter(Boolean).join(" ")
}
