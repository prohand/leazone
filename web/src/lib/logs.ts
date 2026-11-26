import type { DhcpLogEvent, DnsLogSource } from "@/api/types"

/* Labels and helpers for the DNS / DHCP logs and the dashboard. */

export const fmtInt = new Intl.NumberFormat("fr-FR")
export const fmtOneDecimal = new Intl.NumberFormat("fr-FR", { minimumFractionDigits: 1, maximumFractionDigits: 1 })

export const dnsSources: DnsLogSource[] = ["local", "cache", "forwarder", "blocked", "refused", "error"]
export const dnsSourceLabel: Record<DnsLogSource, string> = {
  local: "local",
  cache: "cache",
  forwarder: "redirecteur",
  blocked: "bloqué",
  refused: "refusé",
  error: "erreur",
}
export const dnsSourceClass: Record<DnsLogSource, string> = {
  local: "border-brand/40 text-brand",
  cache: "border-success/40 text-success",
  forwarder: "text-muted-foreground",
  blocked: "border-warning/50 text-warning",
  refused: "border-warning/50 text-warning",
  error: "border-destructive/40 text-destructive",
}

export const rcodes = ["NOERROR", "NXDOMAIN", "SERVFAIL", "REFUSED"] as const
export function rcodeClass(rcode?: string): string {
  switch (rcode) {
    case "NOERROR":
      return "border-success/40 bg-success/10 text-success"
    case "NXDOMAIN":
      return "border-border bg-muted text-muted-foreground"
    case "SERVFAIL":
      return "border-destructive/40 bg-destructive/10 text-destructive"
    case "REFUSED":
      return "border-warning/50 bg-warning/10 text-warning"
  }
  return "text-muted-foreground"
}

export const queryTypes = ["A", "AAAA", "CNAME", "MX", "TXT", "PTR", "SRV", "NS", "SOA", "HTTPS", "SVCB", "CAA", "ANY"] as const

export const dhcpEvents: DhcpLogEvent[] = ["offer", "ack", "nak", "release", "decline", "expire", "ignored"]
export const dhcpEventLabel: Record<DhcpLogEvent, string> = {
  offer: "offre",
  ack: "attribution (ack)",
  nak: "refus (nak)",
  release: "libération",
  decline: "refusée par le client (decline)",
  expire: "expirée",
  ignored: "ignorée",
}
/** Short label for the table badge. */
export const dhcpEventShort: Record<DhcpLogEvent, string> = {
  offer: "offre",
  ack: "attribution",
  nak: "refus",
  release: "libération",
  decline: "refusée (client)",
  expire: "expirée",
  ignored: "ignorée",
}
export const dhcpEventClass: Record<DhcpLogEvent, string> = {
  offer: "border-brand/40 text-brand",
  ack: "border-success/40 text-success",
  nak: "border-destructive/40 text-destructive",
  release: "text-muted-foreground",
  decline: "border-warning/50 text-warning",
  expire: "text-muted-foreground",
  ignored: "border-border bg-muted text-muted-foreground",
}

export type Period = "15m" | "1h" | "24h" | "7d" | "custom"
export const periods: { value: Period; label: string; seconds?: number }[] = [
  { value: "15m", label: "15 dernières min", seconds: 15 * 60 },
  { value: "1h", label: "Dernière heure", seconds: 3600 },
  { value: "24h", label: "Dernières 24 h", seconds: 86400 },
  { value: "7d", label: "7 derniers jours", seconds: 7 * 86400 },
  { value: "custom", label: "Personnalisée…" },
]
export const isPeriod = (v: string | null): v is Period => periods.some((p) => p.value === v)

/** Value of a datetime-local input ("2026-11-26T10:05") as an ISO date, or undefined. */
export function localToIso(v?: string | null): string | undefined {
  if (!v) return undefined
  const d = new Date(v)
  return Number.isNaN(d.getTime()) ? undefined : d.toISOString()
}

/** ISO date -> value for a datetime-local input (local time). */
export function isoToLocal(d: Date): string {
  const p = (n: number) => String(n).padStart(2, "0")
  return `${d.getFullYear()}-${p(d.getMonth() + 1)}-${p(d.getDate())}T${p(d.getHours())}:${p(d.getMinutes())}`
}

/** from/to sent to the server for a period (relative ones are computed now). */
export function periodRange(period: Period, from?: string | null, to?: string | null): { from?: string; to?: string } {
  if (period === "custom") return { from: localToIso(from), to: localToIso(to) }
  const s = periods.find((p) => p.value === period)?.seconds ?? 3600
  return { from: new Date(Date.now() - s * 1000).toISOString() }
}

const hms = new Intl.DateTimeFormat("fr-FR", { hour: "2-digit", minute: "2-digit", second: "2-digit" })
const full = new Intl.DateTimeFormat("fr-FR", { dateStyle: "full", timeStyle: "medium" })
const dayShort = new Intl.DateTimeFormat("fr-FR", { day: "numeric", month: "short" })
export const hhmm = new Intl.DateTimeFormat("fr-FR", { hour: "2-digit", minute: "2-digit" })

/** "14:05:09" for today, "26 nov. 14:05:09" otherwise; full date for the title. */
export function logTime(value?: string): { short: string; title: string } {
  if (!value) return { short: "—", title: "" }
  const d = new Date(value)
  if (Number.isNaN(d.getTime())) return { short: "—", title: "" }
  const today = d.toDateString() === new Date().toDateString()
  return { short: today ? hms.format(d) : `${dayShort.format(d)} ${hms.format(d)}`, title: full.format(d) }
}

/** Bytes as "12,3 Mo" (1 Mo = 1 000 000 octets, like the settings). */
export function formatMb(bytes?: number): string {
  const mb = (bytes ?? 0) / 1_000_000
  return `${mb.toLocaleString("fr-FR", { maximumFractionDigits: mb < 10 ? 1 : 0 })} Mo`
}

/** Short size: "812 o", "4,2 Ko", "1,3 Mo". */
export function formatSize(bytes?: number): string {
  const b = bytes ?? 0
  if (b < 1000) return `${b} o`
  if (b < 1_000_000) return `${(b / 1000).toLocaleString("fr-FR", { maximumFractionDigits: 1 })} Ko`
  return formatMb(b)
}

/** Percent 0..100 as "72 %" ("4,5 %" under 10). */
export function formatPct(p?: number | null): string {
  if (p === undefined || p === null || !Number.isFinite(p)) return "—"
  return `${p.toLocaleString("fr-FR", { maximumFractionDigits: p > 0 && p < 10 ? 1 : 0 })} %`
}

/** Compact count for axis ticks: 950, 1,2 k, 12 k, 1,5 M. */
export function compact(n: number): string {
  return new Intl.NumberFormat("fr-FR", { notation: "compact", maximumFractionDigits: 1 }).format(n)
}
