import type { ForwarderProtocol, InterfaceType, RecordType } from "@/api/types"

/** "86400" -> "1 jour", "5400" -> "1 h 30 min". */
export function humanDuration(seconds: number): string {
  if (!Number.isFinite(seconds) || seconds < 0) return ""
  if (seconds === 0) return "0 s"
  const units: [number, string, string][] = [
    [604800, "semaine", "semaines"],
    [86400, "jour", "jours"],
    [3600, "h", "h"],
    [60, "min", "min"],
    [1, "s", "s"],
  ]
  const parts: string[] = []
  let rest = Math.floor(seconds)
  for (const [size, one, many] of units) {
    const n = Math.floor(rest / size)
    if (n > 0) {
      parts.push(`${n} ${n > 1 ? many : one}`)
      rest -= n * size
    }
    if (parts.length === 2) break
  }
  return parts.join(" ")
}

export const recordTypes: RecordType[] = ["A", "AAAA", "CNAME", "MX", "TXT", "SRV", "PTR", "NS"]

export const recordTypeHelp: Record<RecordType, string> = {
  A: "Adresse IPv4 d'un nom.",
  AAAA: "Adresse IPv6 d'un nom.",
  CNAME: "Alias vers un autre nom.",
  MX: "Serveur de messagerie du domaine.",
  TXT: "Texte libre (SPF, vérification de domaine…).",
  SRV: "Emplacement d'un service (port et serveur).",
  PTR: "Nom associé à une adresse IP (zone inverse).",
  NS: "Serveur DNS faisant autorité pour un nom.",
}

export const lookupTypes = ["A", "AAAA", "CNAME", "MX", "TXT", "SRV", "PTR", "NS", "SOA"] as const

export const interfaceTypeLabel: Record<InterfaceType, string> = {
  physical: "Physique",
  vlan: "VLAN",
  bond: "Agrégat",
  bridge: "Pont",
  loopback: "Boucle locale",
  virtual: "Virtuelle",
  other: "Autre",
}

export const protocolLabel: Record<ForwarderProtocol, string> = {
  udp: "UDP",
  tcp: "TCP",
  dot: "DoT",
  doh: "DoH",
}

export const protocolLongLabel: Record<ForwarderProtocol, string> = {
  udp: "UDP (classique)",
  tcp: "TCP",
  dot: "DoT : DNS chiffré par TLS",
  doh: "DoH : DNS chiffré par HTTPS",
}

export const defaultPort: Record<ForwarderProtocol, number> = { udp: 53, tcp: 53, dot: 853, doh: 443 }

export function formatLatency(ms: number | undefined | null): string {
  if (ms === undefined || ms === null || !Number.isFinite(ms)) return ""
  return ms < 10 ? `${ms.toFixed(1).replace(".", ",")} ms` : `${Math.round(ms)} ms`
}

export function hitRate(hits = 0, misses = 0): number | null {
  const total = hits + misses
  return total > 0 ? hits / total : null
}

export const percent = (v: number) => `${Math.round(v * 100)} %`
