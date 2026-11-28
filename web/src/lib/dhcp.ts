import type { DhcpOptionType, LeaseState, Scope, ScopeInput, ScopeMode } from "@/api/types"
import { isIPv4 } from "./net"

/* DHCP labels and small IPv4 helpers (client-side hints only; the server validates). */

export const modeLabel: Record<ScopeMode, string> = {
  direct: "Direct",
  relay: "Relais",
  both: "Les deux",
  none: "Inactif",
}

export const modeHelp: Record<ScopeMode, string> = {
  direct: "Leazone répond lui-même sur une interface du VLAN.",
  relay: "Le routeur relaie les demandes (ip helper-address).",
  both: "En direct sur l'interface et par un relais.",
  none: "Aucun mode choisi : l'étendue ne sert aucun client.",
}

export const leaseStateLabel: Record<LeaseState, string> = {
  offered: "offert",
  bound: "actif",
  released: "libéré",
  expired: "expiré",
  declined: "refusé",
}

export const leaseStates: LeaseState[] = ["bound", "offered", "declined", "released", "expired"]

export const optionTypes: { value: DhcpOptionType; label: string; placeholder: string }[] = [
  { value: "ip", label: "IP", placeholder: "192.168.20.5" },
  { value: "ips", label: "Liste d'IP", placeholder: "10.0.0.1, 10.0.0.2" },
  { value: "string", label: "Texte", placeholder: "pxelinux.0" },
  { value: "u8", label: "Entier 8 bits", placeholder: "0 à 255" },
  { value: "u16", label: "Entier 16 bits", placeholder: "0 à 65535" },
  { value: "u32", label: "Entier 32 bits", placeholder: "0 à 4294967295" },
  { value: "bool", label: "Oui / non", placeholder: "true ou false" },
  { value: "hex", label: "Hexadécimal", placeholder: "01:02:0a" },
]

/** Value check of a custom option, by type. Returns an error message or undefined. */
export function checkOptionValue(type: DhcpOptionType, value: string): string | undefined {
  const v = value.trim()
  if (!v) return "Obligatoire."
  const int = (max: number) => (/^\d+$/.test(v) && Number(v) <= max ? undefined : `Entier entre 0 et ${max}.`)
  switch (type) {
    case "ip":
      return isIPv4(v) ? undefined : "Adresse IPv4 attendue."
    case "ips":
      return v.split(",").every((x) => isIPv4(x.trim())) ? undefined : "Adresses IPv4 séparées par des virgules."
    case "u8":
      return int(255)
    case "u16":
      return int(65535)
    case "u32":
      return int(4294967295)
    case "bool":
      return v === "true" || v === "false" ? undefined : "true ou false."
    case "hex":
      return /^[0-9a-fA-F]{2}([:]?[0-9a-fA-F]{2})*$/.test(v) ? undefined : "Octets en hexadécimal, ex. : 01:02:0a."
  }
  return undefined
}

// ---- IPv4 arithmetic ----

export function ipToInt(ip: string): number | null {
  if (!isIPv4(ip)) return null
  return ip.split(".").reduce((acc, o) => acc * 256 + Number(o), 0)
}

export function intToIp(n: number): string {
  return [24, 16, 8, 0].map((s) => Math.floor(n / 2 ** s) % 256).join(".")
}

export type Net4 = { base: number; prefix: number; size: number; broadcast: number }

/** Parse an IPv4 CIDR; the host bits are cleared (192.168.20.5/24 -> 192.168.20.0/24). */
export function parseNet4(cidr: string): Net4 | null {
  const m = /^(.+)\/(\d{1,2})$/.exec(cidr.trim())
  if (!m) return null
  const ip = ipToInt(m[1])
  const prefix = Number(m[2])
  if (ip === null || prefix > 32) return null
  const size = 2 ** (32 - prefix)
  const base = Math.floor(ip / size) * size
  return { base, prefix, size, broadcast: base + size - 1 }
}

export const net4String = (n: Net4) => `${intToIp(n.base)}/${n.prefix}`

export function netContains(n: Net4 | null, ip: string): boolean {
  const v = ipToInt(ip)
  return !!n && v !== null && v >= n.base && v <= n.broadcast
}

/** Dynamic range proposed for a network: .100-.199 for a /24 or larger, upper half otherwise. */
export function suggestRange(cidr: string): { start: string; end: string } | null {
  const n = parseNet4(cidr)
  if (!n || n.prefix > 30) return null
  if (n.size >= 256) return { start: intToIp(n.base + 100), end: intToIp(n.base + 199) }
  return { start: intToIp(n.base + n.size / 2), end: intToIp(n.broadcast - 1) }
}

/** Prefix lengths the server accepts for a scope (dhcpconf.validate). */
export const SCOPE_MIN_PREFIX = 8
export const SCOPE_MAX_PREFIX = 30
/** Largest distributed range (dhcpconf.MaxScopeSize). */
export const MAX_SCOPE_SIZE = 65536
/** Lease time bounds, in seconds (dhcpconf.validate). */
export const MIN_LEASE_SECONDS = 60
export const MAX_LEASE_SECONDS = 365 * 86400

/** True when ip is a host address of n: inside the network, but neither its network address nor its broadcast. */
export function netHostContains(n: Net4 | null, ip: string): boolean {
  const v = ipToInt(ip)
  return !!n && v !== null && v > n.base && v < n.broadcast
}

/**
 * Reverse zones the server creates for a network (port of dnsconf.ReverseZonesFor):
 * one per /24 for /17 to /32, one per /16 for /9 to /16, else the /8.
 * 192.168.0.0/20 -> 16 zones, 0.168.192.in-addr.arpa … 15.168.192.in-addr.arpa.
 */
export function reverseZonesOf(cidr: string): string[] {
  const n = parseNet4(cidr)
  if (!n) return []
  const step = n.prefix <= 8 ? 8 : n.prefix <= 16 ? 16 : 24
  const zoneSize = 2 ** (32 - step)
  const first = Math.floor(n.base / zoneSize) * zoneSize
  const count = n.prefix >= step ? 1 : 2 ** (step - n.prefix)
  const out: string[] = []
  for (let i = 0; i < count; i++) {
    const octets = intToIp(first + i * zoneSize).split(".")
    out.push(octets.slice(0, step / 8).reverse().join(".") + ".in-addr.arpa")
  }
  return out
}

/** "a.in-addr.arpa", "a et b", or "first … last (16 zones)". */
export function reverseZonesSummary(zones: string[]): string {
  if (zones.length <= 2) return zones.join(" et ")
  return `${zones[0]} … ${zones[zones.length - 1]} (${zones.length} zones)`
}

/**
 * Option codes the server refuses in custom options (dhcpconf reservedCodes):
 * they are set by dedicated fields or by the protocol itself. Value = what to do instead.
 */
export const reservedOptionCodes: Record<number, string> = {
  1: "le masque est déduit du champ Réseau",
  3: "utilisez le champ Passerelle",
  6: "utilisez le champ Serveurs DNS",
  15: "utilisez le champ Domaine",
  42: "utilisez le champ Serveurs NTP",
  51: "utilisez le champ Durée du bail",
  50: "elle fait partie du protocole DHCP",
  53: "elle fait partie du protocole DHCP",
  54: "elle fait partie du protocole DHCP",
  55: "elle fait partie du protocole DHCP",
  58: "elle fait partie du protocole DHCP",
  59: "elle fait partie du protocole DHCP",
  61: "elle fait partie du protocole DHCP",
  82: "elle est ajoutée par les relais",
}

/** "L'option 3 est gérée par Leazone : utilisez le champ Passerelle." or undefined. */
export function reservedOptionMessage(code: number): string | undefined {
  const why = reservedOptionCodes[code]
  return why ? `L'option ${code} est gérée par Leazone : ${why}.` : undefined
}

/** "aa-bb-cc-dd-ee-ff", "AABBCCDDEEFF"... -> "aa:bb:cc:dd:ee:ff"; null when not a MAC. */
export function normalizeMac(v: string): string | null {
  const hex = v.trim().replace(/[:\-.\s]/g, "").toLowerCase()
  if (!/^[0-9a-f]{12}$/.test(hex)) return null
  return hex.match(/../g)!.join(":")
}

/** Scope -> body for PUT (drops read-only fields). */
export function scopeInputOf(s: Scope, patch: Partial<ScopeInput> = {}): ScopeInput {
  const {
    id: _id,
    vlanName: _vlanName,
    mode: _mode,
    usage: _usage,
    reverseZones: _rz,
    createdAt: _c,
    updatedAt: _u,
    ...rest
  } = s
  return { ...rest, ...patch }
}

/** "VLAN 20 · Invités", "VLAN 20", or "Sans VLAN". */
export function vlanLabel(vlanId?: number | null, name?: string | null): string {
  if (vlanId === null || vlanId === undefined) return "Sans VLAN"
  return name ? `VLAN ${vlanId} · ${name}` : `VLAN ${vlanId}`
}

export const fmtInt = new Intl.NumberFormat("fr-FR")

export function formatPercent(p?: number | null): string {
  if (p === null || p === undefined || !Number.isFinite(p)) return "—"
  return `${p < 10 && p > 0 ? p.toFixed(1).replace(".", ",") : Math.round(p)} %`
}

/** French count: 0 and 1 take the singular ("0 bail actif", "1 bail actif", "3 baux actifs"). */
export const countLabel = (n: number, singular: string, plural: string) => `${fmtInt.format(n)} ${n >= 2 ? plural : singular}`

/** "0 bail actif", "1 bail actif", "3 baux actifs". */
export const activeLeasesLabel = (n: number) => countLabel(n, "bail actif", "baux actifs")
