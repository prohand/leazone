/* Small address helpers used for client-side form checks (the server validates again). */

export function isIPv4(v: string): boolean {
  const m = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.exec(v)
  return !!m && m.slice(1).every((o) => Number(o) <= 255 && String(Number(o)) === o)
}

export function isIPv6(v: string): boolean {
  if (!v.includes(":") || !/^[0-9a-fA-F:.]+$/.test(v)) return false
  if ((v.match(/::/g) ?? []).length > 1) return false
  const parts = v.split(":")
  const last = parts[parts.length - 1]
  const hasV4 = last.includes(".")
  if (hasV4 && !isIPv4(last)) return false
  const groups = hasV4 ? parts.slice(0, -1) : parts
  if (!groups.every((g) => g === "" || /^[0-9a-fA-F]{1,4}$/.test(g))) return false
  const count = groups.filter(Boolean).length + (hasV4 ? 2 : 0)
  return v.includes("::") ? count < 8 : count === 8
}

export const isIP = (v: string) => isIPv4(v) || isIPv6(v)

export function isCidr(v: string): boolean {
  const i = v.lastIndexOf("/")
  if (i < 0) return false
  const ip = v.slice(0, i)
  const bits = v.slice(i + 1)
  if (!/^\d{1,3}$/.test(bits)) return false
  if (isIPv4(ip)) return Number(bits) <= 32
  if (isIPv6(ip)) return Number(bits) <= 128
  return false
}

/** Split a textarea into trimmed non-empty lines. */
export const lines = (text: string) =>
  text
    .split(/\r?\n/)
    .map((l) => l.trim())
    .filter(Boolean)

/** 192.168.1.10 -> 10.1.168.192.in-addr.arpa (for PTR lookups). */
export function reverseName(ip: string): string | null {
  if (!isIPv4(ip)) return null
  return ip.split(".").reverse().join(".") + ".in-addr.arpa"
}

/** Host of a URL, without IPv6 brackets; null when it does not parse. */
export function urlHost(url: string): string | null {
  try {
    return new URL(url).hostname.replace(/^\[|\]$/g, "")
  } catch {
    return null
  }
}
