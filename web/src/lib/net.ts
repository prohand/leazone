/* Small address helpers used for client-side form checks (the server validates again). */

export function isIPv4(v: string): boolean {
  const m = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.exec(v)
  return !!m && m.slice(1).every((o) => Number(o) <= 255 && String(Number(o)) === o)
}

/**
 * The 8 groups of an IPv6 address (numbers), or null when it is not one.
 * Accepts "::" once and an embedded IPv4 at the end (::ffff:192.0.2.1).
 */
function ipv6Groups(v: string): number[] | null {
  if (!v.includes(":") || !/^[0-9a-fA-F:.]+$/.test(v)) return null
  const halves = v.split("::")
  if (halves.length > 2) return null // ":::" or two "::"
  const parse = (s: string, last: boolean): number[] | null => {
    if (s === "") return []
    const out: number[] = []
    const parts = s.split(":")
    for (let i = 0; i < parts.length; i++) {
      const g = parts[i]
      if (last && i === parts.length - 1 && g.includes(".")) {
        if (!isIPv4(g)) return null
        const o = g.split(".").map(Number)
        out.push((o[0] << 8) | o[1], (o[2] << 8) | o[3])
      } else if (/^[0-9a-fA-F]{1,4}$/.test(g)) out.push(parseInt(g, 16))
      else return null // empty group: a single ":" at the start or end, or "::" split badly
    }
    return out
  }
  if (halves.length === 1) {
    const g = parse(v, true)
    return g && g.length === 8 ? g : null
  }
  const head = parse(halves[0], false)
  const tail = parse(halves[1], true)
  if (!head || !tail || head.length + tail.length > 7) return null
  return [...head, ...Array<number>(8 - head.length - tail.length).fill(0), ...tail]
}

export const isIPv6 = (v: string): boolean => ipv6Groups(v) !== null

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

/**
 * Reverse name for PTR lookups:
 * 192.168.1.10 -> 10.1.168.192.in-addr.arpa,
 * fd00::10 -> 0.1.0.0.(…).0.0.d.f.ip6.arpa (32 nibbles of the expanded address).
 */
export function reverseName(ip: string): string | null {
  if (isIPv4(ip)) return ip.split(".").reverse().join(".") + ".in-addr.arpa"
  const groups = ipv6Groups(ip)
  if (!groups) return null
  const nibbles = groups.map((g) => g.toString(16).padStart(4, "0")).join("")
  return nibbles.split("").reverse().join(".") + ".ip6.arpa"
}

/** Host of a URL, without IPv6 brackets; null when it does not parse. */
export function urlHost(url: string): string | null {
  try {
    return new URL(url).hostname.replace(/^\[|\]$/g, "")
  } catch {
    return null
  }
}
