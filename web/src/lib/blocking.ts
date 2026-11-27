import { useMutation, useQueryClient } from "@tanstack/react-query"
import { toast } from "sonner"
import { api } from "@/api/client"
import { qk } from "@/api/queries"
import type { BlockingStatus, BlockListFormat, BlockRuleKind, BlockTargetKind } from "@/api/types"
import { urlHost } from "./net"

export const fmtInt = new Intl.NumberFormat("fr-FR")
const hhmm = new Intl.DateTimeFormat("fr-FR", { hour: "2-digit", minute: "2-digit" })
const dayHhmm = new Intl.DateTimeFormat("fr-FR", { weekday: "long", hour: "2-digit", minute: "2-digit" })

/** "14:35", or "demain 14:35"-like ("jeudi 14:35") when not today. */
export function formatUntil(value?: string | null): string {
  if (!value) return ""
  const d = new Date(value)
  if (Number.isNaN(d.getTime())) return ""
  return d.toDateString() === new Date().toDateString() ? hhmm.format(d) : dayHhmm.format(d)
}

/** Blocked share: the server's percent, else computed. */
export function blockedPercent(s?: BlockingStatus): string {
  if (!s) return "—"
  const p = typeof s.percent === "number" ? s.percent : s.queries ? ((s.blocked ?? 0) / s.queries) * 100 : 0
  return `${p.toLocaleString("fr-FR", { maximumFractionDigits: p < 10 ? 1 : 0 })} %`
}

export const formatLabel: Record<BlockListFormat, string> = {
  auto: "Automatique",
  hosts: "hosts",
  domains: "domaines",
  adblock: "AdBlock",
}

export const targetKindLabel: Record<BlockTargetKind, string> = {
  interface: "Interface",
  vlan: "VLAN",
  network: "Réseau client",
}

export const pauseChoices = [
  { minutes: 5, label: "Pause 5 min" },
  { minutes: 60, label: "Pause 1 h" },
  { minutes: 1440, label: "Pause 24 h" },
] as const

/** Suggested public lists (one click in the "add a list" dialog). */
export const suggestedLists: { name: string; label: string; url: string; format: BlockListFormat }[] = [
  { name: "StevenBlack", label: "StevenBlack (hosts)", url: "https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts", format: "hosts" },
  { name: "OISD small", label: "OISD small (AdBlock)", url: "https://small.oisd.nl/", format: "adblock" },
  { name: "HaGeZi Light", label: "HaGeZi Light (domaines)", url: "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/domains/light.txt", format: "domains" },
]

const DOMAIN = /^(?=.{1,253}$)([a-z0-9_]([a-z0-9_-]{0,61}[a-z0-9_])?)(\.[a-z0-9_]([a-z0-9_-]{0,61}[a-z0-9_])?)*$/

/**
 * Domain typed by the user, cleaned up: lower case, no trailing dot, no
 * leading "*." (sub-domains are always included), host of a pasted URL.
 * Returns null when it is not a domain, or (with `multiLabel`) when it has a
 * single label ("com", "lan"): blocking it would block a whole TLD.
 */
export function cleanDomain(input: string, { multiLabel = false }: { multiLabel?: boolean } = {}): string | null {
  let v = input.trim().toLowerCase()
  if (/^[a-z][a-z0-9+.-]*:\/\//.test(v)) v = urlHost(v) ?? ""
  v = v.replace(/^\*\./, "").replace(/\.$/, "")
  if (multiLabel && !v.includes(".")) return null
  return DOMAIN.test(v) ? v : null
}

/** Pause (minutes > 0) or resume (0) blocking, with a toast. */
export function usePauseBlocking() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: (minutes: number) => api.post("/blocking/pause", { body: { minutes } }),
    onSuccess: (s, minutes) => {
      if (s) qc.setQueryData(qk.blockingStatus, s)
      void qc.invalidateQueries({ queryKey: qk.blockingStatus })
      if (minutes === 0) toast.success("Blocage repris.")
      else {
        const until = formatUntil(s?.pausedUntil ?? new Date(Date.now() + minutes * 60_000).toISOString())
        toast.success(`Blocage en pause jusqu'à ${until}.`)
      }
    },
  })
}

/**
 * Add a domain to the blacklist (deny) or whitelist (allow). `silent`: the
 * caller shows the errors itself (form), so no global error toast.
 */
export function useAddRule({ silent = false }: { silent?: boolean } = {}) {
  const qc = useQueryClient()
  return useMutation({
    meta: { silent },
    mutationFn: (body: { domain: string; kind: BlockRuleKind; comment?: string }) => api.post("/blocking/rules", { body }),
    onSuccess: (_r, v) => {
      void qc.invalidateQueries({ queryKey: qk.blockRules })
      void qc.invalidateQueries({ queryKey: qk.blockingStatus })
      toast.success(v.kind === "allow" ? `${v.domain} ajouté à la liste blanche.` : `${v.domain} ajouté à la liste noire.`)
    },
  })
}
