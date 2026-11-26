import { useQuery } from "@tanstack/react-query"
import { dnssecZonesQuery } from "@/api/queries"
import type { DnssecKeyState } from "@/api/types"
import { useModules } from "./modules"

export function algorithmLabel(a?: number): string {
  if (a === 13) return "ECDSA P-256"
  if (a === 15) return "Ed25519"
  return a ? `algorithme ${a}` : "—"
}

export const nsecLabel = { nsec: "NSEC", nsec3: "NSEC3" } as const

export const keyStateLabel: Record<DnssecKeyState, string> = {
  published: "publiée",
  active: "active",
  retired: "retirée",
  "ds-pending": "DS en attente",
}

export const keyStateClass: Record<DnssecKeyState, string> = {
  published: "border-brand/40 text-brand",
  active: "border-success/40 text-success",
  retired: "text-muted-foreground",
  "ds-pending": "border-warning/50 text-warning",
}

/** DNSSEC state of a DNS zone (for a badge), only when the module is on. */
export function useZoneDnssec(zoneId: string) {
  const { dnssec } = useModules()
  const q = useQuery({ ...dnssecZonesQuery, enabled: dnssec && !!zoneId, staleTime: 30_000 })
  return dnssec ? q.data?.items?.find((z) => z.zoneId === zoneId) : undefined
}
