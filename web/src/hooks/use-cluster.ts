import { useQuery } from "@tanstack/react-query"
import { clusterQuery } from "@/api/queries"
import type { ClusterView } from "@/api/types"
import { useCurrentUser } from "@/hooks/use-session"
import { can, type Action } from "@/lib/permissions"

/** Cluster state, shared with the read-only banner (polled every 10 s). */
export function useClusterView() {
  return useQuery(clusterQuery)
}

export type Writability = {
  /** Config changes are accepted by this node. */
  writable: boolean
  /** This node is a cluster member that is not the primary. */
  secondary: boolean
  /** Short explanation for tooltips. */
  hint: string
  /** Server explanation (frozen config, quorum lost...). */
  reason: string
  /** UI address of the primary, when known. */
  primaryUrl: string
  view?: ClusterView
}

export const READ_ONLY_HINT = "Lecture seule sur le nœud secondaire"

/** Pure helper (also used outside React). */
export function writabilityOf(view?: ClusterView): Writability {
  // Unknown (loading, error, old server) = writable: the server enforces it anyway.
  const writable = !view || !view.enabled || view.writable !== false
  const secondary = !!view?.enabled && view.role !== "primary"
  const reason = view?.readOnlyReason ?? ""
  return {
    writable,
    secondary,
    hint: writable ? "" : secondary ? READ_ONLY_HINT : reason ? `Lecture seule : ${reason}` : "Configuration en lecture seule",
    reason,
    primaryUrl: safeUrl(view?.primaryUrl),
    view,
  }
}

/** Whether this node currently accepts config changes (cluster secondary = no). */
export function useWritable(): Writability {
  const { data } = useClusterView()
  return writabilityOf(data)
}

/**
 * Permission checks for the current user on this node:
 * - `can(action)`: role allows it AND the node accepts the change
 *   (config changes are refused on a cluster secondary);
 * - `allowed(action)`: role only, to show a disabled control with a hint.
 */
export function usePermissions() {
  const role = useCurrentUser()?.role
  const w = useWritable()
  return {
    role,
    ...w,
    can: (a: Action) => can(role, a) && (w.writable || isLocalAction(a)),
    allowed: (a: Action) => can(role, a),
  }
}

/** Actions that do not change the replicated configuration (work on every node). */
export function isLocalAction(a: Action): boolean {
  return a === "read" || a === "leases.release" || a === "cache.flush"
}

/** Only http(s) URLs may be opened from a server value. */
export function safeUrl(u?: string): string {
  if (!u) return ""
  try {
    const url = new URL(u, window.location.href)
    return url.protocol === "https:" || url.protocol === "http:" ? url.href : ""
  } catch {
    return ""
  }
}
