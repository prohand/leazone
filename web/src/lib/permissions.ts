import type { Role } from "@/api/types"

/*
 * Client-side mirror of the role table (PLAN §4). The server enforces it;
 * the UI only uses it to hide what the user cannot do. Inside the app, prefer
 * usePermissions() (hooks/use-cluster): it also says no to config changes on
 * a read-only cluster node.
 */
export type Action =
  | "read"
  | "records.write" // DNS records, leases, reservations
  | "leases.write" // same right as records.write: reservations
  | "leases.release" // same right as records.write; local to the node (works on a secondary)
  | "cache.flush" // same right as records.write; local to the node
  | "blocking.refresh" // same right as config.write; downloads the lists on this node only
  | "config.write" // zones, forwarders, scopes, interfaces, blocking (lists, rules, pause, policies), DNSSEC signing
  | "admin" // users, HA, settings, modules, backup, DNSSEC key export

const matrix: Record<Role, ReadonlySet<Action>> = {
  admin: new Set<Action>(["read", "records.write", "leases.write", "leases.release", "cache.flush", "blocking.refresh", "config.write", "admin"]),
  operator: new Set<Action>(["read", "records.write", "leases.write", "leases.release", "cache.flush"]),
  readonly: new Set<Action>(["read"]),
}

export function can(role: Role | undefined, action: Action): boolean {
  if (!role) return false
  return matrix[role]?.has(action) ?? false
}

export const roleLabel: Record<Role, string> = {
  admin: "Administrateur",
  operator: "Opérateur",
  readonly: "Lecture seule",
}
