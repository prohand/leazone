import type { Role } from "@/api/types"

/*
 * Client-side mirror of the role table (PLAN §4). The server enforces it;
 * the UI only uses it to hide what the user cannot do.
 */
export type Action =
  | "read"
  | "records.write" // DNS records, leases, reservations
  | "config.write" // zones, forwarders, scopes, interfaces, modules
  | "admin" // users, HA, settings, backup, DNSSEC keys

const matrix: Record<Role, ReadonlySet<Action>> = {
  admin: new Set<Action>(["read", "records.write", "config.write", "admin"]),
  operator: new Set<Action>(["read", "records.write"]),
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
