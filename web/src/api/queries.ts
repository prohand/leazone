import { queryOptions } from "@tanstack/react-query"
import { api } from "./client"

/* Shared query keys / options. Pages use these with useQuery. */

export const qk = {
  session: ["session"] as const,
  systemInfo: ["system-info"] as const,
  me: ["me"] as const,
  passkeys: ["me", "passkeys"] as const,
  totp: ["me", "totp"] as const,
  recovery: ["me", "recovery-codes"] as const,
  sessions: ["me", "sessions"] as const,
  tokens: ["me", "tokens"] as const,
  users: ["users"] as const,
  securitySettings: ["settings", "security"] as const,
  tls: ["settings", "tls"] as const,
  audit: (q: string, action: string) => ["audit", q, action] as const,
  interfaces: ["interfaces"] as const,
  dns: ["dns"] as const,
  dnsSettings: ["dns", "settings"] as const,
  dnsStatus: ["dns", "status"] as const,
  zones: ["dns", "zones"] as const,
  zone: (id: string) => ["dns", "zones", id] as const,
  records: (id: string) => ["dns", "zones", id, "records"] as const,
  forwarders: ["dns", "forwarders"] as const,
  vlans: ["vlans"] as const,
  dhcp: ["dhcp"] as const,
  dhcpStatus: ["dhcp", "status"] as const,
  scopes: ["dhcp", "scopes"] as const,
  reservations: (scope?: string) => ["dhcp", "reservations", scope ?? ""] as const,
  leasesAll: ["dhcp", "leases"] as const,
  leases: (f: LeaseFilters) => ["dhcp", "leases", f] as const,
  cluster: ["cluster"] as const,
  clusterSettings: ["cluster", "settings"] as const,
  clusterConflicts: ["cluster", "conflicts"] as const,
  modules: ["settings", "modules"] as const,
  blocking: ["blocking"] as const,
  blockingStatus: ["blocking", "status"] as const,
  blockingSettings: ["blocking", "settings"] as const,
  blockLists: ["blocking", "lists"] as const,
  blockRules: ["blocking", "rules"] as const,
  blockPolicies: ["blocking", "policies"] as const,
  dnssec: ["dnssec"] as const,
  dnssecZones: ["dnssec", "zones"] as const,
  dnssecZone: (id: string) => ["dnssec", "zones", id] as const,
  dashboard: ["dashboard"] as const,
  logs: ["logs"] as const,
  dnsLogs: (f: object) => ["logs", "dns", f] as const,
  dhcpLogs: (f: object) => ["logs", "dhcp", f] as const,
  logSettings: ["logs", "settings"] as const,
  logStatus: ["logs", "status"] as const,
  backups: ["backups"] as const,
}

export type LeaseFilters = {
  scope?: string
  vlan?: number
  state?: "offered" | "bound" | "released" | "expired" | "declined"
  all?: boolean
}

export const sessionQuery = queryOptions({
  queryKey: qk.session,
  queryFn: () => api.get("/auth/session"),
  staleTime: 60_000,
  // Coming back to the tab after the idle timeout should land on the login page.
  refetchOnWindowFocus: true,
  retry: 1,
})

export const systemInfoQuery = queryOptions({
  queryKey: qk.systemInfo,
  queryFn: () => api.get("/system/info"),
  staleTime: 5 * 60_000,
})

export const meQuery = queryOptions({
  queryKey: qk.me,
  queryFn: () => api.get("/me"),
  staleTime: 30_000,
})

// ---- Phase 2: interfaces and DNS ----

export const interfacesQuery = queryOptions({
  queryKey: qk.interfaces,
  queryFn: () => api.get("/interfaces"),
  // Hot-added VLANs show up without a reload.
  refetchInterval: 5_000,
})

export const dnsStatusQuery = queryOptions({
  queryKey: qk.dnsStatus,
  queryFn: () => api.get("/dns/status"),
  refetchInterval: 10_000,
})

export const dnsSettingsQuery = queryOptions({
  queryKey: qk.dnsSettings,
  queryFn: () => api.get("/dns/settings"),
})

export const zonesQuery = queryOptions({
  queryKey: qk.zones,
  queryFn: () => api.get("/dns/zones"),
})

export const zoneQuery = (id: string) =>
  queryOptions({
    queryKey: qk.zone(id),
    queryFn: () => api.get("/dns/zones/{id}", { params: { id } }),
  })

export const recordsQuery = (id: string) =>
  queryOptions({
    queryKey: qk.records(id),
    queryFn: () => api.get("/dns/zones/{id}/records", { params: { id } }),
  })

export const forwardersQuery = queryOptions({
  queryKey: qk.forwarders,
  queryFn: () => api.get("/dns/forwarders"),
  // Health changes on its own.
  refetchInterval: 15_000,
})

// ---- Phase 3: DHCP and VLANs ----

export const vlansQuery = queryOptions({
  queryKey: qk.vlans,
  queryFn: () => api.get("/vlans"),
  refetchInterval: 10_000,
})

export const dhcpStatusQuery = queryOptions({
  queryKey: qk.dhcpStatus,
  queryFn: () => api.get("/dhcp/status"),
  refetchInterval: 15_000,
})

export const scopesQuery = queryOptions({
  queryKey: qk.scopes,
  queryFn: () => api.get("/dhcp/scopes"),
  // Usage moves with the leases.
  refetchInterval: 10_000,
})

export const reservationsQuery = (scope?: string) =>
  queryOptions({
    queryKey: qk.reservations(scope),
    queryFn: () => api.get("/dhcp/reservations", { query: scope ? { scope } : undefined }),
  })

export const leasesQuery = (f: LeaseFilters) =>
  queryOptions({
    queryKey: qk.leases(f),
    queryFn: () =>
      api.get("/dhcp/leases", {
        query: { scope: f.scope, vlan: f.vlan, state: f.state, all: f.all ? true : undefined },
      }),
    // "Real time" view: clients come and go.
    refetchInterval: 5_000,
  })

// ---- Phase 4: high availability ----

/**
 * Cluster state. Shared by the read-only banner (every page, 10 s; 60 s
 * without HA) and the Cluster page, which adds its own faster refresh (HA on)
 * while it is open.
 */
export const clusterQuery = queryOptions({
  queryKey: qk.cluster,
  queryFn: () => api.get("/cluster"),
  // Single node (HA not configured): the state hardly changes, poll slowly.
  refetchInterval: (q) => (q.state.data && !q.state.data.enabled ? 60_000 : 10_000),
  // An old backend without /cluster must not break the app (treated as a single node).
  retry: false,
})

export const clusterSettingsQuery = queryOptions({
  queryKey: qk.clusterSettings,
  queryFn: () => api.get("/cluster/settings"),
})

export const clusterConflictsQuery = queryOptions({
  queryKey: qk.clusterConflicts,
  queryFn: () => api.get("/cluster/conflicts"),
})

// ---- Phase 5: optional modules ----

/**
 * Optional modules state (any role). Shared by the sidebar, ⌘K, routes and
 * the dashboard; refreshed now and then so a change made by another admin
 * (or on the other node) shows up without a reload.
 */
export const modulesQuery = queryOptions({
  queryKey: qk.modules,
  queryFn: () => api.get("/settings/modules"),
  staleTime: 30_000,
  refetchInterval: 60_000,
  // An old backend without modules: treated as "all off".
  retry: false,
})

export const blockingStatusQuery = queryOptions({
  queryKey: qk.blockingStatus,
  queryFn: () => api.get("/blocking/status"),
  // Live counters and pause countdown.
  refetchInterval: 5_000,
})

export const blockingSettingsQuery = queryOptions({
  queryKey: qk.blockingSettings,
  queryFn: () => api.get("/blocking/settings"),
})

export const blockListsQuery = queryOptions({
  queryKey: qk.blockLists,
  queryFn: () => api.get("/blocking/lists"),
  // Downloads finish in the background (a new list is fetched at once).
  refetchInterval: 15_000,
})

/** Both kinds at once: the page splits them (and marks allowed domains in the top 10). */
export const blockRulesQuery = queryOptions({
  queryKey: qk.blockRules,
  queryFn: () => api.get("/blocking/rules"),
})

export const blockPoliciesQuery = queryOptions({
  queryKey: qk.blockPolicies,
  queryFn: () => api.get("/blocking/policies"),
})

export const dnssecZonesQuery = queryOptions({
  queryKey: qk.dnssecZones,
  queryFn: () => api.get("/dnssec/zones"),
})

export const dnssecZoneQuery = (id: string) =>
  queryOptions({
    queryKey: qk.dnssecZone(id),
    queryFn: () => api.get("/dnssec/zones/{id}", { params: { id } }),
  })

// ---- Phase 6: dashboard, logs, backups ----

/** Dashboard of this node. Fed by the SSE stream (hooks/use-dashboard); polled only as a fallback. */
export const dashboardQuery = queryOptions({
  queryKey: qk.dashboard,
  queryFn: () => api.get("/dashboard"),
})

export const logStatusQuery = queryOptions({
  queryKey: qk.logStatus,
  queryFn: () => api.get("/logs/status"),
  refetchInterval: 30_000,
})

export const logSettingsQuery = queryOptions({
  queryKey: qk.logSettings,
  queryFn: () => api.get("/logs/settings"),
})

export const backupsQuery = queryOptions({
  queryKey: qk.backups,
  queryFn: () => api.get("/backups"),
})
