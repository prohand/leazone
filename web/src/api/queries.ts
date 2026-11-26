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
