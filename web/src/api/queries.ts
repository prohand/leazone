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
}

export const sessionQuery = queryOptions({
  queryKey: qk.session,
  queryFn: () => api.get("/auth/session"),
  staleTime: 60_000,
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
