import { useQuery, useQueryClient } from "@tanstack/react-query"
import { useNavigate } from "react-router"
import { api } from "@/api/client"
import { qk, sessionQuery } from "@/api/queries"
import type { SessionState } from "@/api/types"

export function useSession() {
  return useQuery(sessionQuery)
}

/** Current authenticated user (only meaningful inside the app layout). */
export function useCurrentUser() {
  const { data } = useSession()
  return data?.user
}

/** Store a SessionState returned by an auth endpoint (login, MFA, step-up...). */
export function useApplySession() {
  const qc = useQueryClient()
  return (s: SessionState | undefined | null) => {
    if (s && s.state) qc.setQueryData(qk.session, s)
    else void qc.invalidateQueries({ queryKey: qk.session })
  }
}

export function useLogout() {
  const qc = useQueryClient()
  const navigate = useNavigate()
  return async () => {
    try {
      await api.post("/auth/logout")
    } catch {
      // already logged out or server unreachable: continue
    }
    qc.removeQueries({ predicate: (q) => q.queryKey[0] !== "session" && q.queryKey[0] !== "system-info" })
    await qc.resetQueries({ queryKey: qk.session })
    navigate("/login", { replace: true })
  }
}
