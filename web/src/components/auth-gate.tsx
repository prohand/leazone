import type * as React from "react"
import { Navigate, useLocation, useSearchParams } from "react-router"
import { RefreshCw, WifiOff } from "lucide-react"
import type { SessionStateName } from "@/api/types"
import { Button } from "@/components/ui/button"
import { useSession } from "@/hooks/use-session"
import { errorMessage } from "@/lib/errors"
import { FullScreenSpinner } from "./spinner"

const AUTH_PAGES = ["/login", "/login/mfa", "/setup-mfa"]

/** Only allow internal, non-auth paths as redirect targets. */
export function safeNext(next: string | null | undefined): string {
  if (!next || !next.startsWith("/") || next.startsWith("//") || next.startsWith("/\\")) return "/"
  const pathname = next.split(/[?#]/)[0]
  if (AUTH_PAGES.includes(pathname)) return "/"
  return next
}

function targetFor(state: SessionStateName, next: string): string {
  const q = next !== "/" ? `?next=${encodeURIComponent(next)}` : ""
  switch (state) {
    case "anonymous":
      return `/login${q}`
    case "mfa_required":
      return `/login/mfa${q}`
    case "mfa_setup_required":
      return `/setup-mfa${q}`
    default:
      return next
  }
}

/**
 * Renders children only when the session is in the `allow` state.
 * Otherwise redirects to the page matching the current state, keeping
 * the originally requested page in `?next=`.
 */
export function AuthGate({ allow, children }: { allow: SessionStateName; children: React.ReactNode }) {
  const session = useSession()
  const location = useLocation()
  const [params] = useSearchParams()

  if (session.isPending) return <FullScreenSpinner />
  if (session.isError && !session.data) {
    return (
      <div className="flex min-h-svh flex-col items-center justify-center gap-4 p-6 text-center">
        <WifiOff className="size-8 text-muted-foreground" />
        <div>
          <p className="font-medium">Impossible de joindre le serveur</p>
          <p className="text-sm text-muted-foreground">{errorMessage(session.error)}</p>
        </div>
        <Button variant="outline" onClick={() => session.refetch()}>
          <RefreshCw /> Réessayer
        </Button>
      </div>
    )
  }

  const state = session.data.state
  if (state === allow) return <>{children}</>

  const next =
    allow === "authenticated" ? safeNext(location.pathname + location.search) : safeNext(params.get("next"))
  return <Navigate to={targetFor(state, next)} replace />
}
