import type * as React from "react"
import { Lock } from "lucide-react"
import { EmptyState } from "@/components/empty-state"
import { useCurrentUser } from "@/hooks/use-session"
import { can } from "@/lib/permissions"

export function RequireAdmin({ children }: { children: React.ReactNode }) {
  const user = useCurrentUser()
  if (!can(user?.role, "admin")) {
    return (
      <EmptyState
        icon={Lock}
        title="Accès réservé aux administrateurs"
        description="Votre rôle ne permet pas d'ouvrir cette page."
      />
    )
  }
  return <>{children}</>
}
