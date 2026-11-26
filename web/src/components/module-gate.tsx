import type * as React from "react"
import { Link, useLocation } from "react-router"
import { PowerOff, Settings } from "lucide-react"
import { PageHeader } from "@/components/page-header"
import { BlockSpinner } from "@/components/spinner"
import { Button } from "@/components/ui/button"
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"
import { useCurrentUser } from "@/hooks/use-session"
import { useModules, type ModuleName } from "@/lib/modules"
import { findNavItem } from "@/lib/nav"
import { can } from "@/lib/permissions"

const moduleLabel: Record<ModuleName, string> = {
  blocking: "Le blocage des publicités et traqueurs",
  dnssec: "La signature DNSSEC des zones",
}

/**
 * Route guard for pages of an optional module: a direct link to a page whose
 * module is off shows a short card (with a link to turn it on, for admins).
 */
export function RequireModule({ module, children }: { module: ModuleName; children: React.ReactNode }) {
  const modules = useModules()
  const user = useCurrentUser()
  const { pathname } = useLocation()
  if (modules.pending) return <BlockSpinner />
  if (modules[module]) return <>{children}</>
  const item = findNavItem(pathname)
  const isAdmin = can(user?.role, "admin")
  return (
    <>
      <PageHeader title={item?.title ?? "Module"} />
      <Card className="max-w-xl" data-testid="module-off">
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <PowerOff className="size-4 text-muted-foreground" /> Module désactivé
          </CardTitle>
          <CardDescription>
            {moduleLabel[module]} n'est pas activé sur ce serveur.
            {isAdmin ? " Vous pouvez l'activer sans redémarrage." : " Demandez à un administrateur de l'activer."}
          </CardDescription>
        </CardHeader>
        {isAdmin && (
          <CardContent>
            <Button asChild variant="outline">
              <Link to="/settings?tab=modules">
                <Settings /> Paramètres &gt; Modules
              </Link>
            </Button>
          </CardContent>
        )}
      </Card>
    </>
  )
}
