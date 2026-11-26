import type { ClusterRole } from "@/api/types"
import { Badge } from "@/components/ui/badge"
import { cn } from "@/lib/utils"

export const clusterRoleLabel: Record<ClusterRole, string> = {
  standalone: "nœud seul",
  joining: "en démarrage",
  secondary: "secondaire",
  primary: "primaire",
  isolated: "isolé",
  incompatible: "incompatible",
  offline: "hors ligne",
}

const roleTone: Record<ClusterRole, string> = {
  primary: "border-success/40 bg-success/15 text-success",
  secondary: "border-brand/40 bg-brand/15 text-brand",
  isolated: "border-warning/50 bg-warning/15 text-warning",
  incompatible: "border-destructive/40 bg-destructive/10 text-destructive",
  joining: "border-border text-muted-foreground",
  offline: "border-border bg-muted text-muted-foreground",
  standalone: "border-border text-muted-foreground",
}

/** Colored badge for a cluster role (primaire green, secondaire blue...). */
export function ClusterRoleBadge({ role, className }: { role?: ClusterRole; className?: string }) {
  const r = role ?? "joining"
  return (
    <Badge variant="outline" data-role={r} className={cn(roleTone[r], className)}>
      {clusterRoleLabel[r] ?? r}
    </Badge>
  )
}
