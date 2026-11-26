import type { Role } from "@/api/types"
import { Badge } from "@/components/ui/badge"
import { roleLabel } from "@/lib/permissions"

export function RoleBadge({ role }: { role: Role }) {
  const variant = role === "admin" ? "default" : role === "operator" ? "secondary" : "outline"
  return <Badge variant={variant}>{roleLabel[role]}</Badge>
}
