import { ShieldCheck } from "lucide-react"
import { Badge } from "@/components/ui/badge"

export function SignedBadge({ enabled }: { enabled?: boolean }) {
  return enabled ? (
    <Badge variant="outline" className="border-success/40 text-success">
      <ShieldCheck /> signée
    </Badge>
  ) : (
    <Badge variant="outline" className="text-muted-foreground">
      non signée
    </Badge>
  )
}

export function DsPendingBadge() {
  return (
    <Badge variant="outline" className="border-warning/50 bg-warning/10 text-warning">
      DS en attente
    </Badge>
  )
}
