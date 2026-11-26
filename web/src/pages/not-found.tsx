import { Link } from "react-router"
import { Compass } from "lucide-react"
import { EmptyState } from "@/components/empty-state"
import { Button } from "@/components/ui/button"

export default function NotFoundPage() {
  return (
    <EmptyState
      icon={Compass}
      title="Page introuvable"
      description="Cette adresse n'existe pas."
      action={
        <Button asChild variant="outline">
          <Link to="/">Retour au tableau de bord</Link>
        </Button>
      }
    />
  )
}
