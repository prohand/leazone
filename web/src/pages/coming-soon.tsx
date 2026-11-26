import { useLocation } from "react-router"
import { Construction } from "lucide-react"
import { EmptyState } from "@/components/empty-state"
import { PageHeader } from "@/components/page-header"
import { findNavItem } from "@/lib/nav"

/** Placeholder for pages that arrive in a later phase. */
export default function ComingSoonPage() {
  const { pathname } = useLocation()
  const item = findNavItem(pathname)
  return (
    <>
      <PageHeader title={item?.title ?? "Page"} />
      <EmptyState
        icon={item?.icon ?? Construction}
        title="Disponible dans une prochaine version"
        description="Cette page n'est pas encore prête. Elle arrivera avec une prochaine mise à jour de Leazone."
      />
    </>
  )
}
