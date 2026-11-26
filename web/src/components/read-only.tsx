import type * as React from "react"
import { ExternalLink, Info, Lock, TriangleAlert } from "lucide-react"
import { Tooltip, TooltipContent, TooltipTrigger } from "@/components/ui/tooltip"
import { useClusterView, useWritable, writabilityOf } from "@/hooks/use-cluster"
import { cn } from "@/lib/utils"

/** Headline of the read-only banner, by role of this node. */
function headline(role?: string, reason?: string): string {
  switch (role) {
    case "secondary":
      return "Ce nœud est secondaire : configuration en lecture seule."
    case "joining":
      return "Ce nœud démarre et rejoint le cluster : configuration en lecture seule."
    case "isolated":
      return "Ce nœud est isolé (primaire injoignable) : configuration en lecture seule."
    case "incompatible":
      return "Versions incompatibles entre les nœuds : configuration en lecture seule."
  }
  return reason ? `Configuration en lecture seule : ${reason}` : "Configuration en lecture seule."
}

/**
 * Banner shown above every page when this cluster node refuses config
 * changes: blue on a normal secondary (with a link to the primary), orange
 * for any other reason (update in progress, isolated node...).
 */
export function ReadOnlyBanner() {
  const { data } = useClusterView()
  const w = writabilityOf(data)
  if (w.writable || !data) return null
  const calm = data.role === "secondary" || data.role === "joining"
  return (
    <div
      role="status"
      data-testid="read-only-banner"
      className={cn(
        "flex flex-wrap items-center justify-center gap-x-3 gap-y-1 px-4 py-2 text-center text-sm font-medium text-white",
        calm ? "bg-blue-600 dark:bg-blue-700" : "bg-orange-600 dark:bg-orange-700",
      )}
    >
      <span className="inline-flex items-center gap-2">
        {calm ? <Info className="size-4 shrink-0" /> : <TriangleAlert className="size-4 shrink-0" />}
        {headline(data.role, w.reason)}
      </span>
      {w.secondary && w.primaryUrl && (
        <a
          href={w.primaryUrl}
          target="_blank"
          rel="noopener noreferrer"
          className="inline-flex items-center gap-1 underline underline-offset-4 hover:no-underline"
        >
          Ouvrir le primaire <ExternalLink className="size-3.5" />
        </a>
      )}
    </div>
  )
}

/**
 * Wraps config-changing controls. On a read-only node they are disabled
 * (native <fieldset disabled>) and explained by a tooltip; `block` mode is for
 * whole forms: disabled, with a short note above instead of a tooltip.
 */
export function WriteGuard({
  children,
  block = false,
  className,
}: {
  children: React.ReactNode
  block?: boolean
  className?: string
}) {
  const w = useWritable()
  if (w.writable) return <>{children}</>
  if (block) {
    return (
      <div className={cn("space-y-3", className)}>
        <ReadOnlyNote />
        <fieldset disabled className="min-w-0">
          {children}
        </fieldset>
      </div>
    )
  }
  return (
    <Tooltip>
      <TooltipTrigger asChild>
        <div className={cn("inline-flex cursor-not-allowed", className)} tabIndex={0} aria-label={w.hint}>
          {/* pointer-events: none also blocks links (a fieldset only disables form controls). */}
          <fieldset disabled className="pointer-events-none contents [&_a]:opacity-50">
            {children}
          </fieldset>
        </div>
      </TooltipTrigger>
      <TooltipContent>{w.hint}</TooltipContent>
    </Tooltip>
  )
}

/** One-line explanation, for places where a tooltip would be hidden. */
export function ReadOnlyNote({ className }: { className?: string }) {
  const w = useWritable()
  if (w.writable) return null
  return (
    <p className={cn("flex items-center gap-1.5 text-xs text-muted-foreground", className)}>
      <Lock className="size-3.5 shrink-0" />
      {w.hint}.
    </p>
  )
}
