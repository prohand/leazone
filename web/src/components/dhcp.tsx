import * as React from "react"
import { useQuery } from "@tanstack/react-query"
import { Info, Plus, TriangleAlert, X } from "lucide-react"
import { dhcpStatusQuery, scopesQuery } from "@/api/queries"
import type { LeaseState, ScopeMode, ScopeUsage } from "@/api/types"
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert"
import { Badge } from "@/components/ui/badge"
import { Button } from "@/components/ui/button"
import { Input } from "@/components/ui/input"
import { fmtInt, formatPercent, leaseStateLabel, modeHelp, modeLabel } from "@/lib/dhcp"
import { cn } from "@/lib/utils"

/* Small DHCP building blocks shared by the VLAN, scope, lease and dashboard pages. */

export function ModeBadge({ mode }: { mode?: ScopeMode }) {
  const m = mode ?? "none"
  return (
    <Badge
      variant={m === "none" ? "outline" : "secondary"}
      className={cn(m === "none" && "text-muted-foreground")}
      title={modeHelp[m]}
    >
      {modeLabel[m]}
    </Badge>
  )
}

const stateClass: Record<LeaseState, string> = {
  bound: "border-success/40 text-success",
  offered: "border-brand/40 text-brand",
  declined: "border-destructive/40 text-destructive",
  released: "text-muted-foreground",
  expired: "text-muted-foreground",
}

export function LeaseStateBadge({ state }: { state?: LeaseState }) {
  if (!state) return null
  return (
    <Badge variant="outline" className={stateClass[state]}>
      {leaseStateLabel[state]}
    </Badge>
  )
}

export type UsageTone = "ok" | "warning" | "alert"

/**
 * Colour tone of a DHCP usage percentage, shared by every usage display (VLAN cards, scopes, dashboard):
 * - "alert" (red) from `alert` %, the scope alert threshold (80 by default, as on the server);
 * - "warning" (orange) from `alert` − 20 points (so 60 % with the default threshold);
 * - "ok" (green) below.
 * Use `usageToneClass[tone]` for the matching Tailwind classes.
 */
export function usageTone(percent: number | null | undefined, alert = 80): UsageTone {
  const p = percent ?? 0
  const threshold = Number.isFinite(alert) && alert > 0 ? alert : 80
  if (p >= threshold) return "alert"
  if (p >= Math.max(0, threshold - 20)) return "warning"
  return "ok"
}

/** Tailwind classes of a usage tone: `bg` for bars and dots, `text` for figures. */
export const usageToneClass: Record<UsageTone, { bg: string; text: string }> = {
  ok: { bg: "bg-success", text: "text-success" },
  warning: { bg: "bg-warning", text: "text-warning" },
  alert: { bg: "bg-destructive", text: "text-destructive" },
}

/**
 * Horizontal fill bar coloured by `usageTone`. `alert` (the server verdict, ScopeUsage.alert) forces red when true;
 * `threshold` is the scope alert threshold (80 % by default). Width uses an inline style (allowed by the CSP: style-src-attr).
 */
export function UsageBar({
  percent,
  alert,
  threshold,
  className,
  label,
}: {
  percent?: number
  alert?: boolean
  threshold?: number
  className?: string
  label?: string
}) {
  const p = Math.max(0, Math.min(100, percent ?? 0))
  let tone = usageTone(p, threshold)
  // The server decides the alert (its threshold may differ from the default used here).
  if (alert) tone = "alert"
  else if (alert === false && tone === "alert") tone = "warning"
  return (
    <div
      role="progressbar"
      aria-valuemin={0}
      aria-valuemax={100}
      aria-valuenow={Math.round(p)}
      aria-label={label ?? "Remplissage"}
      className={cn("h-2 w-full overflow-hidden rounded-full bg-muted", className)}
    >
      <div className={cn("h-full rounded-full transition-[width]", usageToneClass[tone].bg)} style={{ width: `${p}%` }} />
    </div>
  )
}

/** Usage bar + "42 % · 84 / 200" line. */
export function ScopeUsageLine({ usage, compact = false }: { usage?: ScopeUsage; compact?: boolean }) {
  if (!usage) return <span className="text-sm text-muted-foreground">—</span>
  return (
    <div className={cn("space-y-1", compact ? "w-28" : "w-full")}>
      <UsageBar
        percent={usage.percent}
        alert={usage.alert}
        threshold={usage.alertThreshold}
        label={`Remplissage de ${usage.name ?? "l'étendue"}`} />
      <div className="flex items-center justify-between gap-2 text-xs tabular-nums">
        <span className={cn("font-medium", usage.alert ? "text-destructive" : "text-foreground")}>
          {usage.alert && <TriangleAlert className="mr-1 inline size-3 -translate-y-px" aria-hidden />}
          {formatPercent(usage.percent)}
        </span>
        <span className="text-muted-foreground">
          {fmtInt.format(usage.used ?? 0)} / {fmtInt.format(usage.size ?? 0)}
        </span>
      </div>
    </div>
  )
}

/**
 * Red banner when the DHCP server should listen but does not (an active scope exists: enabled, with a direct or relay
 * mode). Without any active scope the server stays closed on purpose: a neutral hint is shown when an interface has
 * the DHCP enabled, nothing otherwise (fresh install).
 */
export function DhcpStatusBanner({ className }: { className?: string }) {
  const status = useQuery(dhcpStatusQuery)
  const scopes = useQuery(scopesQuery)
  const s = status.data
  if (!s || s.listening !== false || !scopes.data) return null
  const active = (scopes.data.items ?? []).some((sc) => sc.enabled !== false && (sc.mode ?? "none") !== "none")
  if (!active) {
    if ((s.interfaces ?? []).length === 0) return null
    return (
      <Alert className={cn("mb-4", className)}>
        <Info />
        <AlertTitle>Le serveur DHCP attend une étendue active</AlertTitle>
        <AlertDescription>
          <p>Il commence à écouter dès qu'une étendue est activée, en mode direct ou relais.</p>
        </AlertDescription>
      </Alert>
    )
  }
  return (
    <Alert variant="destructive" className={cn("mb-4", className)}>
      <TriangleAlert />
      <AlertTitle>Le serveur DHCP n'écoute pas{s.port ? ` (port ${s.port})` : ""}</AlertTitle>
      <AlertDescription>
        <p>{s.error || "Aucune interface n'a le DHCP activé ou le port est déjà utilisé."}</p>
      </AlertDescription>
    </Alert>
  )
}

/**
 * Editable list of short text values (DNS servers, NTP servers, relay agents).
 * `errorAt(i)` returns the message of item i (e.g. from a 422 "dnsServers[1]").
 * `id` goes on the first input, which only exists when the list is not empty: give `label` (accessible name of
 * the group) and point a <label htmlFor> at `id` only when `values.length > 0`.
 */
export function ListInput({
  id,
  label,
  values,
  onChange,
  placeholder,
  addLabel = "Ajouter",
  errorAt,
  mono = true,
}: {
  id: string
  label?: string
  values: string[]
  onChange: (v: string[]) => void
  placeholder?: string
  addLabel?: string
  errorAt?: (i: number) => string | undefined
  mono?: boolean
}) {
  const refs = React.useRef<Array<HTMLInputElement | null>>([])
  const focusNext = React.useRef<number | null>(null)
  React.useEffect(() => {
    if (focusNext.current !== null) {
      refs.current[focusNext.current]?.focus()
      focusNext.current = null
    }
  })
  return (
    <div role="group" aria-label={label} className="space-y-2">
      {values.map((v, i) => {
        const err = errorAt?.(i)
        return (
          <div key={i} className="space-y-1">
            <div className="flex items-center gap-2">
              <Input
                id={i === 0 ? id : `${id}-${i}`}
                aria-label={label ? (i === 0 ? label : `${label} ${i + 1}`) : undefined}
                ref={(el) => {
                  refs.current[i] = el
                }}
                value={v}
                aria-invalid={!!err || undefined}
                className={cn(mono && "font-mono")}
                autoCapitalize="none"
                spellCheck={false}
                placeholder={placeholder}
                onChange={(e) => onChange(values.map((x, j) => (j === i ? e.target.value : x)))}
                onKeyDown={(e) => {
                  if (e.key === "Enter") {
                    e.preventDefault()
                    focusNext.current = values.length
                    onChange([...values, ""])
                  }
                }}
              />
              <Button
                type="button"
                variant="ghost"
                size="icon-sm"
                aria-label="Retirer"
                className="text-muted-foreground hover:text-destructive"
                onClick={() => onChange(values.filter((_, j) => j !== i))}
              >
                <X />
              </Button>
            </div>
            {err && (
              <p data-slot="field-error" className="text-sm text-destructive">
                {err}
              </p>
            )}
          </div>
        )
      })}
      <Button
        type="button"
        variant="outline"
        size="sm"
        onClick={() => {
          focusNext.current = values.length
          onChange([...values, ""])
        }}
      >
        <Plus /> {addLabel}
      </Button>
    </div>
  )
}

/** Switch row with a title and a one-line explanation. */
export function SwitchRow({
  id,
  title,
  description,
  children,
  className,
}: {
  id: string
  title: React.ReactNode
  description?: React.ReactNode
  children: React.ReactNode
  className?: string
}) {
  return (
    <div className={cn("flex items-center justify-between gap-3 rounded-lg border p-3", className)}>
      <label htmlFor={id} className="flex min-w-0 flex-col gap-0.5 text-sm">
        <span className="font-medium">{title}</span>
        {description && <span className="text-xs text-muted-foreground">{description}</span>}
      </label>
      {children}
    </div>
  )
}
