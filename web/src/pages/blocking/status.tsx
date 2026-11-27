import { useQuery } from "@tanstack/react-query"
import { Check, CirclePause, Loader2, Play, ShieldBan, ShieldCheck } from "lucide-react"
import { blockingStatusQuery, blockRulesQuery } from "@/api/queries"
import type { BlockingStatus } from "@/api/types"
import { WriteGuard } from "@/components/read-only"
import { Skeleton } from "@/components/ui/skeleton"
import { Badge } from "@/components/ui/badge"
import { Button } from "@/components/ui/button"
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table"
import { usePermissions } from "@/hooks/use-cluster"
import { blockedPercent, fmtInt, formatUntil, pauseChoices, useAddRule, usePauseBlocking } from "@/lib/blocking"
import { errorMessage } from "@/lib/errors"
import { cn } from "@/lib/utils"

/** "actif" / "en pause jusqu'à 14:35" / "désactivé", with its tone. */
export function blockingState(s?: BlockingStatus): { label: string; tone: "ok" | "paused" | "off" } {
  if (!s) return { label: "—", tone: "off" }
  if (s.enabled === false) return { label: "Module désactivé", tone: "off" }
  if (s.paused) {
    const until = formatUntil(s.pausedUntil)
    return { label: until ? `En pause jusqu'à ${until}` : "En pause", tone: "paused" }
  }
  return { label: "Actif", tone: "ok" }
}

function Stat({ label, value, className }: { label: string; value: string; className?: string }) {
  return (
    <div className="rounded-lg border p-3">
      <div className={cn("text-xl font-semibold tabular-nums", className)}>{value}</div>
      <div className="text-xs text-muted-foreground">{label}</div>
    </div>
  )
}

/** State, pause buttons and counters (refreshed every 5 s). */
export function StatusCard() {
  const perms = usePermissions()
  const status = useQuery(blockingStatusQuery)
  const pause = usePauseBlocking()
  const s = status.data
  const state = blockingState(s)
  const Icon = state.tone === "paused" ? CirclePause : state.tone === "ok" ? ShieldCheck : ShieldBan
  const busy = pause.isPending ? pause.variables : undefined

  return (
    <Card data-testid="blocking-status">
      <CardContent className="space-y-5">
        <div className="flex flex-col gap-4 md:flex-row md:items-center md:justify-between">
          <div className="flex items-center gap-4">
            <div
              className={cn(
                "flex size-14 shrink-0 items-center justify-center rounded-full",
                state.tone === "ok" && "bg-success/15 text-success",
                state.tone === "paused" && "bg-warning/15 text-warning",
                state.tone === "off" && "bg-muted text-muted-foreground",
              )}
            >
              <Icon className="size-7" />
            </div>
            <div className="min-w-0">
              {status.isPending ? (
                <Skeleton className="h-7 w-40" />
              ) : (
                <p
                  data-testid="blocking-state"
                  className={cn(
                    "text-2xl font-semibold tracking-tight",
                    state.tone === "ok" && "text-success",
                    state.tone === "paused" && "text-warning",
                  )}
                >
                  {state.label}
                </p>
              )}
              <p className="text-sm text-muted-foreground">
                {status.isError
                  ? errorMessage(status.error)
                  : state.tone === "paused"
                    ? "Tous les noms sont résolus normalement pendant la pause."
                    : state.tone === "off"
                      ? s
                        ? "Aucun domaine n'est bloqué : toutes les requêtes sont résolues normalement. Activez le blocage dans l'onglet « Réglages »."
                        : ""
                      : "Module actif : les domaines des listes reçoivent une réponse vide."}
              </p>
            </div>
          </div>
          {perms.allowed("records.write") && s?.enabled !== false && (
            <WriteGuard className="flex-wrap gap-2">
              <div className="flex flex-wrap items-center gap-2">
                {s?.paused && (
                  <Button onClick={() => pause.mutate(0)} disabled={pause.isPending}>
                    {busy === 0 ? <Loader2 className="animate-spin" /> : <Play />} Reprendre
                  </Button>
                )}
                {pauseChoices.map((c) => (
                  <Button key={c.minutes} variant="outline" onClick={() => pause.mutate(c.minutes)} disabled={pause.isPending}>
                    {busy === c.minutes ? <Loader2 className="animate-spin" /> : c.minutes === 5 && <CirclePause />}
                    {c.label}
                  </Button>
                ))}
              </div>
            </WriteGuard>
          )}
        </div>
        <div className="grid grid-cols-2 gap-3 sm:grid-cols-3 lg:grid-cols-5">
          <Stat label="Requêtes vérifiées" value={s ? fmtInt.format(s.queries ?? 0) : "—"} />
          <Stat label="Requêtes bloquées" value={s ? fmtInt.format(s.blocked ?? 0) : "—"} />
          <Stat label="Part bloquée" value={blockedPercent(s)} className={(s?.blocked ?? 0) > 0 ? "text-destructive" : undefined} />
          <Stat label="Domaines chargés" value={s ? fmtInt.format(s.domains ?? 0) : "—"} />
          <Stat label="Listes" value={s ? fmtInt.format(s.lists ?? 0) : "—"} />
        </div>
        <p className="text-xs text-muted-foreground">Compteurs de ce nœud depuis son démarrage. Mis à jour toutes les 5 s.</p>
      </CardContent>
    </Card>
  )
}

/** Top 10 blocked domains, with a quick "allow" action. */
export function TopBlockedCard() {
  const perms = usePermissions()
  const status = useQuery(blockingStatusQuery)
  const rules = useQuery(blockRulesQuery)
  const add = useAddRule()
  const top = (status.data?.top ?? []).slice(0, 10)
  const allowed = new Set((rules.data?.items ?? []).filter((r) => r.kind === "allow").map((r) => r.domain))
  const canAllow = perms.can("records.write")

  return (
    <Card className="gap-4">
      <CardHeader>
        <CardTitle>Les plus bloqués</CardTitle>
        <CardDescription>Si un site utile ne marche plus, autorisez son domaine.</CardDescription>
      </CardHeader>
      <CardContent>
        {top.length === 0 ? (
          <p className="rounded-lg border border-dashed px-4 py-6 text-center text-sm text-muted-foreground">
            {status.isPending ? "Chargement…" : "Rien de bloqué pour l'instant."}
          </p>
        ) : (
          <div className="rounded-lg border">
            <Table>
              <TableHeader>
                <TableRow className="hover:bg-transparent">
                  <TableHead className="text-xs text-muted-foreground">Domaine</TableHead>
                  <TableHead className="text-right text-xs text-muted-foreground">Bloqué</TableHead>
                  {canAllow && <TableHead className="w-0" />}
                </TableRow>
              </TableHeader>
              <TableBody>
                {top.map((t) => {
                  const ok = allowed.has(t.domain)
                  const busy = add.isPending && add.variables?.domain === t.domain
                  return (
                    <TableRow key={t.domain}>
                      <TableCell className="max-w-[11rem] truncate font-mono text-xs sm:max-w-[16rem]" title={t.domain}>
                        {t.domain}
                      </TableCell>
                      <TableCell className="text-right tabular-nums">{fmtInt.format(t.count ?? 0)}</TableCell>
                      {canAllow && (
                        <TableCell className="text-right">
                          {ok ? (
                            <Badge variant="outline" className="border-success/40 text-success">
                              <Check /> autorisé
                            </Badge>
                          ) : (
                            <Button
                              variant="outline"
                              size="xs"
                              disabled={busy}
                              aria-label={`Autoriser ${t.domain}`}
                              onClick={() => t.domain && add.mutate({ domain: t.domain, kind: "allow", comment: "Autorisé depuis les plus bloqués" })}
                            >
                              {busy && <Loader2 className="animate-spin" />} Autoriser
                            </Button>
                          )}
                        </TableCell>
                      )}
                    </TableRow>
                  )
                })}
              </TableBody>
            </Table>
          </div>
        )}
      </CardContent>
    </Card>
  )
}
