import * as React from "react"
import { useSearchParams } from "react-router"
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query"
import { ArrowDown, ArrowUp, FlaskConical, Forward, Loader2, Pencil, Plus, ShieldCheck, Trash2, TriangleAlert } from "lucide-react"
import { toast } from "sonner"
import { api } from "@/api/client"
import { forwardersQuery, qk } from "@/api/queries"
import type { Forwarder, ForwarderInput } from "@/api/types"
import { ConfirmDialog } from "@/components/confirm-dialog"
import { EmptyState } from "@/components/empty-state"
import { PageHeader } from "@/components/page-header"
import { BlockSpinner } from "@/components/spinner"
import { StatusDot } from "@/components/status-dot"
import { Badge } from "@/components/ui/badge"
import { Button } from "@/components/ui/button"
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"
import { Switch } from "@/components/ui/switch"
import { Tooltip, TooltipContent, TooltipTrigger } from "@/components/ui/tooltip"
import { useCurrentUser } from "@/hooks/use-session"
import { defaultPort, formatLatency, protocolLabel } from "@/lib/dns"
import { errorMessage } from "@/lib/errors"
import { formatDateTime } from "@/lib/format"
import { can } from "@/lib/permissions"
import { cn } from "@/lib/utils"
import { ForwarderDialog } from "./forwarder-dialog"

/** Full input of a saved forwarder, used for PUT (enable switch, reorder). */
function inputOf(f: Forwarder, patch: Partial<ForwarderInput> = {}): ForwarderInput {
  const { id: _id, health: _health, ...rest } = f
  return { ...rest, protocol: f.protocol ?? "udp", ...patch }
}

function target(f: Forwarder) {
  if (f.protocol === "doh") return f.dohUrl ?? ""
  const port = f.port ?? defaultPort[f.protocol ?? "udp"]
  const addr = f.address?.includes(":") ? `[${f.address}]` : (f.address ?? "")
  return `${addr}:${port}`
}

function Health({ f }: { f: Forwarder }) {
  const h = f.health
  if (f.enabled === false) return <StatusDot tone="off" label={<span className="text-xs text-muted-foreground">désactivé</span>} />
  if (!h || (!h.lastCheckAt && h.healthy === undefined))
    return <StatusDot tone="off" label={<span className="text-xs text-muted-foreground">pas encore utilisé</span>} />
  const latency = formatLatency(h.lastLatencyMs)
  if (h.healthy)
    return (
      <span title={h.lastCheckAt ? `Vérifié le ${formatDateTime(h.lastCheckAt)}` : undefined}>
        <StatusDot tone="ok" label={<span className="text-xs text-muted-foreground tabular-nums">{latency || "OK"}</span>} />
      </span>
    )
  return (
    <Tooltip>
      <TooltipTrigger asChild>
        <span tabIndex={0} className="cursor-help">
          <StatusDot tone="error" label={<span className="text-xs text-destructive">en panne</span>} />
        </span>
      </TooltipTrigger>
      <TooltipContent className="max-w-xs">{h.lastError || "Ne répond pas."}</TooltipContent>
    </Tooltip>
  )
}

function ForwarderRow({
  f,
  index,
  count,
  canEdit,
  busy,
  onTest,
  testing,
  onToggle,
  onMove,
  onEdit,
  onDelete,
}: {
  f: Forwarder
  index: number
  count: number
  canEdit: boolean
  busy: boolean
  testing: boolean
  onTest: () => void
  onToggle: (v: boolean) => void
  onMove: (dir: -1 | 1) => void
  onEdit: () => void
  onDelete: () => void
}) {
  const tls = f.protocol === "dot" || f.protocol === "doh"
  return (
    <li
      className={cn(
        "flex flex-col gap-3 px-4 py-3 sm:flex-row sm:items-center",
        f.enabled === false && "text-muted-foreground",
      )}
    >
      <div className="flex min-w-0 flex-1 items-start gap-3">
        <span className="mt-0.5 flex size-6 shrink-0 items-center justify-center rounded-full border text-xs font-medium tabular-nums">
          {index + 1}
        </span>
        <div className="min-w-0 flex-1 space-y-1">
          <div className="flex flex-wrap items-center gap-2">
            <Badge variant="outline" className="font-mono">
              {protocolLabel[f.protocol ?? "udp"]}
            </Badge>
            <span className="truncate font-mono text-sm" title={target(f)}>
              {target(f)}
            </span>
            {f.protocol === "doh" && f.address && (
              <span className="text-xs text-muted-foreground">via {f.address}</span>
            )}
          </div>
          <div className="flex flex-wrap items-center gap-x-3 gap-y-1">
            <Health f={f} />
            {tls && f.protocol === "dot" && f.tlsServerName && (
              <span className="font-mono text-xs text-muted-foreground">{f.tlsServerName}</span>
            )}
            {tls &&
              (f.tlsVerify === false ? (
                <Badge variant="outline" className="border-warning/50 text-warning">
                  <TriangleAlert /> certificat non vérifié
                </Badge>
              ) : (
                <span className="inline-flex items-center gap-1 text-xs text-muted-foreground">
                  <ShieldCheck className="size-3.5" /> vérification TLS
                </span>
              ))}
          </div>
        </div>
      </div>
      <div className="flex flex-wrap items-center gap-1 pl-9 sm:pl-0">
        <Button variant="outline" size="sm" onClick={onTest} disabled={testing}>
          {testing ? <Loader2 className="animate-spin" /> : <FlaskConical />} Tester
        </Button>
        {canEdit && (
          <>
            <Switch
              className="mx-2"
              checked={f.enabled !== false}
              disabled={busy}
              onCheckedChange={onToggle}
              aria-label={f.enabled === false ? "Activer ce redirecteur" : "Désactiver ce redirecteur"}
            />
            <Button variant="ghost" size="icon-sm" aria-label="Monter" disabled={busy || index === 0} onClick={() => onMove(-1)}>
              <ArrowUp />
            </Button>
            <Button
              variant="ghost"
              size="icon-sm"
              aria-label="Descendre"
              disabled={busy || index === count - 1}
              onClick={() => onMove(1)}
            >
              <ArrowDown />
            </Button>
            <Button variant="ghost" size="icon-sm" aria-label="Modifier" onClick={onEdit}>
              <Pencil />
            </Button>
            <Button
              variant="ghost"
              size="icon-sm"
              aria-label="Supprimer"
              className="text-muted-foreground hover:text-destructive"
              onClick={onDelete}
            >
              <Trash2 />
            </Button>
          </>
        )}
        {!canEdit && f.enabled === false && <Badge variant="outline">désactivé</Badge>}
      </div>
    </li>
  )
}

export default function ForwardersPage() {
  const qc = useQueryClient()
  const user = useCurrentUser()
  const canEdit = can(user?.role, "config.write")
  const [params, setParams] = useSearchParams()
  const list = useQuery(forwardersQuery)
  const [editing, setEditing] = React.useState<{ forwarder: Forwarder | null; domain?: string } | null>(null)
  const [deleting, setDeleting] = React.useState<Forwarder | null>(null)

  // ⌘K "Ajouter un redirecteur" lands here with ?new=1.
  React.useEffect(() => {
    if (params.get("new") === "1") {
      if (canEdit) setEditing({ forwarder: null })
      setParams({}, { replace: true })
    }
  }, [params, setParams, canEdit])

  const refresh = () => {
    void qc.invalidateQueries({ queryKey: qk.forwarders })
    void qc.invalidateQueries({ queryKey: qk.dnsStatus })
  }

  const update = useMutation({
    mutationFn: (v: { f: Forwarder; patch: Partial<ForwarderInput> }) =>
      api.put("/dns/forwarders/{id}", { params: { id: v.f.id ?? "" }, body: inputOf(v.f, v.patch) }),
    onSettled: refresh,
  })
  const remove = useMutation({
    mutationFn: (id: string) => api.delete("/dns/forwarders/{id}", { params: { id } }),
    onSuccess: () => {
      toast.success("Redirecteur supprimé.")
      refresh()
    },
  })
  const test = useMutation({
    mutationFn: (f: Forwarder) => api.post("/dns/forwarders/{id}/test", { params: { id: f.id ?? "" } }),
    onSuccess: (r, f) => {
      const answers = (r.answers ?? []).slice(0, 3).join("\n")
      if (r.ok)
        toast.success(`${target(f)} répond en ${formatLatency(r.latencyMs)}`, {
          description: answers || r.rcode,
        })
      else toast.error(`${target(f)} ne répond pas`, { description: r.error || r.rcode })
      void qc.invalidateQueries({ queryKey: qk.forwarders })
    },
  })

  // Group by domain ("" = global), each group sorted by position.
  const groups = React.useMemo(() => {
    const map = new Map<string, Forwarder[]>()
    for (const f of list.data?.items ?? []) {
      const d = (f.domain ?? "").replace(/\.$/, "")
      map.set(d, [...(map.get(d) ?? []), f])
    }
    for (const arr of map.values()) arr.sort((a, b) => (a.position ?? 0) - (b.position ?? 0))
    const global = map.get("") ?? []
    map.delete("")
    const conditional = [...map.entries()].sort(([a], [b]) => a.localeCompare(b))
    return { global, conditional }
  }, [list.data])

  const testingId = test.isPending ? test.variables?.id : undefined

  const renderList = (items: Forwarder[]) => (
    <ul className="divide-y rounded-lg border">
      {items.map((f, i) => (
        <ForwarderRow
          key={f.id}
          f={f}
          index={i}
          count={items.length}
          canEdit={canEdit}
          busy={update.isPending}
          testing={testingId === f.id}
          onTest={() => test.mutate(f)}
          onToggle={(v) =>
            update.mutate(
              { f, patch: { enabled: v } },
              { onSuccess: () => toast.success(v ? "Redirecteur activé." : "Redirecteur désactivé.") },
            )
          }
          onMove={(dir) => update.mutate({ f, patch: { position: i + dir } })}
          onEdit={() => setEditing({ forwarder: f })}
          onDelete={() => setDeleting(f)}
        />
      ))}
    </ul>
  )

  return (
    <>
      <PageHeader
        title="Redirecteurs"
        description="Serveurs DNS qui résolvent les noms externes, dans l'ordre : si un redirecteur ne répond pas, Leazone passe au suivant."
        actions={
          canEdit && (
            <Button onClick={() => setEditing({ forwarder: null })}>
              <Plus /> Ajouter un redirecteur
            </Button>
          )
        }
      />
      {list.isPending ? (
        <BlockSpinner />
      ) : list.isError ? (
        <p className="text-sm text-destructive">{errorMessage(list.error)}</p>
      ) : (
        <div className="space-y-8">
          <section className="space-y-3">
            <div>
              <h2 className="text-lg font-semibold">Redirecteurs globaux</h2>
              <p className="text-sm text-muted-foreground">Utilisés pour tous les noms qui ne sont pas dans une zone locale.</p>
            </div>
            {groups.global.length === 0 ? (
              <EmptyState
                icon={Forward}
                title="Aucun redirecteur global"
                description="Sans redirecteur, Leazone ne répond qu'aux noms de ses zones locales."
                action={
                  canEdit && (
                    <Button onClick={() => setEditing({ forwarder: null })}>
                      <Plus /> Ajouter un redirecteur
                    </Button>
                  )
                }
                className="py-10"
              />
            ) : (
              renderList(groups.global)
            )}
          </section>

          <section className="space-y-3">
            <div>
              <h2 className="text-lg font-semibold">Redirecteurs conditionnels</h2>
              <p className="text-sm text-muted-foreground">
                Envoient un domaine précis (et ses sous-domaines) à un autre serveur, par exemple le DNS de l'entreprise.
              </p>
            </div>
            {groups.conditional.length === 0 ? (
              <p className="rounded-lg border border-dashed px-4 py-6 text-center text-sm text-muted-foreground">
                Aucun redirecteur conditionnel.
              </p>
            ) : (
              groups.conditional.map(([domain, items]) => (
                <Card key={domain} className="gap-3 py-4">
                  <CardHeader className="flex flex-row items-center justify-between gap-2 px-4">
                    <div>
                      <CardTitle className="font-mono text-base">{domain}</CardTitle>
                      <CardDescription>et ses sous-domaines</CardDescription>
                    </div>
                    {canEdit && (
                      <Button variant="outline" size="sm" onClick={() => setEditing({ forwarder: null, domain })}>
                        <Plus /> Ajouter
                      </Button>
                    )}
                  </CardHeader>
                  <CardContent className="px-4">{renderList(items)}</CardContent>
                </Card>
              ))
            )}
          </section>
        </div>
      )}

      <ForwarderDialog
        open={!!editing}
        onOpenChange={(o) => !o && setEditing(null)}
        forwarder={editing?.forwarder ?? null}
        defaultDomain={editing?.domain}
      />
      {deleting && (
        <ConfirmDialog
          open={!!deleting}
          onOpenChange={(o) => !o && setDeleting(null)}
          title="Supprimer ce redirecteur ?"
          description={
            <>
              <span className="font-mono">{target(deleting)}</span>
              {deleting.domain ? ` pour ${deleting.domain}` : ""} ne sera plus utilisé.
            </>
          }
          confirmLabel="Supprimer"
          destructive
          onConfirm={() => remove.mutateAsync(deleting.id ?? "")}
        />
      )}
    </>
  )
}
