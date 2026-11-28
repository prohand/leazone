import * as React from "react"
import { Link, useSearchParams } from "react-router"
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query"
import { Layers, Loader2, Pencil, Plus, Tag, Trash2, TriangleAlert } from "lucide-react"
import { toast } from "sonner"
import { api } from "@/api/client"
import { qk, vlansQuery } from "@/api/queries"
import type { ScopeUsage, VlanInput, VlanOverview } from "@/api/types"
import { ConfirmDialog } from "@/components/confirm-dialog"
import { DhcpStatusBanner, ModeBadge, ScopeUsageLine } from "@/components/dhcp"
import { EmptyState } from "@/components/empty-state"
import { Field, FormError } from "@/components/form-field"
import { PageHeader } from "@/components/page-header"
import { BlockSpinner } from "@/components/spinner"
import { Badge } from "@/components/ui/badge"
import { Button } from "@/components/ui/button"
import { Card, CardAction, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog"
import { Input } from "@/components/ui/input"
import { WriteGuard } from "@/components/read-only"
import { usePermissions } from "@/hooks/use-cluster"
import { activeLeasesLabel, countLabel, vlanLabel } from "@/lib/dhcp"
import { errorMessage, fieldError, formError } from "@/lib/errors"
import { cn } from "@/lib/utils"

type Editing = { id: string | null; vlanId?: number; name?: string; lockId?: boolean }

export default function VlansPage() {
  const qc = useQueryClient()
  const perms = usePermissions()
  const canConfig = perms.can("config.write")
  const [params, setParams] = useSearchParams()
  const list = useQuery(vlansQuery)
  const [editing, setEditing] = React.useState<Editing | null>(null)
  const [deleting, setDeleting] = React.useState<VlanOverview | null>(null)

  // ⌘K "Nommer un VLAN" lands here with ?new=1.
  React.useEffect(() => {
    if (params.get("new") === "1") {
      if (canConfig) setEditing({ id: null })
      setParams({}, { replace: true })
    }
  }, [params, setParams, canConfig])

  const remove = useMutation({
    mutationFn: (id: string) => api.delete("/vlans/{id}", { params: { id } }),
    onSuccess: () => {
      toast.success("Nom du VLAN supprimé.")
      void qc.invalidateQueries({ queryKey: qk.vlans })
    },
  })

  const vlans = React.useMemo(
    () => [...(list.data?.items ?? [])].sort((a, b) => (a.vlanId ?? 0) - (b.vlanId ?? 0)),
    [list.data],
  )
  const untagged = list.data?.untaggedScopes ?? []
  const empty = !list.isPending && !list.isError && vlans.length === 0 && untagged.length === 0

  return (
    <>
      <PageHeader
        title="VLAN"
        description="Remplissage des étendues DHCP, VLAN par VLAN. Actualisé toutes les 10 secondes."
        actions={
          perms.allowed("config.write") && (
            <WriteGuard className="gap-2">
              <Button variant="outline" asChild>
                <Link to="/dhcp/scopes?new=1">
                  <Plus /> Nouvelle étendue
                </Link>
              </Button>
              <Button onClick={() => setEditing({ id: null })}>
                <Tag /> Nommer un VLAN
              </Button>
            </WriteGuard>
          )
        }
      />
      <DhcpStatusBanner />
      {list.isPending ? (
        <BlockSpinner />
      ) : list.isError ? (
        <p className="text-sm text-destructive">{errorMessage(list.error)}</p>
      ) : empty ? (
        <EmptyState
          icon={Layers}
          title="Aucun VLAN"
          description="Les VLAN de l'hôte (ex. : eno1.20) apparaissent ici tout seuls. Vous pouvez aussi nommer un VLAN servi par un relais."
          action={
            canConfig && (
              <Button onClick={() => setEditing({ id: null })}>
                <Tag /> Nommer un VLAN
              </Button>
            )
          }
        />
      ) : (
        <div className="grid gap-4 md:grid-cols-2 xl:grid-cols-3">
          {vlans.map((v) => (
            <VlanCard
              key={`${v.vlanId}`}
              vlan={v}
              canConfig={canConfig}
              // The number of an existing VLAN is fixed: changing it would move all its scopes (UpdateVLAN).
              onName={() => setEditing({ id: v.id ?? null, vlanId: v.vlanId, name: v.name, lockId: true })}
              onDelete={() => setDeleting(v)}
            />
          ))}
          {untagged.length > 0 && (
            <Card className="gap-4">
              <CardHeader>
                <CardTitle className="text-base">Sans VLAN</CardTitle>
                <CardDescription>Étendues qui ne sont liées à aucun VLAN.</CardDescription>
              </CardHeader>
              <CardContent className="space-y-3">
                {untagged.map((s) => (
                  <ScopeTile key={s.id} scope={s} />
                ))}
              </CardContent>
            </Card>
          )}
        </div>
      )}

      <VlanDialog editing={editing} onOpenChange={(o) => !o && setEditing(null)} />
      {deleting && (
        <ConfirmDialog
          open={!!deleting}
          onOpenChange={(o) => !o && setDeleting(null)}
          title={`Supprimer le nom du VLAN ${deleting.vlanId} ?`}
          description={
            (deleting.scopes ?? []).length > 0
              ? "Des étendues utilisent ce VLAN : le serveur refusera tant qu'elles existent."
              : "Le VLAN reste visible s'il existe sur l'hôte, mais sans nom."
          }
          confirmLabel="Supprimer"
          destructive
          onConfirm={() => remove.mutateAsync(deleting.id ?? "")}
        />
      )}
    </>
  )
}

function VlanCard({
  vlan: v,
  canConfig,
  onName,
  onDelete,
}: {
  vlan: VlanOverview
  canConfig: boolean
  onName: () => void
  onDelete: () => void
}) {
  const ifaces = v.interfaces ?? []
  const scopes = v.scopes ?? []
  const alert = scopes.some((s) => s.alert)
  const active = scopes.reduce((n, s) => n + (s.activeLeases ?? 0), 0)
  return (
    <Card className={cn("gap-4", alert && "border-destructive/50")} data-testid={`vlan-${v.vlanId}`}>
      <CardHeader>
        <CardTitle className="flex items-center gap-2 text-base">
          {alert && <TriangleAlert className="size-4 text-destructive" aria-label="Alerte de remplissage" />}
          {v.name ? (
            <span>{vlanLabel(v.vlanId, v.name)}</span>
          ) : (
            <span>
              VLAN {v.vlanId} <span className="font-normal text-muted-foreground">(sans nom)</span>
            </span>
          )}
        </CardTitle>
        <CardDescription>
          {scopes.length === 0
            ? "Aucune étendue"
            : `${countLabel(scopes.length, "étendue", "étendues")} · ${activeLeasesLabel(active)}`}
        </CardDescription>
        {canConfig && (
          <CardAction className="flex items-center gap-1">
            {v.name ? (
              <>
                <Button variant="ghost" size="icon-sm" aria-label={`Renommer le VLAN ${v.vlanId}`} onClick={onName}>
                  <Pencil />
                </Button>
                {v.id && (
                  <Button
                    variant="ghost"
                    size="icon-sm"
                    aria-label={`Supprimer le nom du VLAN ${v.vlanId}`}
                    className="text-muted-foreground hover:text-destructive"
                    onClick={onDelete}
                  >
                    <Trash2 />
                  </Button>
                )}
              </>
            ) : (
              <Button variant="outline" size="sm" onClick={onName}>
                <Tag /> Nommer
              </Button>
            )}
          </CardAction>
        )}
      </CardHeader>
      <CardContent className="space-y-4">
        <div className="space-y-2">
          {ifaces.length === 0 ? (
            <p className="flex items-start gap-1.5 text-xs text-warning">
              <TriangleAlert className="mt-px size-3.5 shrink-0" />
              <span>Absent de l'hôte : seul un relais peut servir ce VLAN.</span>
            </p>
          ) : (
            ifaces.map((i) => (
              <div key={i.name} className="flex flex-wrap items-center gap-x-2 gap-y-1 text-sm">
                <span className="font-medium">{i.name}</span>
                {i.parent && <span className="text-xs text-muted-foreground">sur {i.parent}</span>}
                <Badge
                  variant="outline"
                  className={cn(i.dhcpEnabled ? "border-success/40 text-success" : "text-muted-foreground")}
                >
                  DHCP {i.dhcpEnabled ? "activé" : "désactivé"}
                </Badge>
                <span className="w-full font-mono text-xs text-muted-foreground">
                  {(i.addresses ?? []).length > 0 ? (i.addresses ?? []).join(", ") : "aucune IP"}
                </span>
              </div>
            ))
          )}
        </div>
        {scopes.length > 0 ? (
          <div className="space-y-3">
            {scopes.map((s) => (
              <ScopeTile key={s.id} scope={s} />
            ))}
          </div>
        ) : (
          canConfig && (
            <Button variant="outline" size="sm" asChild>
              <Link to={`/dhcp/scopes?new=1&vlan=${v.vlanId}`}>
                <Plus /> Créer une étendue
              </Link>
            </Button>
          )
        )}
      </CardContent>
    </Card>
  )
}

/** One scope inside a VLAN card; opens its leases. */
function ScopeTile({ scope: s }: { scope: ScopeUsage }) {
  return (
    <Link
      to={`/dhcp/leases?scope=${encodeURIComponent(s.id ?? "")}`}
      aria-label={`Baux de ${s.name}`}
      className={cn(
        "block space-y-2 rounded-lg border p-3 transition-colors hover:bg-muted/50 focus-visible:ring-[3px] focus-visible:ring-ring/50 focus-visible:outline-none",
        s.alert && "border-destructive/50 bg-destructive/5 hover:bg-destructive/10",
        s.enabled === false && "opacity-60",
      )}
    >
      <div className="flex flex-wrap items-center gap-2">
        <span className="min-w-0 flex-1 truncate text-sm font-medium">{s.name}</span>
        {s.enabled === false && <Badge variant="outline">désactivée</Badge>}
        <ModeBadge mode={s.mode} />
      </div>
      <div className="flex items-center justify-between gap-2 text-xs text-muted-foreground">
        <span className="font-mono">{s.network}</span>
        <span className="tabular-nums">
          {activeLeasesLabel(s.activeLeases ?? 0)}
        </span>
      </div>
      <ScopeUsageLine usage={s} />
      {s.alert && (
        <p className="text-xs font-medium text-destructive">Au-dessus de {s.alertThreshold ?? 80} % : pensez à agrandir la plage.</p>
      )}
    </Link>
  )
}

function VlanDialog({ editing, onOpenChange }: { editing: Editing | null; onOpenChange: (o: boolean) => void }) {
  const qc = useQueryClient()
  const open = !!editing
  const [vlanId, setVlanId] = React.useState("")
  const [name, setName] = React.useState("")
  const [local, setLocal] = React.useState<Record<string, string>>({})

  const save = useMutation({
    mutationFn: (body: VlanInput) =>
      editing?.id ? api.put("/vlans/{id}", { params: { id: editing.id }, body }) : api.post("/vlans", { body }),
    meta: { silent: true },
    onSuccess: (_, body) => {
      void qc.invalidateQueries({ queryKey: qk.vlans })
      void qc.invalidateQueries({ queryKey: qk.scopes })
      toast.success(`VLAN ${body.vlanId} nommé « ${body.name} ».`)
      onOpenChange(false)
    },
  })

  React.useEffect(() => {
    if (open) {
      setVlanId(editing?.vlanId ? String(editing.vlanId) : "")
      setName(editing?.name ?? "")
      setLocal({})
      save.reset()
    }
    // Reset only when the dialog opens.
  }, [open])

  const err = (k: string) => local[k] ?? fieldError(save.error, k)

  const submit = (e: React.FormEvent) => {
    e.preventDefault()
    const e2: Record<string, string> = {}
    const n = Number(vlanId)
    if (!/^\d+$/.test(vlanId.trim()) || n < 1 || n > 4094) e2.vlanId = "Numéro entre 1 et 4094."
    if (!name.trim()) e2.name = "Obligatoire."
    else if (name.trim().length > 64) e2.name = "64 caractères au plus."
    setLocal(e2)
    if (Object.keys(e2).length === 0) save.mutate({ vlanId: n, name: name.trim() })
  }

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="sm:max-w-md">
        <form onSubmit={submit} className="space-y-4">
          <DialogHeader>
            <DialogTitle>{editing?.id ? "Renommer le VLAN" : "Nommer un VLAN"}</DialogTitle>
            <DialogDescription>
              Un nom lisible pour un numéro de VLAN, ex. : VLAN 20 · Invités. Le VLAN lui-même se crée sur l'hôte ou le routeur.
            </DialogDescription>
          </DialogHeader>
          <div className="grid gap-4 sm:grid-cols-[7rem_1fr]">
            <Field label="Numéro" htmlFor="vlan-id" error={err("vlanId")}>
              <Input
                id="vlan-id"
                inputMode="numeric"
                value={vlanId}
                disabled={editing?.lockId}
                onChange={(e) => setVlanId(e.target.value)}
                placeholder="20"
              />
            </Field>
            <Field label="Nom" htmlFor="vlan-name" error={err("name")}>
              <Input
                id="vlan-name"
                value={name}
                autoFocus={!!editing?.lockId}
                onChange={(e) => setName(e.target.value)}
                placeholder="Invités"
                maxLength={64}
              />
            </Field>
          </div>
          <FormError message={formError(save.error, ["vlanId", "name"])} />
          <DialogFooter>
            <Button type="button" variant="ghost" onClick={() => onOpenChange(false)}>
              Annuler
            </Button>
            <Button type="submit" disabled={save.isPending}>
              {save.isPending && <Loader2 className="animate-spin" />}
              Enregistrer
            </Button>
          </DialogFooter>
        </form>
      </DialogContent>
    </Dialog>
  )
}
