import * as React from "react"
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query"
import { Eraser, Loader2, Settings2, TriangleAlert } from "lucide-react"
import { toast } from "sonner"
import { api } from "@/api/client"
import { logSettingsQuery, logStatusQuery, qk } from "@/api/queries"
import type { LogSettings } from "@/api/types"
import { ConfirmDialog } from "@/components/confirm-dialog"
import { Field, FormError } from "@/components/form-field"
import { WriteGuard } from "@/components/read-only"
import { Button } from "@/components/ui/button"
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle } from "@/components/ui/dialog"
import { Input } from "@/components/ui/input"
import { Label } from "@/components/ui/label"
import { Skeleton } from "@/components/ui/skeleton"
import { Switch } from "@/components/ui/switch"
import { usePermissions } from "@/hooks/use-cluster"
import { fieldError, formError } from "@/lib/errors"
import { formatDateTime } from "@/lib/format"
import { fmtInt, formatMb } from "@/lib/logs"
import { cn } from "@/lib/utils"

/** "Conservation": size and content of this node's log database, settings, purge. */
export function RetentionCard() {
  const qc = useQueryClient()
  const perms = usePermissions()
  const status = useQuery(logStatusQuery)
  const settings = useQuery(logSettingsQuery)
  const [editing, setEditing] = React.useState(false)
  const [purging, setPurging] = React.useState(false)
  const s = status.data
  const cfg = settings.data
  const dropped = s?.dropped ?? 0

  const purge = useMutation({
    mutationFn: () => api.post("/logs/purge"),
    onSuccess: (st) => {
      if (st) qc.setQueryData(qk.logStatus, st)
      void qc.invalidateQueries({ queryKey: qk.logs })
      toast.success("Journaux DNS et DHCP de ce nœud vidés.")
    },
  })

  const fig = (label: string, value: React.ReactNode, hint?: React.ReactNode, tone?: "warning") => (
    <div className="min-w-0">
      <dt className="text-xs text-muted-foreground">{label}</dt>
      <dd className={cn("mt-0.5 text-lg font-semibold tracking-tight", tone === "warning" && "text-warning")}>{value}</dd>
      {hint && <dd className={cn("text-xs", tone === "warning" ? "text-warning" : "text-muted-foreground")}>{hint}</dd>}
    </div>
  )

  return (
    <Card className="mb-4 gap-4" data-testid="retention-card">
      <CardHeader className="flex flex-col gap-3 sm:flex-row sm:items-start sm:justify-between">
        <div className="space-y-1.5">
          <CardTitle>Conservation</CardTitle>
          <CardDescription>
            Journaux propres à chaque nœud (non synchronisés).{" "}
            {cfg && (
              <span data-testid="retention-summary">
                Gardés {cfg.retentionDays ?? 7} jour{(cfg.retentionDays ?? 7) > 1 ? "s" : ""}, {fmtInt.format(cfg.maxSizeMb ?? 500)} Mo au plus.
                {cfg.dnsQueries === false && " Requêtes DNS non journalisées."}
                {cfg.dhcpEvents === false && " Événements DHCP non journalisés."}
              </span>
            )}
          </CardDescription>
        </div>
        <div className="flex flex-wrap gap-2">
          {perms.allowed("config.write") && (
            <WriteGuard>
              <Button variant="outline" size="sm" onClick={() => setEditing(true)} disabled={!cfg}>
                <Settings2 /> Réglages
              </Button>
            </WriteGuard>
          )}
          {perms.allowed("admin") && (
            <Button variant="outline" size="sm" className="text-destructive hover:text-destructive" onClick={() => setPurging(true)}>
              <Eraser /> Vider les journaux
            </Button>
          )}
        </div>
      </CardHeader>
      <CardContent>
        {!s ? (
          status.isError ? (
            <p className="text-sm text-muted-foreground">État indisponible.</p>
          ) : (
            <Skeleton className="h-12 w-full" />
          )
        ) : (
          <dl className="grid grid-cols-2 gap-4 lg:grid-cols-4">
            {fig(
              "Entrées",
              fmtInt.format((s.dnsEntries ?? 0) + (s.dhcpEntries ?? 0)),
              `${fmtInt.format(s.dnsEntries ?? 0)} DNS · ${fmtInt.format(s.dhcpEntries ?? 0)} DHCP`,
            )}
            {fig("Taille", formatMb(s.sizeBytes), cfg ? `sur ${fmtInt.format(cfg.maxSizeMb ?? 500)} Mo au plus` : undefined)}
            {fig("Plus ancienne", <span className="text-base">{s.oldest ? formatDateTime(s.oldest) : "—"}</span>)}
            {fig(
              "Perdues",
              <span className="inline-flex items-center gap-1.5">
                {dropped > 0 && <TriangleAlert className="size-4" aria-hidden />}
                {fmtInt.format(dropped)}
              </span>,
              dropped > 0 ? "trop d'entrées d'un coup depuis le démarrage" : "aucune depuis le démarrage",
              dropped > 0 ? "warning" : undefined,
            )}
          </dl>
        )}
      </CardContent>
      {cfg && <SettingsDialog open={editing} onOpenChange={setEditing} initial={cfg} />}
      <ConfirmDialog
        open={purging}
        onOpenChange={setPurging}
        title="Vider les journaux de ce nœud ?"
        description="Toutes les requêtes DNS et tous les événements DHCP enregistrés sur ce nœud sont effacés. Le journal d'audit est gardé. L'autre nœud garde ses propres journaux."
        confirmLabel="Vider les journaux"
        destructive
        onConfirm={() => purge.mutateAsync()}
      />
    </Card>
  )
}

type Form = { dnsQueries: boolean; dhcpEvents: boolean; retentionDays: string; maxSizeMb: string }

function SettingsDialog({ open, onOpenChange, initial }: { open: boolean; onOpenChange: (o: boolean) => void; initial: LogSettings }) {
  const qc = useQueryClient()
  const toForm = (c: LogSettings): Form => ({
    dnsQueries: c.dnsQueries !== false,
    dhcpEvents: c.dhcpEvents !== false,
    retentionDays: String(c.retentionDays ?? 7),
    maxSizeMb: String(c.maxSizeMb ?? 500),
  })
  const [form, setForm] = React.useState<Form>(() => toForm(initial))
  const [local, setLocal] = React.useState<Record<string, string>>({})
  const save = useMutation({
    mutationFn: (body: LogSettings) => api.put("/logs/settings", { body }),
    meta: { silent: true },
    onSuccess: (c) => {
      qc.setQueryData(qk.logSettings, c)
      toast.success("Réglages des journaux enregistrés.")
      onOpenChange(false)
    },
  })
  React.useEffect(() => {
    if (open) {
      setForm(toForm(initial))
      setLocal({})
      save.reset()
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [open])

  const set = (patch: Partial<Form>) => {
    setForm((f) => ({ ...f, ...patch }))
    setLocal({})
  }
  const err = (k: string) => local[k] ?? fieldError(save.error, k)
  const submit = (e: React.FormEvent) => {
    e.preventDefault()
    const days = Number(form.retentionDays)
    const mb = Number(form.maxSizeMb)
    const errs: Record<string, string> = {}
    if (!/^\d+$/.test(form.retentionDays.trim()) || days < 1 || days > 365) errs.retentionDays = "Entre 1 et 365 jours."
    if (!/^\d+$/.test(form.maxSizeMb.trim()) || mb < 10 || mb > 100000) errs.maxSizeMb = "Entre 10 et 100 000 Mo."
    if (Object.keys(errs).length) return setLocal(errs)
    save.mutate({ dnsQueries: form.dnsQueries, dhcpEvents: form.dhcpEvents, retentionDays: days, maxSizeMb: mb })
  }

  return (
    <Dialog open={open} onOpenChange={(o) => !save.isPending && onOpenChange(o)}>
      <DialogContent className="sm:max-w-md">
        <form onSubmit={submit} className="space-y-5" noValidate>
          <DialogHeader>
            <DialogTitle>Réglages des journaux</DialogTitle>
            <DialogDescription>Les mêmes réglages sur tous les nœuds ; chaque nœud garde ses propres journaux.</DialogDescription>
          </DialogHeader>
          <div className="space-y-4">
            <div className="flex items-center justify-between gap-4">
              <Label htmlFor="log-dns">Journaliser les requêtes DNS</Label>
              <Switch id="log-dns" checked={form.dnsQueries} onCheckedChange={(v) => set({ dnsQueries: v })} />
            </div>
            <div className="flex items-center justify-between gap-4">
              <Label htmlFor="log-dhcp">Journaliser les événements DHCP</Label>
              <Switch id="log-dhcp" checked={form.dhcpEvents} onCheckedChange={(v) => set({ dhcpEvents: v })} />
            </div>
            <div className="grid gap-4 sm:grid-cols-2">
              <Field label="Conserver (jours)" htmlFor="log-days" help="De 1 à 365." error={err("retentionDays")}>
                <Input
                  id="log-days"
                  type="number"
                  inputMode="numeric"
                  min={1}
                  max={365}
                  value={form.retentionDays}
                  onChange={(e) => set({ retentionDays: e.target.value })}
                />
              </Field>
              <Field label="Taille max (Mo)" htmlFor="log-mb" help="Les plus anciennes partent d'abord." error={err("maxSizeMb")}>
                <Input
                  id="log-mb"
                  type="number"
                  inputMode="numeric"
                  min={10}
                  max={100000}
                  value={form.maxSizeMb}
                  onChange={(e) => set({ maxSizeMb: e.target.value })}
                />
              </Field>
            </div>
          </div>
          <FormError message={formError(save.error, ["dnsQueries", "dhcpEvents", "retentionDays", "maxSizeMb"])} />
          <DialogFooter>
            <Button type="button" variant="outline" onClick={() => onOpenChange(false)} disabled={save.isPending}>
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
