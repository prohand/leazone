import * as React from "react"
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query"
import { Info, Loader2, Pencil, Plus, Trash2 } from "lucide-react"
import { toast } from "sonner"
import { api } from "@/api/client"
import { blockingSettingsQuery, blockPoliciesQuery, interfacesQuery, qk, vlansQuery } from "@/api/queries"
import type { BlockPolicy, BlockPolicyInput, BlockTargetKind } from "@/api/types"
import { ConfirmDialog } from "@/components/confirm-dialog"
import { Field, FormError } from "@/components/form-field"
import { WriteGuard } from "@/components/read-only"
import { BlockSpinner } from "@/components/spinner"
import { Badge } from "@/components/ui/badge"
import { Button } from "@/components/ui/button"
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle } from "@/components/ui/dialog"
import { Input } from "@/components/ui/input"
import { Label } from "@/components/ui/label"
import { RadioGroup, RadioGroupItem } from "@/components/ui/radio-group"
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select"
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table"
import { usePermissions } from "@/hooks/use-cluster"
import { targetKindLabel } from "@/lib/blocking"
import { errorMessage, fieldError, formError } from "@/lib/errors"
import { isCidr } from "@/lib/net"
import { cn } from "@/lib/utils"

// Most precise first, as the server applies them.
const kindOrder: Record<BlockTargetKind, number> = { network: 0, vlan: 1, interface: 2 }

function useVlanNames() {
  const vlans = useQuery(vlansQuery)
  return React.useMemo(() => {
    const m = new Map<string, string>()
    for (const v of vlans.data?.items ?? []) if (v.vlanId != null && v.name) m.set(String(v.vlanId), v.name)
    return m
  }, [vlans.data])
}

function EffectBadge({ enabled }: { enabled: boolean }) {
  return enabled ? (
    <Badge variant="outline" className="border-destructive/40 text-destructive">
      Bloquer
    </Badge>
  ) : (
    <Badge variant="outline" className="border-success/40 text-success">
      Ne pas bloquer
    </Badge>
  )
}

/** Where blocking applies: per interface, VLAN or client network. */
export function PoliciesTab() {
  const qc = useQueryClient()
  const perms = usePermissions()
  const canEdit = perms.can("config.write")
  const policies = useQuery(blockPoliciesQuery)
  const settings = useQuery(blockingSettingsQuery)
  const vlanNames = useVlanNames()
  const [editing, setEditing] = React.useState<{ policy: BlockPolicy | null } | null>(null)
  const [deleting, setDeleting] = React.useState<BlockPolicy | null>(null)

  const remove = useMutation({
    mutationFn: (id: string) => api.delete("/blocking/policies/{id}", { params: { id } }),
    onSuccess: () => {
      toast.success("Règle supprimée.")
      void qc.invalidateQueries({ queryKey: qk.blockPolicies })
    },
  })

  const items = [...(policies.data?.items ?? [])].sort(
    (a, b) => kindOrder[a.targetKind] - kindOrder[b.targetKind] || a.target.localeCompare(b.target, "fr", { numeric: true }),
  )
  const label = (p: BlockPolicy) =>
    p.targetKind === "vlan" ? `VLAN ${p.target}${vlanNames.get(p.target) ? ` · ${vlanNames.get(p.target)}` : ""}` : p.target

  return (
    <div className="space-y-4">
      <div className="flex flex-col gap-3 sm:flex-row sm:items-start sm:justify-between">
        <p className="flex max-w-2xl items-start gap-2 text-sm text-muted-foreground">
          <Info className="mt-0.5 size-4 shrink-0" />
          La règle la plus précise gagne : réseau client, puis VLAN, puis interface. Sinon : réglage par défaut.
        </p>
        {perms.allowed("config.write") && (
          <WriteGuard>
            <Button onClick={() => setEditing({ policy: null })}>
              <Plus /> Ajouter une règle
            </Button>
          </WriteGuard>
        )}
      </div>
      {policies.isPending ? (
        <BlockSpinner />
      ) : policies.isError ? (
        <p className="text-sm text-destructive">{errorMessage(policies.error)}</p>
      ) : (
        <div className="rounded-lg border">
          <Table>
            <TableHeader>
              <TableRow className="hover:bg-transparent">
                <TableHead className="text-xs text-muted-foreground">Cible</TableHead>
                <TableHead className="text-xs text-muted-foreground">Blocage</TableHead>
                <TableHead className="text-xs text-muted-foreground">Commentaire</TableHead>
                <TableHead className="w-0" />
              </TableRow>
            </TableHeader>
            <TableBody>
              {items.map((p) => (
                <TableRow key={p.id ?? `${p.targetKind}-${p.target}`}>
                  <TableCell>
                    <div className="flex flex-wrap items-center gap-2">
                      <Badge variant="secondary">{targetKindLabel[p.targetKind]}</Badge>
                      <span className="font-mono text-sm">{label(p)}</span>
                    </div>
                  </TableCell>
                  <TableCell>
                    <EffectBadge enabled={p.enabled} />
                  </TableCell>
                  <TableCell className="text-sm text-muted-foreground">{p.comment || "—"}</TableCell>
                  <TableCell>
                    {canEdit && (
                      <div className="flex justify-end gap-1">
                        <Button variant="ghost" size="icon-sm" aria-label={`Modifier ${label(p)}`} onClick={() => setEditing({ policy: p })}>
                          <Pencil />
                        </Button>
                        <Button
                          variant="ghost"
                          size="icon-sm"
                          className="text-muted-foreground hover:text-destructive"
                          aria-label={`Supprimer ${label(p)}`}
                          onClick={() => setDeleting(p)}
                        >
                          <Trash2 />
                        </Button>
                      </div>
                    )}
                  </TableCell>
                </TableRow>
              ))}
              <TableRow className="bg-muted/30 hover:bg-muted/30" data-testid="policy-default">
                <TableCell>
                  <span className="text-sm font-medium">Partout ailleurs</span>
                </TableCell>
                <TableCell>{settings.data ? <EffectBadge enabled={settings.data.defaultEnabled !== false} /> : "—"}</TableCell>
                <TableCell className="text-sm text-muted-foreground">Réglage par défaut (onglet Réglages)</TableCell>
                <TableCell />
              </TableRow>
            </TableBody>
          </Table>
        </div>
      )}
      <PolicyDialog
        open={!!editing}
        onOpenChange={(o) => !o && setEditing(null)}
        policy={editing?.policy ?? null}
        defaultEnabled={settings.data?.defaultEnabled !== false}
      />
      {deleting && (
        <ConfirmDialog
          open={!!deleting}
          onOpenChange={(o) => !o && setDeleting(null)}
          title={`Supprimer la règle pour ${label(deleting)} ?`}
          description="Cette cible suivra ensuite une règle moins précise, ou le réglage par défaut."
          confirmLabel="Supprimer"
          destructive
          onConfirm={() => remove.mutateAsync(deleting.id ?? "")}
        />
      )}
    </div>
  )
}

type Form = { targetKind: BlockTargetKind; iface: string; vlan: string; network: string; enabled: "on" | "off"; comment: string }

function PolicyDialog({
  open,
  onOpenChange,
  policy,
  defaultEnabled,
}: {
  open: boolean
  onOpenChange: (o: boolean) => void
  policy: BlockPolicy | null
  /** Default setting: a new rule usually says the opposite. */
  defaultEnabled: boolean
}) {
  const qc = useQueryClient()
  const ifaces = useQuery({ ...interfacesQuery, enabled: open, refetchInterval: false })
  const vlanNames = useVlanNames()
  const [form, setForm] = React.useState<Form>({ targetKind: "interface", iface: "", vlan: "", network: "", enabled: "off", comment: "" })
  const [local, setLocal] = React.useState<Record<string, string>>({})

  const save = useMutation({
    mutationFn: (body: BlockPolicyInput) =>
      policy?.id ? api.put("/blocking/policies/{id}", { params: { id: policy.id }, body }) : api.post("/blocking/policies", { body }),
    meta: { silent: true },
    onSuccess: () => {
      void qc.invalidateQueries({ queryKey: qk.blockPolicies })
      toast.success(policy ? "Règle modifiée." : "Règle ajoutée.")
      onOpenChange(false)
    },
  })

  React.useEffect(() => {
    if (open) {
      const p = policy
      setForm({
        targetKind: p?.targetKind ?? "interface",
        iface: p?.targetKind === "interface" ? p.target : "",
        vlan: p?.targetKind === "vlan" ? p.target : "",
        network: p?.targetKind === "network" ? p.target : "",
        enabled: p ? (p.enabled ? "on" : "off") : defaultEnabled ? "off" : "on",
        comment: p?.comment ?? "",
      })
      setLocal({})
      save.reset()
    }
    // Reset only when the dialog opens.
  }, [open])

  const set = (patch: Partial<Form>) => {
    setForm((f) => ({ ...f, ...patch }))
    setLocal({})
    if (save.isError) save.reset()
  }
  const err = (k: string) => local[k] ?? fieldError(save.error, k)
  const names = (ifaces.data?.items ?? []).filter((i) => i.type !== "loopback").map((i) => i.name ?? "").filter(Boolean)
  if (form.iface && !names.includes(form.iface)) names.push(form.iface)

  const submit = (e: React.FormEvent) => {
    e.preventDefault()
    let target = ""
    const errs: Record<string, string> = {}
    if (form.targetKind === "interface") {
      target = form.iface
      if (!target) errs.target = "Choisissez une interface."
    } else if (form.targetKind === "vlan") {
      target = form.vlan.trim()
      const n = Number(target)
      if (!/^\d+$/.test(target) || n < 1 || n > 4094) errs.target = "Numéro de VLAN entre 1 et 4094."
    } else {
      target = form.network.trim()
      if (!isCidr(target)) errs.target = "Réseau non valide (ex. : 192.168.20.0/24)."
    }
    setLocal(errs)
    if (Object.keys(errs).length) return
    save.mutate({ targetKind: form.targetKind, target, enabled: form.enabled === "on", comment: form.comment.trim() || undefined })
  }

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="max-h-[90svh] overflow-y-auto sm:max-w-lg">
        <form onSubmit={submit} className="space-y-4">
          <DialogHeader>
            <DialogTitle>{policy ? "Modifier la règle" : "Où bloquer ?"}</DialogTitle>
            <DialogDescription>Choisissez une cible puis si le blocage s'y applique.</DialogDescription>
          </DialogHeader>
          <Field label="Type de cible" htmlFor="pol-kind">
            <Select value={form.targetKind} onValueChange={(v) => set({ targetKind: v as BlockTargetKind })}>
              <SelectTrigger id="pol-kind" className="w-full">
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="interface">Interface</SelectItem>
                <SelectItem value="vlan">VLAN</SelectItem>
                <SelectItem value="network">Réseau client</SelectItem>
              </SelectContent>
            </Select>
          </Field>
          {form.targetKind === "interface" && (
            <Field label="Interface" htmlFor="pol-iface" error={err("target")}>
              <Select value={form.iface} onValueChange={(v) => set({ iface: v })}>
                <SelectTrigger id="pol-iface" className="w-full font-mono">
                  <SelectValue placeholder={ifaces.isPending ? "Chargement…" : "Choisir une interface"} />
                </SelectTrigger>
                <SelectContent>
                  {names.map((n) => (
                    <SelectItem key={n} value={n} className="font-mono">
                      {n}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </Field>
          )}
          {form.targetKind === "vlan" && (
            <Field
              label="Numéro de VLAN"
              htmlFor="pol-vlan"
              help={vlanNames.get(form.vlan.trim()) ? `VLAN « ${vlanNames.get(form.vlan.trim())} »` : "Entre 1 et 4094."}
              error={err("target")}
            >
              <Input id="pol-vlan" inputMode="numeric" value={form.vlan} onChange={(e) => set({ vlan: e.target.value })} placeholder="20" />
            </Field>
          )}
          {form.targetKind === "network" && (
            <Field label="Réseau des clients" htmlFor="pol-net" help="Adresse et masque, ex. : 192.168.20.0/24." error={err("target")}>
              <Input
                id="pol-net"
                autoCapitalize="none"
                spellCheck={false}
                className="font-mono"
                value={form.network}
                onChange={(e) => set({ network: e.target.value })}
                placeholder="192.168.20.0/24"
              />
            </Field>
          )}
          <Field label="Blocage" error={err("enabled")}>
            <RadioGroup value={form.enabled} onValueChange={(v) => set({ enabled: v as Form["enabled"] })} className="grid-cols-2">
              {(["on", "off"] as const).map((v) => (
                <Label
                  key={v}
                  htmlFor={`pol-${v}`}
                  className={cn(
                    "flex cursor-pointer items-center gap-2 rounded-lg border p-3 font-normal",
                    form.enabled === v && "border-primary",
                  )}
                >
                  <RadioGroupItem value={v} id={`pol-${v}`} />
                  {v === "on" ? "Bloquer" : "Ne pas bloquer"}
                </Label>
              ))}
            </RadioGroup>
          </Field>
          <Field label="Commentaire (facultatif)" htmlFor="pol-comment" error={err("comment")}>
            <Input id="pol-comment" value={form.comment} onChange={(e) => set({ comment: e.target.value })} placeholder="Ex. : pas de blocage pour le bureau" />
          </Field>
          <FormError message={formError(save.error, ["targetKind", "target", "enabled", "comment"])} />
          <DialogFooter>
            <Button type="button" variant="outline" onClick={() => onOpenChange(false)}>
              Annuler
            </Button>
            <Button type="submit" disabled={save.isPending}>
              {save.isPending && <Loader2 className="animate-spin" />}
              {policy ? "Enregistrer" : "Ajouter"}
            </Button>
          </DialogFooter>
        </form>
      </DialogContent>
    </Dialog>
  )
}
