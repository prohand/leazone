import * as React from "react"
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query"
import { Loader2 } from "lucide-react"
import { toast } from "sonner"
import { api } from "@/api/client"
import { qk, scopesQuery } from "@/api/queries"
import type { Reservation, ReservationInput } from "@/api/types"
import { Field, FormError } from "@/components/form-field"
import { Button } from "@/components/ui/button"
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog"
import { Input } from "@/components/ui/input"
import { Label } from "@/components/ui/label"
import { RadioGroup, RadioGroupItem } from "@/components/ui/radio-group"
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select"
import { Textarea } from "@/components/ui/textarea"
import { ipToInt, net4String, netContains, normalizeMac, parseNet4 } from "@/lib/dhcp"
import { fieldError, formError } from "@/lib/errors"
import { isIPv4 } from "@/lib/net"

type Form = {
  scopeId: string
  by: "mac" | "clientId"
  mac: string
  clientId: string
  ip: string
  hostname: string
  description: string
}

const known = ["scopeId", "mac", "clientId", "ip", "hostname", "description"]

export function ReservationDialog({
  open,
  onOpenChange,
  reservation,
  defaultScopeId,
}: {
  open: boolean
  onOpenChange: (o: boolean) => void
  /** null = new reservation */
  reservation: Reservation | null
  defaultScopeId?: string
}) {
  const qc = useQueryClient()
  const scopes = useQuery({ ...scopesQuery, enabled: open })
  const [form, setForm] = React.useState<Form>({ scopeId: "", by: "mac", mac: "", clientId: "", ip: "", hostname: "", description: "" })
  const [local, setLocal] = React.useState<Record<string, string>>({})

  const save = useMutation({
    mutationFn: (body: ReservationInput) =>
      reservation?.id
        ? api.put("/dhcp/reservations/{id}", { params: { id: reservation.id }, body })
        : api.post("/dhcp/reservations", { body }),
    meta: { silent: true },
    onSuccess: (r) => {
      void qc.invalidateQueries({ queryKey: qk.dhcp })
      void qc.invalidateQueries({ queryKey: qk.vlans })
      toast.success(reservation ? "Réservation modifiée." : `${r.ip} réservée.`)
      onOpenChange(false)
    },
  })

  React.useEffect(() => {
    if (!open) return
    const r = reservation
    setForm({
      scopeId: r?.scopeId ?? defaultScopeId ?? "",
      by: r && !r.mac && r.clientId ? "clientId" : "mac",
      mac: r?.mac ?? "",
      clientId: r?.clientId ?? "",
      ip: r?.ip ?? "",
      hostname: r?.hostname ?? "",
      description: r?.description ?? "",
    })
    setLocal({})
    save.reset()
    // Reset only when the dialog opens.
  }, [open])

  // A single scope: pick it.
  const items = scopes.data?.items ?? []
  React.useEffect(() => {
    if (open && !form.scopeId && items.length === 1) setForm((f) => ({ ...f, scopeId: items[0].id ?? "" }))
  }, [open, items.length])

  const set = (patch: Partial<Form>) => setForm((f) => ({ ...f, ...patch }))
  const err = (k: string) => local[k] ?? fieldError(save.error, k)
  const scope = items.find((s) => s.id === form.scopeId)
  const net = parseNet4(scope?.network ?? "")

  const inRange = (ip: string) => {
    const v = ipToInt(ip)
    const a = ipToInt(scope?.rangeStart ?? "")
    const b = ipToInt(scope?.rangeEnd ?? "")
    return v !== null && a !== null && b !== null && v >= a && v <= b
  }

  const submit = (e: React.FormEvent) => {
    e.preventDefault()
    const errors: Record<string, string> = {}
    if (!form.scopeId) errors.scopeId = "Choisissez une étendue."
    let mac = ""
    if (form.by === "mac") {
      const m = normalizeMac(form.mac)
      if (!m) errors.mac = "Adresse MAC non valide (ex. : aa:bb:cc:dd:ee:ff)."
      else mac = m
    } else if (!/^[0-9a-fA-F]{2}(:?[0-9a-fA-F]{2})+$/.test(form.clientId.trim())) {
      errors.clientId = "Identifiant en hexadécimal (ex. : 01:aa:bb:cc:dd:ee:ff)."
    }
    const ip = form.ip.trim()
    if (!isIPv4(ip)) errors.ip = "Adresse IPv4 non valide."
    else if (net && !netContains(net, ip)) errors.ip = `L'adresse doit être dans ${net4String(net)}.`
    if (form.hostname.trim() && !/^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?$/.test(form.hostname.trim()))
      errors.hostname = "Lettres, chiffres et tirets seulement (ex. : imprimante-rdc)."
    setLocal(errors)
    if (Object.keys(errors).length > 0) return
    if (mac) set({ mac })
    save.mutate({
      scopeId: form.scopeId,
      mac: form.by === "mac" ? mac : "",
      clientId: form.by === "clientId" ? form.clientId.trim().toLowerCase() : "",
      ip,
      hostname: form.hostname.trim(),
      description: form.description.trim(),
    })
  }

  const ipHint = scope
    ? `Dans ${scope.network}. Plage dynamique : ${scope.rangeStart} – ${scope.rangeEnd}. Une adresse hors de la plage évite toute confusion.`
    : "Choisissez d'abord l'étendue."

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="max-h-[90svh] overflow-y-auto sm:max-w-lg">
        <form onSubmit={submit} className="space-y-4" noValidate>
          <DialogHeader>
            <DialogTitle>{reservation ? "Modifier la réservation" : "Nouvelle réservation"}</DialogTitle>
            <DialogDescription>Un appareil reçoit toujours la même adresse IP.</DialogDescription>
          </DialogHeader>

          <Field label="Étendue" htmlFor="rs-scope" error={err("scopeId")}>
            <Select value={form.scopeId} onValueChange={(v) => set({ scopeId: v })}>
              <SelectTrigger id="rs-scope" className="w-full">
                <SelectValue placeholder={scopes.isPending ? "Chargement…" : "Choisir une étendue"} />
              </SelectTrigger>
              <SelectContent>
                {items.map((s) => (
                  <SelectItem key={s.id} value={s.id ?? ""}>
                    {s.name} <span className="font-mono text-xs text-muted-foreground">{s.network}</span>
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
          </Field>

          <div className="space-y-2">
            <Label>Identifier l'appareil par</Label>
            <RadioGroup value={form.by} onValueChange={(v) => set({ by: v as Form["by"] })} className="flex flex-wrap gap-4">
              <label className="flex items-center gap-2 text-sm">
                <RadioGroupItem value="mac" /> Adresse MAC
              </label>
              <label className="flex items-center gap-2 text-sm">
                <RadioGroupItem value="clientId" /> Identifiant client (option 61)
              </label>
            </RadioGroup>
          </div>

          {form.by === "mac" ? (
            <Field label="Adresse MAC" htmlFor="rs-mac" error={err("mac")} help="Tous les formats sont acceptés : aa-bb-cc…, AABBCC…">
              <Input
                id="rs-mac"
                className="font-mono"
                autoCapitalize="none"
                spellCheck={false}
                value={form.mac}
                onChange={(e) => set({ mac: e.target.value })}
                onBlur={() => {
                  const m = normalizeMac(form.mac)
                  if (m) set({ mac: m })
                }}
                placeholder="aa:bb:cc:dd:ee:ff"
              />
            </Field>
          ) : (
            <Field label="Identifiant client" htmlFor="rs-cid" error={err("clientId")} help="En hexadécimal, tel qu'envoyé par l'appareil.">
              <Input
                id="rs-cid"
                className="font-mono"
                autoCapitalize="none"
                spellCheck={false}
                value={form.clientId}
                onChange={(e) => set({ clientId: e.target.value })}
                placeholder="01:aa:bb:cc:dd:ee:ff"
              />
            </Field>
          )}

          <Field label="Adresse IP" htmlFor="rs-ip" error={err("ip")} help={ipHint}>
            <Input
              id="rs-ip"
              className="font-mono"
              value={form.ip}
              onChange={(e) => set({ ip: e.target.value })}
              placeholder={net ? `${scope?.network?.split(".").slice(0, 3).join(".")}.20` : "192.168.20.20"}
            />
            {scope && isIPv4(form.ip.trim()) && inRange(form.ip.trim()) && !err("ip") && (
              <p className="text-xs text-warning">Cette adresse est dans la plage dynamique : elle ne sera plus donnée à d'autres.</p>
            )}
          </Field>

          <Field label="Nom d'hôte (facultatif)" htmlFor="rs-host" error={err("hostname")} help="Utilisé pour le nom DNS automatique.">
            <Input
              id="rs-host"
              autoCapitalize="none"
              spellCheck={false}
              value={form.hostname}
              onChange={(e) => set({ hostname: e.target.value })}
              placeholder="imprimante-rdc"
            />
          </Field>

          <Field label="Description (facultatif)" htmlFor="rs-desc" error={err("description")}>
            <Textarea
              id="rs-desc"
              rows={2}
              value={form.description}
              onChange={(e) => set({ description: e.target.value })}
              placeholder="Imprimante du rez-de-chaussée"
            />
          </Field>

          <FormError message={formError(save.error, known)} />
          <DialogFooter>
            <Button type="button" variant="ghost" onClick={() => onOpenChange(false)}>
              Annuler
            </Button>
            <Button type="submit" disabled={save.isPending}>
              {save.isPending && <Loader2 className="animate-spin" />}
              {reservation ? "Enregistrer" : "Réserver"}
            </Button>
          </DialogFooter>
        </form>
      </DialogContent>
    </Dialog>
  )
}
