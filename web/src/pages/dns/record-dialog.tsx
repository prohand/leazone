import * as React from "react"
import { useMutation, useQueryClient } from "@tanstack/react-query"
import { Loader2 } from "lucide-react"
import { toast } from "sonner"
import { api } from "@/api/client"
import { qk } from "@/api/queries"
import type { DnsRecord, RecordData, RecordInput, RecordType, Zone } from "@/api/types"
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
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select"
import { Textarea } from "@/components/ui/textarea"
import { humanDuration, recordTypeHelp, recordTypes } from "@/lib/dns"
import { fieldError, formError } from "@/lib/errors"
import { isIPv4, isIPv6 } from "@/lib/net"

type DataKey = keyof RecordData
type Form = { name: string; type: RecordType; ttl: string } & Record<DataKey, string>

// Data fields of each type, in display order.
const fieldsByType: Record<RecordType, DataKey[]> = {
  A: ["ip"],
  AAAA: ["ip"],
  CNAME: ["target"],
  PTR: ["target"],
  NS: ["host"],
  MX: ["preference", "exchange"],
  TXT: ["text"],
  SRV: ["priority", "weight", "port", "target"],
}
const numeric: DataKey[] = ["preference", "priority", "weight", "port"]
const allDataKeys: DataKey[] = ["ip", "target", "host", "preference", "exchange", "text", "priority", "weight", "port"]

function dataLabel(type: RecordType, k: DataKey): { label: string; placeholder?: string; help?: string } {
  switch (k) {
    case "ip":
      return type === "A"
        ? { label: "Adresse IPv4", placeholder: "192.168.1.10" }
        : { label: "Adresse IPv6", placeholder: "fd00::10" }
    case "target":
      if (type === "CNAME") return { label: "Nom cible", placeholder: "nas", help: "Nom relatif à la zone, ou complet avec un point final (ex. : exemple.com.)." }
      if (type === "PTR") return { label: "Nom de la machine", placeholder: "nas.maison.lan.", help: "Nom complet avec un point final." }
      return { label: "Serveur cible", placeholder: "sip.maison.lan.", help: "Machine qui offre le service." }
    case "host":
      return { label: "Serveur DNS", placeholder: "ns1.maison.lan." }
    case "preference":
      return { label: "Priorité", placeholder: "10", help: "Le plus petit nombre est essayé en premier." }
    case "exchange":
      return { label: "Serveur de messagerie", placeholder: "mail" }
    case "text":
      return { label: "Texte", placeholder: "v=spf1 mx -all", help: "Les textes longs sont découpés automatiquement." }
    case "priority":
      return { label: "Priorité", placeholder: "10" }
    case "weight":
      return { label: "Poids", placeholder: "5" }
    case "port":
      return { label: "Port", placeholder: "5060" }
  }
}

function emptyForm(type: RecordType): Form {
  return { name: "", type, ttl: "", ip: "", target: "", host: "", preference: "", exchange: "", text: "", priority: "", weight: "", port: "" }
}

function recordToForm(r: DnsRecord): Form {
  const f = emptyForm(r.type ?? "A")
  f.name = r.name ?? ""
  f.ttl = r.ttl === null || r.ttl === undefined ? "" : String(r.ttl)
  for (const k of allDataKeys) {
    const v = r.data?.[k]
    if (v !== undefined && v !== null) f[k] = String(v)
  }
  return f
}

/** Fully qualified preview of the name typed in the form. */
function preview(name: string, zone: string) {
  const n = name.trim()
  const z = zone.replace(/\.$/, "")
  if (!n || n === "@") return `${z}.`
  if (n.endsWith(".")) return n
  if (n === z || n.endsWith("." + z)) return `${n}.`
  return `${n}.${z}.`
}

export function RecordDialog({
  zone,
  record,
  open,
  onOpenChange,
}: {
  zone: Zone
  /** null = new record */
  record: DnsRecord | null
  open: boolean
  onOpenChange: (o: boolean) => void
}) {
  const qc = useQueryClient()
  const zoneId = zone.id ?? ""
  const defaultType: RecordType = zone.kind === "reverse" ? "PTR" : "A"
  const [form, setForm] = React.useState<Form>(() => emptyForm(defaultType))
  const [local, setLocal] = React.useState<Record<string, string>>({})

  const save = useMutation({
    mutationFn: (body: RecordInput) =>
      record?.id
        ? api.put("/dns/zones/{id}/records/{rid}", { params: { id: zoneId, rid: record.id }, body })
        : api.post("/dns/zones/{id}/records", { params: { id: zoneId }, body }),
    meta: { silent: true },
    onSuccess: (r) => {
      void qc.invalidateQueries({ queryKey: qk.records(zoneId) })
      void qc.invalidateQueries({ queryKey: qk.zone(zoneId) })
      void qc.invalidateQueries({ queryKey: qk.zones, exact: true })
      toast.success(record ? "Enregistrement modifié." : `Enregistrement ${r.fqdn ?? r.name ?? ""} ajouté.`)
      onOpenChange(false)
    },
  })

  React.useEffect(() => {
    if (open) {
      setForm(record ? recordToForm(record) : emptyForm(defaultType))
      setLocal({})
      save.reset()
    }
  }, [open])

  const set = <K extends keyof Form>(k: K, v: Form[K]) => {
    setForm((f) => ({ ...f, [k]: v }))
    // A server error is about the old values: hide it once the user edits.
    if (save.isError) save.reset()
  }
  const err = (k: string) => local[k] ?? fieldError(save.error, k)
  const fields = fieldsByType[form.type]
  const known = ["name", "type", "ttl", ...fields.map((k) => `data.${k}`)]

  const submit = (e: React.FormEvent) => {
    e.preventDefault()
    const errors: Record<string, string> = {}
    const data: RecordData = {}
    for (const k of fields) {
      const raw = form[k].trim()
      if (!raw) {
        errors[`data.${k}`] = "Obligatoire."
        continue
      }
      if (numeric.includes(k)) {
        const n = Number(raw)
        if (!Number.isInteger(n) || n < 0 || n > 65535) errors[`data.${k}`] = "Nombre entre 0 et 65535."
        else (data as Record<string, number>)[k] = n
      } else {
        ;(data as Record<string, string>)[k] = k === "text" ? form[k] : raw
      }
    }
    if (form.type === "A" && data.ip && !isIPv4(data.ip)) errors["data.ip"] = "Adresse IPv4 non valide (ex. : 192.168.1.10)."
    if (form.type === "AAAA" && data.ip && !isIPv6(data.ip)) errors["data.ip"] = "Adresse IPv6 non valide (ex. : fd00::10)."
    let ttl: number | null = null
    if (form.ttl.trim()) {
      const n = Number(form.ttl)
      if (!Number.isInteger(n) || n < 0 || n > 2147483647) errors.ttl = "Nombre de secondes entier."
      else ttl = n
    }
    setLocal(errors)
    if (Object.keys(errors).length) return
    save.mutate({ name: form.name.trim() || "@", type: form.type, ttl, data })
  }

  const zoneName = zone.name ?? ""
  const reverse = zone.kind === "reverse"
  const ttlNum = Number(form.ttl)

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="max-h-[90svh] overflow-y-auto sm:max-w-lg">
        <form onSubmit={submit} className="space-y-4">
          <DialogHeader>
            <DialogTitle>{record ? "Modifier l'enregistrement" : "Ajouter un enregistrement"}</DialogTitle>
            <DialogDescription>Zone {zoneName}</DialogDescription>
          </DialogHeader>
          <div className="grid gap-4 sm:grid-cols-[1fr_9rem]">
            <Field
              label="Nom"
              htmlFor="rec-name"
              help={
                <>
                  {reverse ? "Fin de l'adresse, ex. : 10 pour …10. " : "@ = la zone elle-même. "}
                  <span className="font-mono">{preview(form.name, zoneName)}</span>
                </>
              }
              error={err("name")}
            >
              <Input
                id="rec-name"
                autoFocus
                autoCapitalize="none"
                spellCheck={false}
                value={form.name}
                onChange={(e) => set("name", e.target.value)}
                placeholder="@"
              />
            </Field>
            <Field label="Type" htmlFor="rec-type" error={err("type")}>
              <Select value={form.type} onValueChange={(v) => set("type", v as RecordType)}>
                <SelectTrigger id="rec-type" className="w-full">
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  {recordTypes.map((t) => (
                    <SelectItem key={t} value={t}>
                      {t}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </Field>
          </div>
          <p className="-mt-2 text-xs text-muted-foreground">{recordTypeHelp[form.type]}</p>

          <div
            className={
              form.type === "SRV"
                ? "grid gap-4 sm:grid-cols-3"
                : form.type === "MX"
                  ? "grid gap-4 sm:grid-cols-[8rem_1fr]"
                  : "space-y-4"
            }
          >
            {fields.map((k) => {
              const meta = dataLabel(form.type, k)
              const wide = form.type === "SRV" && k === "target"
              return (
                <Field
                  key={`${form.type}-${k}`}
                  label={meta.label}
                  htmlFor={`rec-${k}`}
                  help={meta.help}
                  error={err(`data.${k}`)}
                  className={wide ? "sm:col-span-3" : undefined}
                >
                  {k === "text" ? (
                    <Textarea
                      id={`rec-${k}`}
                      rows={4}
                      className="font-mono text-sm"
                      spellCheck={false}
                      value={form[k]}
                      placeholder={meta.placeholder}
                      onChange={(e) => set(k, e.target.value)}
                    />
                  ) : (
                    <Input
                      id={`rec-${k}`}
                      inputMode={numeric.includes(k) ? "numeric" : undefined}
                      autoCapitalize="none"
                      spellCheck={false}
                      className={numeric.includes(k) ? undefined : "font-mono"}
                      value={form[k]}
                      placeholder={meta.placeholder}
                      onChange={(e) => set(k, e.target.value)}
                    />
                  )}
                </Field>
              )
            })}
          </div>

          <Field
            label="TTL (secondes, facultatif)"
            htmlFor="rec-ttl"
            help={
              form.ttl.trim() && Number.isFinite(ttlNum)
                ? `= ${humanDuration(ttlNum)}`
                : `Vide = TTL par défaut de la zone (${zone.ttl ?? 3600} s).`
            }
            error={err("ttl")}
          >
            <Input
              id="rec-ttl"
              inputMode="numeric"
              value={form.ttl}
              placeholder={`défaut (${zone.ttl ?? 3600})`}
              onChange={(e) => set("ttl", e.target.value)}
            />
          </Field>
          <FormError message={formError(save.error, known)} />
          <DialogFooter>
            <Button type="button" variant="ghost" onClick={() => onOpenChange(false)}>
              Annuler
            </Button>
            <Button type="submit" disabled={save.isPending}>
              {save.isPending && <Loader2 className="animate-spin" />}
              {record ? "Enregistrer" : "Ajouter"}
            </Button>
          </DialogFooter>
        </form>
      </DialogContent>
    </Dialog>
  )
}
