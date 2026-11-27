import * as React from "react"
import { useMutation, useQueryClient } from "@tanstack/react-query"
import { ChevronRight, FileUp, Loader2, TriangleAlert } from "lucide-react"
import { toast } from "sonner"
import { api } from "@/api/client"
import { qk } from "@/api/queries"
import type { Soa, Zone } from "@/api/types"
import { Field, FormError } from "@/components/form-field"
import { Alert, AlertDescription } from "@/components/ui/alert"
import { Button } from "@/components/ui/button"
import { Checkbox } from "@/components/ui/checkbox"
import { Collapsible, CollapsibleContent, CollapsibleTrigger } from "@/components/ui/collapsible"
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
import { Textarea } from "@/components/ui/textarea"
import { humanDuration } from "@/lib/dns"
import { fieldError, formError } from "@/lib/errors"
import { isCidr } from "@/lib/net"
import { cn } from "@/lib/utils"

// ---- SOA fields shared by "Nouvelle zone" and "Paramètres" ----

type SoaForm = Record<keyof Soa, string>
const soaKeys: (keyof Soa)[] = ["primaryNs", "adminEmail", "refresh", "retry", "expire", "minimum"]
const soaNumeric: (keyof Soa)[] = ["refresh", "retry", "expire", "minimum"]
const soaDefaults: Record<string, number> = { refresh: 3600, retry: 600, expire: 604800, minimum: 300 }
/* Bounds of the server (internal/dnsconf): 32-bit timers (RFC 2181: 2^31 − 1 at most), negative TTL ≤ 1 day. */
const SOA_MAX: Record<string, number> = { refresh: 2147483647, retry: 2147483647, expire: 2147483647, minimum: 86400 }
/** Default TTL of a zone: 1 s to 7 days (internal/dnsconf/zones.go). */
const ZONE_TTL_MAX = 604800

const emptySoa = (): SoaForm => ({ primaryNs: "", adminEmail: "", refresh: "", retry: "", expire: "", minimum: "" })
const soaToForm = (s?: Soa): SoaForm => {
  const f = emptySoa()
  for (const k of soaKeys) if (s?.[k] !== undefined && s[k] !== null) f[k] = String(s[k])
  return f
}

const soaLabels: Record<keyof Soa, { label: string; help: string }> = {
  primaryNs: { label: "Serveur principal", help: "ex. : ns1.maison.lan." },
  adminEmail: { label: "E-mail de l'administrateur", help: "ex. : admin@maison.lan" },
  refresh: { label: "Rafraîchissement (s)", help: "Délai avant qu'un serveur secondaire revérifie la zone." },
  retry: { label: "Nouvel essai (s)", help: "Délai avant un nouvel essai si le rafraîchissement échoue." },
  expire: { label: "Expiration (s)", help: "Un secondaire arrête de répondre après ce délai sans nouvelles." },
  minimum: { label: "TTL négatif (s)", help: "Durée en cache d'une réponse « nom inconnu »." },
}

/** Checks the SOA form; returns errors keyed like the API ("soa.refresh"). */
function checkSoa(f: SoaForm): { soa?: Soa; errors: Record<string, string> } {
  const errors: Record<string, string> = {}
  const soa: Soa = {}
  if (f.primaryNs.trim()) soa.primaryNs = f.primaryNs.trim()
  if (f.adminEmail.trim()) soa.adminEmail = f.adminEmail.trim()
  for (const k of soaNumeric) {
    const v = f[k].trim()
    if (!v) continue
    const n = Number(v)
    if (!/^\d+$/.test(v) || !Number.isSafeInteger(n) || n > SOA_MAX[k])
      errors[`soa.${k}`] = `Nombre de secondes entier, entre 0 (valeur par défaut) et ${SOA_MAX[k].toLocaleString("fr-FR")}.`
    else (soa as Record<string, unknown>)[k] = n
  }
  return { soa: Object.keys(soa).length ? soa : undefined, errors }
}

function SoaFields({
  value,
  onChange,
  errors,
  idPrefix,
  placeholders,
}: {
  value: SoaForm
  onChange: (v: SoaForm, changed: keyof Soa) => void
  errors: (key: string) => string | undefined
  idPrefix: string
  placeholders?: Partial<SoaForm>
}) {
  return (
    <div className="grid gap-4 sm:grid-cols-2">
      {soaKeys.map((k) => {
        const n = Number(value[k] || placeholders?.[k] || soaDefaults[k])
        const isNum = soaNumeric.includes(k)
        return (
          <Field
            key={k}
            label={soaLabels[k].label}
            htmlFor={`${idPrefix}-${k}`}
            help={isNum && Number.isFinite(n) ? `${soaLabels[k].help} (= ${humanDuration(n)})` : soaLabels[k].help}
            error={errors(`soa.${k}`)}
          >
            <Input
              id={`${idPrefix}-${k}`}
              inputMode={isNum ? "numeric" : undefined}
              autoCapitalize="none"
              spellCheck={false}
              value={value[k]}
              placeholder={placeholders?.[k] ?? (isNum ? String(soaDefaults[k]) : "automatique")}
              onChange={(e) => onChange({ ...value, [k]: e.target.value }, k)}
            />
          </Field>
        )
      })}
    </div>
  )
}

function SoaSection(props: React.ComponentProps<typeof SoaFields> & { defaultOpen?: boolean }) {
  const { defaultOpen, ...rest } = props
  const [open, setOpen] = React.useState(!!defaultOpen)
  return (
    <Collapsible open={open} onOpenChange={setOpen} className="rounded-lg border">
      <CollapsibleTrigger asChild>
        <button
          type="button"
          className="flex w-full items-center gap-2 px-3 py-2.5 text-left text-sm font-medium hover:bg-muted/50"
        >
          <ChevronRight className={cn("size-4 transition-transform", open && "rotate-90")} />
          SOA avancé
          <span className="ml-auto text-xs font-normal text-muted-foreground">facultatif</span>
        </button>
      </CollapsibleTrigger>
      <CollapsibleContent className="border-t p-3">
        <SoaFields {...rest} />
      </CollapsibleContent>
    </Collapsible>
  )
}

const ttlHelp = (ttl: string) => {
  const n = Number(ttl)
  return `Durée en cache des enregistrements sans TTL propre${ttl && Number.isFinite(n) && n > 0 ? ` (= ${humanDuration(n)})` : ""}.`
}

function parseTtl(v: string): number | undefined | null {
  if (!v.trim()) return undefined
  const n = Number(v)
  return Number.isInteger(n) && n > 0 && n <= ZONE_TTL_MAX ? n : null
}
const ttlError = `Nombre de secondes entier, entre 1 et ${ZONE_TTL_MAX.toLocaleString("fr-FR")} (7 jours).`

/** Local (client-side) errors, each one cleared as soon as its field changes. */
function useLocalErrors() {
  const [local, setLocal] = React.useState<Record<string, string>>({})
  const clear = React.useCallback(
    (key: string) =>
      setLocal((l) => {
        if (!(key in l)) return l
        const next = { ...l }
        delete next[key]
        return next
      }),
    [],
  )
  return [local, setLocal, clear] as const
}

// ---- Nouvelle zone ----

export function ZoneCreateDialog({
  open,
  onOpenChange,
  onCreated,
}: {
  open: boolean
  onOpenChange: (o: boolean) => void
  onCreated: (z: Zone) => void
}) {
  const qc = useQueryClient()
  const [name, setName] = React.useState("")
  const [ttl, setTtl] = React.useState("3600")
  const [soa, setSoa] = React.useState<SoaForm>(emptySoa)
  const [local, setLocal, clearLocal] = useLocalErrors()

  const create = useMutation({
    mutationFn: (body: { name: string; ttl?: number; soa?: Soa }) => api.post("/dns/zones", { body }),
    meta: { silent: true },
    onSuccess: (z) => {
      void qc.invalidateQueries({ queryKey: qk.zones, exact: true })
      toast.success(`Zone ${z.name} créée.`)
      onCreated(z)
    },
  })

  React.useEffect(() => {
    if (open) {
      setName("")
      setTtl("3600")
      setSoa(emptySoa())
      setLocal({})
      create.reset()
    }
  }, [open])

  const err = (k: string) => local[k] ?? fieldError(create.error, k)
  const known = ["name", "ttl", ...soaKeys.map((k) => `soa.${k}`)]

  const submit = (e: React.FormEvent) => {
    e.preventDefault()
    const errors: Record<string, string> = {}
    const n = name.trim()
    if (!n) errors.name = "Indiquez un nom de zone."
    const t = parseTtl(ttl)
    if (t === null) errors.ttl = ttlError
    const s = checkSoa(soa)
    Object.assign(errors, s.errors)
    setLocal(errors)
    if (Object.keys(errors).length) return
    create.mutate({ name: n, ...(t ? { ttl: t } : {}), ...(s.soa ? { soa: s.soa } : {}) })
  }

  const reverse = isCidr(name.trim())

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="max-h-[90svh] overflow-y-auto sm:max-w-lg">
        <form onSubmit={submit} className="space-y-4">
          <DialogHeader>
            <DialogTitle>Nouvelle zone</DialogTitle>
            <DialogDescription>Leazone répondra pour ce domaine avec les enregistrements que vous ajouterez.</DialogDescription>
          </DialogHeader>
          <Field
            label="Nom"
            htmlFor="zone-name"
            help={
              reverse
                ? "Zone inverse : elle donnera le nom des adresses de ce réseau (enregistrements PTR)."
                : "maison.lan, ou un réseau comme 192.168.20.0/24 pour une zone inverse"
            }
            error={err("name")}
          >
            <Input
              id="zone-name"
              autoFocus
              autoCapitalize="none"
              spellCheck={false}
              value={name}
              onChange={(e) => {
                setName(e.target.value)
                clearLocal("name")
              }}
              placeholder="maison.lan"
            />
          </Field>
          <Field label="TTL par défaut (secondes)" htmlFor="zone-ttl" help={ttlHelp(ttl)} error={err("ttl")}>
            <Input
              id="zone-ttl"
              inputMode="numeric"
              value={ttl}
              onChange={(e) => {
                setTtl(e.target.value)
                clearLocal("ttl")
              }}
            />
          </Field>
          <SoaSection
            value={soa}
            onChange={(v, k) => {
              setSoa(v)
              clearLocal(`soa.${k}`)
            }}
            errors={err}
            idPrefix="new-soa"
          />
          <FormError message={formError(create.error, known)} />
          <DialogFooter>
            <Button type="button" variant="ghost" onClick={() => onOpenChange(false)}>
              Annuler
            </Button>
            <Button type="submit" disabled={create.isPending || !name.trim()}>
              {create.isPending && <Loader2 className="animate-spin" />}
              Créer la zone
            </Button>
          </DialogFooter>
        </form>
      </DialogContent>
    </Dialog>
  )
}

// ---- Paramètres (TTL + SOA) ----

export function ZoneSettingsDialog({
  zone,
  open,
  onOpenChange,
}: {
  zone: Zone
  open: boolean
  onOpenChange: (o: boolean) => void
}) {
  const qc = useQueryClient()
  const [ttl, setTtl] = React.useState("")
  const [soa, setSoa] = React.useState<SoaForm>(emptySoa)
  const [local, setLocal, clearLocal] = useLocalErrors()
  const id = zone.id ?? ""

  const save = useMutation({
    mutationFn: (body: { ttl?: number; soa?: Soa }) => api.patch("/dns/zones/{id}", { params: { id }, body }),
    meta: { silent: true },
    onSuccess: (z) => {
      qc.setQueryData(qk.zone(id), z)
      void qc.invalidateQueries({ queryKey: qk.zones, exact: true })
      toast.success("Paramètres de la zone enregistrés.")
      onOpenChange(false)
    },
  })

  React.useEffect(() => {
    if (open) {
      setTtl(zone.ttl !== undefined ? String(zone.ttl) : "")
      setSoa(soaToForm(zone.soa))
      setLocal({})
      save.reset()
    }
  }, [open])

  const err = (k: string) => local[k] ?? fieldError(save.error, k)
  const known = ["ttl", ...soaKeys.map((k) => `soa.${k}`)]

  const submit = (e: React.FormEvent) => {
    e.preventDefault()
    const errors: Record<string, string> = {}
    const t = parseTtl(ttl)
    if (t === null) errors.ttl = ttlError
    const s = checkSoa(soa)
    Object.assign(errors, s.errors)
    setLocal(errors)
    if (Object.keys(errors).length) return
    save.mutate({ ...(t ? { ttl: t } : {}), ...(s.soa ? { soa: s.soa } : {}) })
  }

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="max-h-[90svh] overflow-y-auto sm:max-w-lg">
        <form onSubmit={submit} className="space-y-4">
          <DialogHeader>
            <DialogTitle>Paramètres de {zone.name}</DialogTitle>
            <DialogDescription>Le numéro de série augmente tout seul à chaque changement.</DialogDescription>
          </DialogHeader>
          <Field label="TTL par défaut (secondes)" htmlFor="zs-ttl" help={ttlHelp(ttl)} error={err("ttl")}>
            <Input
              id="zs-ttl"
              inputMode="numeric"
              value={ttl}
              onChange={(e) => {
                setTtl(e.target.value)
                clearLocal("ttl")
              }}
            />
          </Field>
          <SoaSection
            value={soa}
            onChange={(v, k) => {
              setSoa(v)
              clearLocal(`soa.${k}`)
            }}
            errors={err}
            idPrefix="zs-soa"
            defaultOpen
          />
          <FormError message={formError(save.error, known)} />
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

// ---- Importer ----

type ImportResult = { imported?: number; skipped?: number; errors?: string[] }

export function ZoneImportDialog({
  zone,
  open,
  onOpenChange,
}: {
  zone: Zone
  open: boolean
  onOpenChange: (o: boolean) => void
}) {
  const qc = useQueryClient()
  const [content, setContent] = React.useState("")
  const [replace, setReplace] = React.useState(false)
  const [result, setResult] = React.useState<ImportResult | null>(null)
  const fileRef = React.useRef<HTMLInputElement>(null)
  const id = zone.id ?? ""

  const run = useMutation({
    mutationFn: () => api.post("/dns/zones/{id}/import", { params: { id }, body: { content, replace } }),
    meta: { silent: true },
    onSuccess: (r) => {
      setResult(r ?? {})
      void qc.invalidateQueries({ queryKey: qk.zone(id) })
      void qc.invalidateQueries({ queryKey: qk.zones, exact: true })
      const n = r?.imported ?? 0
      toast.success(n === 1 ? "1 enregistrement importé." : `${n} enregistrements importés.`)
    },
  })

  React.useEffect(() => {
    if (open) {
      setContent("")
      setReplace(false)
      setResult(null)
      run.reset()
    }
  }, [open])

  const onFile = async (e: React.ChangeEvent<HTMLInputElement>) => {
    const f = e.target.files?.[0]
    if (!f) return
    if (f.size > 2 * 1024 * 1024) return void toast.error("Fichier trop gros (2 Mo au plus).")
    setContent(await f.text())
    e.target.value = ""
  }

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="max-h-[90svh] overflow-y-auto sm:max-w-2xl">
        <DialogHeader>
          <DialogTitle>Importer dans {zone.name}</DialogTitle>
          <DialogDescription>
            Fichier de zone au format BIND. Les lignes SOA sont ignorées.
          </DialogDescription>
        </DialogHeader>
        {result ? (
          <div className="space-y-3">
            <div className="grid grid-cols-2 gap-3">
              <div className="rounded-lg border p-3">
                <div className="text-2xl font-semibold tabular-nums">{result.imported ?? 0}</div>
                <div className="text-xs text-muted-foreground">importés</div>
              </div>
              <div className="rounded-lg border p-3">
                <div className="text-2xl font-semibold tabular-nums">{result.skipped ?? 0}</div>
                <div className="text-xs text-muted-foreground">ignorés</div>
              </div>
            </div>
            {(result.errors ?? []).length > 0 && (
              <div className="space-y-1">
                <p className="text-sm font-medium text-destructive">Lignes en erreur</p>
                <ul className="max-h-48 space-y-1 overflow-y-auto rounded-md border bg-muted/40 p-3 font-mono text-xs">
                  {(result.errors ?? []).map((e, i) => (
                    <li key={i}>{e}</li>
                  ))}
                </ul>
              </div>
            )}
            <DialogFooter>
              <Button onClick={() => onOpenChange(false)}>Fermer</Button>
            </DialogFooter>
          </div>
        ) : (
          <form
            className="space-y-4"
            onSubmit={(e) => {
              e.preventDefault()
              if (content.trim()) run.mutate()
            }}
          >
            <div className="space-y-2">
              <div className="flex items-end justify-between gap-2">
                <Label htmlFor="import-content">Contenu</Label>
                <input ref={fileRef} type="file" accept=".zone,.txt,.db,text/plain" className="hidden" onChange={onFile} />
                <Button type="button" variant="outline" size="sm" onClick={() => fileRef.current?.click()}>
                  <FileUp /> Choisir un fichier
                </Button>
              </div>
              <Textarea
                id="import-content"
                rows={12}
                className="font-mono text-xs"
                spellCheck={false}
                value={content}
                onChange={(e) => setContent(e.target.value)}
                placeholder={"www   3600  IN  A      192.168.1.10\nnas         IN  A      192.168.1.20\n@           IN  MX 10  mail"}
              />
            </div>
            <div className="flex items-start gap-3">
              <Checkbox id="import-replace" checked={replace} onCheckedChange={(v) => setReplace(v === true)} />
              <Label htmlFor="import-replace" className="flex flex-col items-start gap-0.5 font-normal">
                <span>Remplacer les enregistrements existants</span>
                <span className="text-xs text-muted-foreground">Les enregistrements manuels actuels seront supprimés avant l'import.</span>
              </Label>
            </div>
            {replace && (
              <Alert variant="destructive">
                <TriangleAlert />
                <AlertDescription>Les enregistrements actuels de la zone seront effacés.</AlertDescription>
              </Alert>
            )}
            <FormError message={run.error ? formError(run.error, []) : undefined} />
            <DialogFooter>
              <Button type="button" variant="ghost" onClick={() => onOpenChange(false)}>
                Annuler
              </Button>
              <Button type="submit" disabled={run.isPending || !content.trim()}>
                {run.isPending && <Loader2 className="animate-spin" />}
                Importer
              </Button>
            </DialogFooter>
          </form>
        )}
      </DialogContent>
    </Dialog>
  )
}

// ---- Supprimer (confirmation en tapant le nom) ----

export function ZoneDeleteDialog({
  zone,
  open,
  onOpenChange,
  onDeleted,
}: {
  zone: Zone
  open: boolean
  onOpenChange: (o: boolean) => void
  onDeleted: () => void
}) {
  const qc = useQueryClient()
  const [typed, setTyped] = React.useState("")
  const id = zone.id ?? ""
  const del = useMutation({
    mutationFn: () => api.delete("/dns/zones/{id}", { params: { id } }),
    meta: { silent: true },
    onSuccess: () => {
      // Only the list: refetching the deleted zone itself would 404.
      void qc.invalidateQueries({ queryKey: qk.zones, exact: true })
      toast.success(`Zone ${zone.name} supprimée.`)
      onDeleted()
    },
  })

  React.useEffect(() => {
    if (open) {
      setTyped("")
      del.reset()
    }
  }, [open])

  const match = typed.trim().replace(/\.$/, "").toLowerCase() === (zone.name ?? "").replace(/\.$/, "").toLowerCase()

  return (
    <Dialog open={open} onOpenChange={(o) => !del.isPending && onOpenChange(o)}>
      <DialogContent className="sm:max-w-md">
        <form
          className="space-y-4"
          onSubmit={(e) => {
            e.preventDefault()
            if (match) del.mutate()
          }}
        >
          <DialogHeader>
            <DialogTitle>Supprimer la zone {zone.name} ?</DialogTitle>
            <DialogDescription>
              La zone et ses {zone.recordCount ?? 0} enregistrements seront supprimés. Les appareils ne pourront plus
              résoudre ces noms. Cette action est définitive.
            </DialogDescription>
          </DialogHeader>
          <Field label={<>Tapez <span className="font-mono">{zone.name}</span> pour confirmer</>} htmlFor="zone-confirm">
            <Input
              id="zone-confirm"
              autoFocus
              autoComplete="off"
              autoCapitalize="none"
              spellCheck={false}
              value={typed}
              onChange={(e) => setTyped(e.target.value)}
            />
          </Field>
          <FormError message={del.error ? formError(del.error, []) : undefined} />
          <DialogFooter>
            <Button type="button" variant="ghost" onClick={() => onOpenChange(false)} disabled={del.isPending}>
              Annuler
            </Button>
            <Button type="submit" variant="destructive" disabled={!match || del.isPending}>
              {del.isPending && <Loader2 className="animate-spin" />}
              Supprimer la zone
            </Button>
          </DialogFooter>
        </form>
      </DialogContent>
    </Dialog>
  )
}
