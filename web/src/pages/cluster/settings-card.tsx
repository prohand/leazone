import * as React from "react"
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query"
import { Loader2, Timer } from "lucide-react"
import { toast } from "sonner"
import { api } from "@/api/client"
import { clusterSettingsQuery, qk } from "@/api/queries"
import type { ClusterSettings, ClusterView } from "@/api/types"
import { Field, FormError } from "@/components/form-field"
import { ReadOnlyNote, WriteGuard } from "@/components/read-only"
import { Button } from "@/components/ui/button"
import { Card, CardContent, CardDescription, CardFooter, CardHeader, CardTitle } from "@/components/ui/card"
import { Input } from "@/components/ui/input"
import { Label } from "@/components/ui/label"
import { RadioGroup, RadioGroupItem } from "@/components/ui/radio-group"
import { useWritable } from "@/hooks/use-cluster"
import { fieldError, formError } from "@/lib/errors"
import { formatDuration } from "@/lib/format"

type Form = {
  heartbeatMs: string
  failCount: string
  leaseMs: string
  failbackMode: NonNullable<ClusterSettings["failbackMode"]>
  failbackDelaySec: string
  dhcpMode: NonNullable<ClusterSettings["dhcpMode"]>
}

const fields = ["heartbeatMs", "failCount", "leaseMs", "failbackMode", "failbackDelaySec", "dhcpMode"] as const

function toForm(s: ClusterSettings): Form {
  return {
    heartbeatMs: String(s.heartbeatMs ?? 1000),
    failCount: String(s.failCount ?? 3),
    leaseMs: String(s.leaseMs ?? 6000),
    failbackMode: s.failbackMode ?? "auto",
    failbackDelaySec: String(s.failbackDelaySec ?? 300),
    dhcpMode: s.dhcpMode ?? "load-balancing",
  }
}

const int = (v: string) => (/^\d+$/.test(v.trim()) ? Number(v) : NaN)

/** Seconds with at most one decimal, French style: 3 -> "3", 1.5 -> "1,5". */
const secs = (ms: number) => new Intl.NumberFormat("fr-FR", { maximumFractionDigits: 1 }).format(ms / 1000)

function validate(f: Form): Record<string, string> {
  const e: Record<string, string> = {}
  const hb = int(f.heartbeatMs)
  const fc = int(f.failCount)
  const lease = int(f.leaseMs)
  const delay = int(f.failbackDelaySec)
  if (!(hb >= 100 && hb <= 10000)) e.heartbeatMs = "Entre 100 et 10 000 ms."
  if (!(fc >= 2 && fc <= 20)) e.failCount = "Entre 2 et 20."
  if (!(lease >= 2000 && lease <= 60000)) e.leaseMs = "Entre 2 000 et 60 000 ms."
  else if (hb > 0 && fc > 0 && lease < hb * fc) e.leaseMs = `Au moins la durée de détection (${hb * fc} ms).`
  if (!(delay >= 0 && delay <= 86400)) e.failbackDelaySec = "Entre 0 et 86 400 s (24 h)."
  return e
}

function Choice({ value, id, label, help }: { value: string; id: string; label: string; help?: string }) {
  return (
    <div className="flex items-start gap-3">
      <RadioGroupItem value={value} id={id} className="mt-0.5" />
      <Label htmlFor={id} className="flex flex-col items-start gap-0.5 font-normal">
        <span className="font-medium">{label}</span>
        {help && <span className="text-xs text-muted-foreground">{help}</span>}
      </Label>
    </div>
  )
}

/** Cluster timing, failback and DHCP sharing settings (admin, on the primary). */
export function SettingsCard({ view, isAdmin }: { view: ClusterView; isAdmin: boolean }) {
  const qc = useQueryClient()
  const { writable } = useWritable()
  const settings = useQuery({ ...clusterSettingsQuery, placeholderData: view.settings })
  const [form, setForm] = React.useState<Form | null>(null)
  const [errors, setErrors] = React.useState<Record<string, string>>({})
  const [dirty, setDirty] = React.useState(false)

  // Load the stored values, unless the user is typing.
  React.useEffect(() => {
    if (settings.data && !dirty) setForm(toForm(settings.data))
  }, [settings.data, dirty])

  const save = useMutation({
    mutationFn: (body: ClusterSettings) => api.put("/cluster/settings", { body }),
    meta: { silent: true },
    onSuccess: (s) => {
      qc.setQueryData(qk.clusterSettings, s)
      void qc.invalidateQueries({ queryKey: qk.cluster })
      setDirty(false)
      toast.success("Réglages du cluster enregistrés.")
    },
    onError: (e) => setErrors(Object.fromEntries(fields.map((k) => [k, fieldError(e, k) ?? ""]))),
  })

  if (!form) return null
  const set = <K extends keyof Form>(k: K, v: Form[K]) => {
    setForm({ ...form, [k]: v })
    setDirty(true)
  }

  const hb = int(form.heartbeatMs)
  const fc = int(form.failCount)
  const detection = hb > 0 && fc > 0 ? hb * fc : NaN
  const delay = int(form.failbackDelaySec)

  const submit = (e: React.FormEvent) => {
    e.preventDefault()
    const errs = validate(form)
    setErrors(errs)
    if (Object.keys(errs).length) return
    save.mutate({
      heartbeatMs: hb,
      failCount: fc,
      leaseMs: int(form.leaseMs),
      failbackMode: form.failbackMode,
      failbackDelaySec: delay,
      dhcpMode: form.dhcpMode,
    })
  }

  const body = (
    <CardContent className="space-y-6">
      <div className="grid gap-5 sm:grid-cols-2">
        <Field label="Intervalle du heartbeat (ms)" htmlFor="cl-hb" help="Entre 100 et 10 000. Défaut : 1 000." error={errors.heartbeatMs}>
          <Input id="cl-hb" type="number" inputMode="numeric" min={100} max={10000} step={100} value={form.heartbeatMs} onChange={(e) => set("heartbeatMs", e.target.value)} />
        </Field>
        <Field label="Nombre d'échecs avant bascule" htmlFor="cl-fc" help="Entre 2 et 20. Défaut : 3." error={errors.failCount}>
          <Input id="cl-fc" type="number" inputMode="numeric" min={2} max={20} value={form.failCount} onChange={(e) => set("failCount", e.target.value)} />
        </Field>
      </div>
      <p className="flex items-center gap-2 rounded-md bg-muted/60 px-3 py-2 text-sm" data-testid="detection">
        <Timer className="size-4 shrink-0 text-muted-foreground" />
        {Number.isFinite(detection) ? (
          <span>
            Détection de panne en <strong>~{secs(detection)} s</strong> (heartbeat × échecs).
          </span>
        ) : (
          <span className="text-muted-foreground">Détection de panne : —</span>
        )}
      </p>
      <Field
        label="Durée du bail témoin (ms)"
        htmlFor="cl-lease"
        help="Temps pendant lequel le témoin garde le primaire sans nouvelles. Au moins la durée de détection. Défaut : 6 000."
        error={errors.leaseMs}
      >
        <Input id="cl-lease" type="number" inputMode="numeric" min={2000} max={60000} step={500} value={form.leaseMs} onChange={(e) => set("leaseMs", e.target.value)} />
      </Field>

      <Field label="Retour du primaire d'origine" error={errors.failbackMode}>
        <RadioGroup value={form.failbackMode} onValueChange={(v) => set("failbackMode", v as Form["failbackMode"])}>
          <Choice value="auto" id="fb-auto" label="Automatique" help="Il reprend la main après le délai, une fois sa synchro vérifiée." />
          <Choice value="manual" id="fb-manual" label="Manuel" help="Avec le bouton « Rebasculer »." />
        </RadioGroup>
      </Field>
      {form.failbackMode === "auto" && (
        <Field
          label="Délai avant le retour (s)"
          htmlFor="cl-delay"
          help={Number.isFinite(delay) && delay >= 0 ? `= ${formatDuration(delay)} de synchro sans erreur. Défaut : 300 (5 min).` : "Défaut : 300 (5 min)."}
          error={errors.failbackDelaySec}
        >
          <Input id="cl-delay" type="number" inputMode="numeric" min={0} max={86400} step={30} value={form.failbackDelaySec} onChange={(e) => set("failbackDelaySec", e.target.value)} />
        </Field>
      )}

      <Field label="Mode DHCP" error={errors.dhcpMode}>
        <RadioGroup value={form.dhcpMode} onValueChange={(v) => set("dhcpMode", v as Form["dhcpMode"])}>
          <Choice
            value="load-balancing"
            id="dhcp-lb"
            label="Répartition 50/50 par client"
            help="Chaque nœud répond à la moitié des clients. Si un nœud tombe, l'autre sert tout le monde."
          />
          <Choice value="active-passive" id="dhcp-ap" label="Le primaire sert tout" help="Le secondaire ne répond qu'après une bascule." />
        </RadioGroup>
      </Field>
      <FormError message={formError(save.error, fields as unknown as string[])} />
    </CardContent>
  )

  return (
    <form onSubmit={submit} noValidate>
      <Card className="gap-4" data-testid="cluster-settings">
        <CardHeader>
          <CardTitle>Réglages</CardTitle>
          <CardDescription>Détection des pannes, retour du primaire d'origine et partage du DHCP. Appliqués aux deux nœuds.</CardDescription>
        </CardHeader>
        {isAdmin && <ReadOnlyNote className="px-6" />}
        <fieldset disabled={!isAdmin || !writable} className="min-w-0">
          {body}
        </fieldset>
        {isAdmin && (
          <CardFooter className="justify-end gap-2 border-t pt-4">
            <WriteGuard className="gap-2">
              <Button
                type="button"
                variant="ghost"
                disabled={!dirty}
                onClick={() => {
                  if (settings.data) setForm(toForm(settings.data))
                  setErrors({})
                  setDirty(false)
                  save.reset()
                }}
              >
                Annuler
              </Button>
              <Button type="submit" disabled={save.isPending || !dirty}>
                {save.isPending && <Loader2 className="animate-spin" />}
                Enregistrer
              </Button>
            </WriteGuard>
          </CardFooter>
        )}
      </Card>
    </form>
  )
}
