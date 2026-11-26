import * as React from "react"
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query"
import { Loader2 } from "lucide-react"
import { toast } from "sonner"
import { api } from "@/api/client"
import { blockingSettingsQuery, qk } from "@/api/queries"
import type { BlockingSettings } from "@/api/types"
import { Field, FormError } from "@/components/form-field"
import { WriteGuard } from "@/components/read-only"
import { BlockSpinner } from "@/components/spinner"
import { Button } from "@/components/ui/button"
import { Card, CardContent, CardFooter } from "@/components/ui/card"
import { Input } from "@/components/ui/input"
import { Label } from "@/components/ui/label"
import { RadioGroup, RadioGroupItem } from "@/components/ui/radio-group"
import { Switch } from "@/components/ui/switch"
import { usePermissions } from "@/hooks/use-cluster"
import { errorMessage, fieldError, formError } from "@/lib/errors"

type Mode = NonNullable<BlockingSettings["responseMode"]>
type Form = { responseMode: Mode; refreshHours: string; defaultEnabled: boolean }

const toForm = (s: BlockingSettings): Form => ({
  responseMode: s.responseMode ?? "nxdomain",
  refreshHours: String(s.refreshHours ?? 24),
  defaultEnabled: s.defaultEnabled !== false,
})

export function SettingsTab() {
  const perms = usePermissions()
  return perms.allowed("config.write") ? (
    <WriteGuard block>
      <SettingsForm canEdit />
    </WriteGuard>
  ) : (
    <SettingsForm canEdit={false} />
  )
}

function SettingsForm({ canEdit }: { canEdit: boolean }) {
  const qc = useQueryClient()
  const settings = useQuery(blockingSettingsQuery)
  const [form, setForm] = React.useState<Form | null>(null)
  const [local, setLocal] = React.useState<Record<string, string>>({})

  React.useEffect(() => {
    if (settings.data) setForm(toForm(settings.data))
  }, [settings.data])

  const save = useMutation({
    mutationFn: (body: BlockingSettings) => api.put("/blocking/settings", { body }),
    meta: { silent: true },
    onSuccess: (s) => {
      qc.setQueryData(qk.blockingSettings, s)
      toast.success("Réglages du blocage enregistrés.")
    },
  })

  if (settings.isPending || !form)
    return settings.isError ? <p className="text-sm text-destructive">{errorMessage(settings.error)}</p> : <BlockSpinner />

  const set = (patch: Partial<Form>) => {
    setForm({ ...form, ...patch })
    setLocal({})
    if (save.isError) save.reset()
  }
  const err = (k: string) => local[k] ?? fieldError(save.error, k)

  const submit = (e: React.FormEvent) => {
    e.preventDefault()
    const h = Number(form.refreshHours)
    if (!/^\d+$/.test(form.refreshHours.trim()) || h < 1 || h > 168) return setLocal({ refreshHours: "Entre 1 et 168 heures (7 jours)." })
    save.mutate({ responseMode: form.responseMode, refreshHours: h, defaultEnabled: form.defaultEnabled })
  }

  return (
    <form onSubmit={submit} noValidate>
      <Card>
        <CardContent className="space-y-6">
          <fieldset disabled={!canEdit} className="min-w-0 space-y-6">
            <Field label="Réponse pour un domaine bloqué" error={err("responseMode")}>
              <RadioGroup value={form.responseMode} onValueChange={(v) => set({ responseMode: v as Mode })} disabled={!canEdit}>
                <div className="flex items-start gap-3">
                  <RadioGroupItem value="nxdomain" id="bs-nx" className="mt-0.5" />
                  <Label htmlFor="bs-nx" className="flex flex-col items-start gap-0.5 font-normal">
                    <span className="font-medium">NXDOMAIN (le domaine n'existe pas)</span>
                    <span className="text-xs text-muted-foreground">Recommandé : les applications abandonnent vite.</span>
                  </Label>
                </div>
                <div className="flex items-start gap-3">
                  <RadioGroupItem value="null-ip" id="bs-null" className="mt-0.5" />
                  <Label htmlFor="bs-null" className="flex flex-col items-start gap-0.5 font-normal">
                    <span className="font-medium">Adresse nulle 0.0.0.0 et ::</span>
                    <span className="text-xs text-muted-foreground">Pour les appareils qui réessayent sans fin après un NXDOMAIN.</span>
                  </Label>
                </div>
              </RadioGroup>
            </Field>
            <Field
              label="Mise à jour des listes (heures)"
              htmlFor="bs-hours"
              help="Entre 1 et 168 (7 jours). Défaut : 24."
              error={err("refreshHours")}
              className="sm:max-w-xs"
            >
              <Input
                id="bs-hours"
                type="number"
                inputMode="numeric"
                min={1}
                max={168}
                value={form.refreshHours}
                onChange={(e) => set({ refreshHours: e.target.value })}
              />
            </Field>
            <div className="flex items-start gap-3">
              <Switch
                id="bs-default"
                checked={form.defaultEnabled}
                onCheckedChange={(v) => set({ defaultEnabled: v })}
                disabled={!canEdit}
                className="mt-0.5"
              />
              <Label htmlFor="bs-default" className="flex flex-col items-start gap-0.5 font-normal">
                <span className="font-medium">Bloquer partout par défaut</span>
                <span className="text-xs text-muted-foreground">
                  S'applique là où aucune règle de l'onglet « Où bloquer » ne correspond.
                </span>
              </Label>
            </div>
          </fieldset>
          <FormError message={formError(save.error, ["responseMode", "refreshHours", "defaultEnabled"])} />
        </CardContent>
        {canEdit && (
          <CardFooter className="justify-end">
            <Button type="submit" disabled={save.isPending}>
              {save.isPending && <Loader2 className="animate-spin" />}
              Enregistrer
            </Button>
          </CardFooter>
        )}
      </Card>
    </form>
  )
}
