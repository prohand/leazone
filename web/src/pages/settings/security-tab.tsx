import * as React from "react"
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query"
import { Loader2, TriangleAlert } from "lucide-react"
import { toast } from "sonner"
import { api } from "@/api/client"
import { qk } from "@/api/queries"
import type { SecuritySettings } from "@/api/types"
import { Field } from "@/components/form-field"
import { BlockSpinner } from "@/components/spinner"
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert"
import { Button } from "@/components/ui/button"
import { Card, CardContent, CardDescription, CardFooter, CardHeader, CardTitle } from "@/components/ui/card"
import { Input } from "@/components/ui/input"
import { Label } from "@/components/ui/label"
import { RadioGroup, RadioGroupItem } from "@/components/ui/radio-group"
import { Textarea } from "@/components/ui/textarea"
import { errorMessage, fieldError, toastError } from "@/lib/errors"

type Form = {
  mfaRequiredFor: NonNullable<SecuritySettings["mfaRequiredFor"]>
  mfaMethods: NonNullable<SecuritySettings["mfaMethods"]>
  sessionMaxHours: string
  sessionIdleMinutes: string
  networks: string
  webauthnRpId: string
}

function toForm(s: SecuritySettings): Form {
  return {
    mfaRequiredFor: s.mfaRequiredFor ?? "all",
    mfaMethods: s.mfaMethods ?? "passkey_or_totp",
    sessionMaxHours: String(s.sessionMaxHours ?? 12),
    sessionIdleMinutes: String(s.sessionIdleMinutes ?? 30),
    networks: (s.uiAllowedNetworks ?? []).join("\n"),
    webauthnRpId: s.webauthnRpId ?? "",
  }
}

function isCidr(v: string): boolean {
  const m4 = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})\/(\d{1,2})$/.exec(v)
  if (m4) return m4.slice(1, 5).every((o) => Number(o) <= 255) && Number(m4[5]) <= 32
  const m6 = /^([0-9a-fA-F:]+)\/(\d{1,3})$/.exec(v)
  return !!m6 && m6[1].includes(":") && Number(m6[2]) <= 128
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

export function SecurityTab() {
  const qc = useQueryClient()
  const settings = useQuery({ queryKey: qk.securitySettings, queryFn: () => api.get("/settings/security") })
  const [form, setForm] = React.useState<Form | null>(null)
  const [errors, setErrors] = React.useState<Record<string, string>>({})

  React.useEffect(() => {
    if (settings.data) setForm(toForm(settings.data))
  }, [settings.data])

  const save = useMutation({
    mutationFn: (body: SecuritySettings) => api.put("/settings/security", { body }),
    meta: { silent: true },
    onSuccess: (s) => {
      qc.setQueryData(qk.securitySettings, s)
      void qc.invalidateQueries({ queryKey: qk.systemInfo })
      toast.success("Paramètres de sécurité enregistrés.")
    },
    onError: (e) => {
      setErrors({
        sessionMaxHours: fieldError(e, "sessionMaxHours") ?? "",
        sessionIdleMinutes: fieldError(e, "sessionIdleMinutes") ?? "",
        networks: fieldError(e, "uiAllowedNetworks") ?? "",
        webauthnRpId: fieldError(e, "webauthnRpId") ?? "",
      })
      toastError(e)
    },
  })

  if (settings.isPending || !form) return settings.isError ? <p className="text-sm text-destructive">{errorMessage(settings.error)}</p> : <BlockSpinner />

  const set = <K extends keyof Form>(k: K, v: Form[K]) => setForm({ ...form, [k]: v })
  // Save / Cancel only make sense once something changed.
  const dirty = !!settings.data && JSON.stringify(form) !== JSON.stringify(toForm(settings.data))

  const submit = (e: React.FormEvent) => {
    e.preventDefault()
    const errs: Record<string, string> = {}
    const maxH = Number(form.sessionMaxHours)
    const idle = Number(form.sessionIdleMinutes)
    if (!Number.isInteger(maxH) || maxH < 1 || maxH > 720) errs.sessionMaxHours = "Entre 1 et 720 heures."
    if (!Number.isInteger(idle) || idle < 5 || idle > 1440) errs.sessionIdleMinutes = "Entre 5 et 1440 minutes."
    const networks = form.networks
      .split(/\r?\n/)
      .map((l) => l.trim())
      .filter(Boolean)
    const bad = networks.filter((n) => !isCidr(n))
    if (bad.length) errs.networks = `Réseau non valide : ${bad.join(", ")} (format attendu : 192.168.1.0/24).`
    setErrors(errs)
    if (Object.keys(errs).length) return
    save.mutate({
      mfaRequiredFor: form.mfaRequiredFor,
      mfaMethods: form.mfaMethods,
      sessionMaxHours: maxH,
      sessionIdleMinutes: idle,
      uiAllowedNetworks: networks,
      webauthnRpId: form.webauthnRpId.trim(),
    })
  }

  const hasNetworks = form.networks.trim().length > 0

  return (
    // noValidate: no native (English) bubbles, the checks below show French messages.
    <form onSubmit={submit} noValidate>
      <Card>
        <CardHeader>
          <CardTitle>Sécurité</CardTitle>
          <CardDescription>Double vérification, sessions et accès à l'interface.</CardDescription>
        </CardHeader>
        <CardContent className="space-y-8">
          <div className="grid gap-8 md:grid-cols-2">
            <Field label="MFA obligatoire pour">
              <RadioGroup value={form.mfaRequiredFor} onValueChange={(v) => set("mfaRequiredFor", v as Form["mfaRequiredFor"])}>
                <Choice value="all" id="mfa-all" label="Tous les comptes" help="Conseillé." />
                <Choice value="admins" id="mfa-admins" label="Administrateurs seulement" />
              </RadioGroup>
            </Field>
            <Field label="Méthodes autorisées">
              <RadioGroup value={form.mfaMethods} onValueChange={(v) => set("mfaMethods", v as Form["mfaMethods"])}>
                <Choice value="passkey" id="m-passkey" label="Passkey seulement" help="Le plus sûr : résiste au hameçonnage." />
                <Choice value="passkey_or_totp" id="m-both" label="Passkey ou application TOTP" />
              </RadioGroup>
            </Field>
          </div>

          <div className="grid gap-6 sm:grid-cols-2">
            <Field label="Durée maximale d'une session (heures)" htmlFor="max-h" help={errors.sessionMaxHours ? undefined : "Entre 1 et 720."} error={errors.sessionMaxHours}>
              <Input id="max-h" type="number" inputMode="numeric" min={1} max={720} value={form.sessionMaxHours} onChange={(e) => set("sessionMaxHours", e.target.value)} />
            </Field>
            <Field label="Déconnexion après inactivité (minutes)" htmlFor="idle" help={errors.sessionIdleMinutes ? undefined : "Entre 5 et 1440."} error={errors.sessionIdleMinutes}>
              <Input id="idle" type="number" inputMode="numeric" min={5} max={1440} value={form.sessionIdleMinutes} onChange={(e) => set("sessionIdleMinutes", e.target.value)} />
            </Field>
          </div>

          <Field
            label="Réseaux autorisés pour l'interface"
            htmlFor="networks"
            help="Un réseau par ligne (ex. : 192.168.1.0/24 ou fd00::/8). Laissez vide pour tout autoriser."
            error={errors.networks}
          >
            <Textarea
              id="networks"
              rows={4}
              className="font-mono text-sm"
              spellCheck={false}
              placeholder={"192.168.1.0/24\n10.0.0.0/8"}
              value={form.networks}
              onChange={(e) => set("networks", e.target.value)}
            />
          </Field>
          {hasNetworks && (
            <Alert variant="destructive">
              <TriangleAlert />
              <AlertTitle>Attention à ne pas vous bloquer</AlertTitle>
              <AlertDescription>
                Si votre adresse IP actuelle n'est pas dans ces réseaux, vous perdrez l'accès à l'interface dès
                l'enregistrement. Derrière un proxy, vérifiez que le proxy est bien déclaré comme proxy de confiance.
              </AlertDescription>
            </Alert>
          )}

          <Field
            label="RP ID WebAuthn"
            htmlFor="rpid"
            help="Nom de domaine utilisé par les passkeys (ex. : leazone.mondomaine.lan). Vide = nom d'hôte de l'URL publique. Le changer rend les passkeys existantes inutilisables."
            error={errors.webauthnRpId}
          >
            <Input
              id="rpid"
              spellCheck={false}
              autoCapitalize="none"
              placeholder="leazone.mondomaine.lan"
              value={form.webauthnRpId}
              onChange={(e) => set("webauthnRpId", e.target.value)}
            />
          </Field>
        </CardContent>
        <CardFooter className="justify-end gap-2 border-t pt-6">
          <Button
            type="button"
            variant="ghost"
            disabled={!dirty || save.isPending}
            onClick={() => {
              if (settings.data) setForm(toForm(settings.data))
              setErrors({})
            }}
          >
            Annuler
          </Button>
          <Button type="submit" disabled={!dirty || save.isPending}>
            {save.isPending && <Loader2 className="animate-spin" />}
            Enregistrer
          </Button>
        </CardFooter>
      </Card>
    </form>
  )
}
