import * as React from "react"
import { useMutation, useQueryClient } from "@tanstack/react-query"
import { Download, Eye, Loader2, TriangleAlert } from "lucide-react"
import { toast } from "sonner"
import { api } from "@/api/client"
import { qk } from "@/api/queries"
import type { ImportItem, ImportReport, TechnitiumImportInput } from "@/api/types"
import { ConfirmDialog } from "@/components/confirm-dialog"
import { SwitchRow } from "@/components/dhcp"
import { Field, FormError } from "@/components/form-field"
import { Badge } from "@/components/ui/badge"
import { Button } from "@/components/ui/button"
import { Card, CardContent, CardDescription, CardFooter, CardHeader, CardTitle } from "@/components/ui/card"
import { Checkbox } from "@/components/ui/checkbox"
import { Input } from "@/components/ui/input"
import { Label } from "@/components/ui/label"
import { RadioGroup, RadioGroupItem } from "@/components/ui/radio-group"
import { Switch } from "@/components/ui/switch"
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table"
import { fieldError, formError } from "@/lib/errors"
import { cn } from "@/lib/utils"

type Form = {
  url: string
  auth: "token" | "password"
  token: string
  username: string
  password: string
  tlsVerify: boolean
  zones: boolean
  forwarders: boolean
  dhcp: boolean
}

type Kind = NonNullable<ImportItem["kind"]>
type Action = NonNullable<ImportItem["action"]>

const kindLabel: Record<Kind, string> = {
  zone: "Zones DNS",
  forwarder: "Redirecteurs",
  scope: "Étendues DHCP",
  reservation: "Réservations DHCP",
}
const kinds: Kind[] = ["zone", "forwarder", "scope", "reservation"]

const actionClass: Record<Action, string> = {
  create: "border-success/40 text-success",
  skip: "text-muted-foreground",
  error: "border-destructive/40 text-destructive",
}
const actionLabel = (a: Action, dryRun: boolean) =>
  a === "create" ? (dryRun ? "à créer" : "créé") : a === "skip" ? "ignoré" : "erreur"

const known = ["url", "token", "username", "password", "tlsVerify", "zones", "forwarders", "dhcp"]

function toInput(f: Form, dryRun: boolean): TechnitiumImportInput {
  const input: TechnitiumImportInput = {
    url: f.url.trim().replace(/\/+$/, ""),
    tlsVerify: f.tlsVerify,
    dryRun,
    zones: f.zones,
    forwarders: f.forwarders,
    dhcp: f.dhcp,
  }
  if (f.auth === "token") input.token = f.token.trim()
  else {
    input.username = f.username.trim()
    input.password = f.password
  }
  return input
}

export function ImportTab() {
  const qc = useQueryClient()
  const [form, setForm] = React.useState<Form>({
    url: "",
    auth: "token",
    token: "",
    username: "admin",
    password: "",
    tlsVerify: true,
    zones: true,
    forwarders: true,
    dhcp: true,
  })
  const [local, setLocal] = React.useState<Record<string, string>>({})
  const [report, setReport] = React.useState<ImportReport | null>(null)
  // Inputs the last preview was made with: "Importer" needs a fresh preview.
  const [previewOf, setPreviewOf] = React.useState<string | null>(null)
  const [confirming, setConfirming] = React.useState(false)

  const run = useMutation({
    mutationFn: (body: TechnitiumImportInput) => api.post("/import/technitium", { body }),
    meta: { silent: true },
  })

  const set = (patch: Partial<Form>) => {
    setForm((f) => ({ ...f, ...patch }))
    if (run.isError) run.reset()
    const keys = Object.keys(patch).flatMap((k) => (k === "zones" || k === "forwarders" || k === "dhcp" ? ["what"] : [k]))
    setLocal((l) => (keys.some((k) => k in l) ? Object.fromEntries(Object.entries(l).filter(([k]) => !keys.includes(k))) : l))
  }
  const err = (k: string) => local[k] ?? fieldError(run.error, k)
  const fingerprint = JSON.stringify(toInput(form, true))
  const previewFresh = previewOf === fingerprint && !!report?.dryRun

  const check = () => {
    const e: Record<string, string> = {}
    if (!/^https?:\/\/[^\s/]+/i.test(form.url.trim())) e.url = "Adresse complète, ex. : http://10.0.0.5:5380"
    if (form.auth === "token" && !form.token.trim()) e.token = "Obligatoire."
    if (form.auth === "password") {
      if (!form.username.trim()) e.username = "Obligatoire."
      if (!form.password) e.password = "Obligatoire."
    }
    if (!form.zones && !form.forwarders && !form.dhcp) e.what = "Cochez au moins un élément."
    setLocal(e)
    return Object.keys(e).length === 0
  }

  const preview = (e: React.FormEvent) => {
    e.preventDefault()
    if (!check()) return
    run.mutate(toInput(form, true), {
      onSuccess: (r) => {
        setReport(r)
        setPreviewOf(fingerprint)
      },
    })
  }

  const doImport = () =>
    run.mutateAsync(toInput(form, false)).then(
      (r) => {
        setReport(r)
        setPreviewOf(null)
        // The secret was only needed for this request.
        setForm((f) => ({ ...f, token: "", password: "" }))
        for (const key of [qk.dns, qk.dhcp, qk.vlans]) void qc.invalidateQueries({ queryKey: key })
        const msg = `Import terminé : ${r.created ?? 0} créé(s), ${r.skipped ?? 0} ignoré(s), ${r.errors ?? 0} erreur(s).`
        if ((r.errors ?? 0) > 0) toast.warning(msg, { description: "Voir le détail des erreurs dans le rapport." })
        else toast.success(msg)
      },
      (e) => {
        // Shown under the form (silent mutation); close the confirmation.
        setConfirming(false)
        throw e
      },
    )

  const toCreate = report?.dryRun ? (report.items ?? []).filter((i) => i.action === "create").length : 0
  const fieldsKnown = known

  return (
    <div className="space-y-6">
      <form onSubmit={preview} noValidate>
        <Card>
          <CardHeader>
            <CardTitle>Importer depuis Technitium DNS Server</CardTitle>
            <CardDescription>
              Leazone lit l'ancien serveur par son API HTTP et reprend ses zones, ses redirecteurs et ses étendues DHCP.
            </CardDescription>
          </CardHeader>
          <CardContent className="space-y-5">
            <Field label="Adresse du serveur Technitium" htmlFor="imp-url" error={err("url")} help="Avec le port de la console web (5380 par défaut).">
              <Input
                id="imp-url"
                className="font-mono sm:max-w-md"
                autoCapitalize="none"
                spellCheck={false}
                value={form.url}
                onChange={(e) => set({ url: e.target.value })}
                placeholder="http://10.0.0.5:5380"
              />
            </Field>

            <div className="space-y-3">
              <Label>Connexion</Label>
              <RadioGroup value={form.auth} onValueChange={(v) => set({ auth: v as Form["auth"] })} className="flex flex-wrap gap-4">
                <label className="flex items-center gap-2 text-sm">
                  <RadioGroupItem value="token" /> Jeton d'API (conseillé)
                </label>
                <label className="flex items-center gap-2 text-sm">
                  <RadioGroupItem value="password" /> Nom d'utilisateur et mot de passe
                </label>
              </RadioGroup>
              {form.auth === "token" ? (
                <Field label="Jeton d'API" htmlFor="imp-token" error={err("token")} help="Dans Technitium : Administration, Sessions, Create Token.">
                  <Input
                    id="imp-token"
                    type="password"
                    autoComplete="off"
                    className="font-mono sm:max-w-md"
                    value={form.token}
                    onChange={(e) => set({ token: e.target.value })}
                  />
                </Field>
              ) : (
                <div className="grid gap-4 sm:max-w-md sm:grid-cols-2">
                  <Field label="Nom d'utilisateur" htmlFor="imp-user" error={err("username")}>
                    <Input
                      id="imp-user"
                      autoComplete="off"
                      autoCapitalize="none"
                      value={form.username}
                      onChange={(e) => set({ username: e.target.value })}
                    />
                  </Field>
                  <Field label="Mot de passe" htmlFor="imp-pass" error={err("password")}>
                    <Input
                      id="imp-pass"
                      type="password"
                      autoComplete="new-password"
                      value={form.password}
                      onChange={(e) => set({ password: e.target.value })}
                    />
                  </Field>
                </div>
              )}
            </div>

            <div className="space-y-2 sm:max-w-md">
              <SwitchRow id="imp-tls" title="Vérifier le certificat TLS" description="Pour une adresse https://. Laissez activé si le certificat est valide.">
                <Switch id="imp-tls" checked={form.tlsVerify} onCheckedChange={(v) => set({ tlsVerify: v })} />
              </SwitchRow>
              {!form.tlsVerify && (
                <p className="flex items-center gap-1.5 text-xs text-warning">
                  <TriangleAlert className="size-3.5" /> Sans vérification, le jeton peut être intercepté sur le réseau.
                </p>
              )}
            </div>

            <fieldset className="space-y-2">
              <legend className="mb-2 text-sm font-medium">À importer</legend>
              {(
                [
                  ["zones", "Zones DNS et leurs enregistrements"],
                  ["forwarders", "Redirecteurs"],
                  ["dhcp", "Étendues DHCP et réservations"],
                ] as const
              ).map(([k, label]) => (
                <label key={k} className="flex items-center gap-2 text-sm">
                  <Checkbox checked={form[k]} onCheckedChange={(v) => set({ [k]: v === true })} aria-label={label} />
                  {label}
                </label>
              ))}
              {local.what && (
                <p data-slot="field-error" className="text-sm text-destructive">
                  {local.what}
                </p>
              )}
            </fieldset>

            <p className="text-xs text-muted-foreground">
              Les objets qui existent déjà dans Leazone ne sont jamais écrasés. Le jeton ou le mot de passe ne sert que pour cette demande : il
              n'est pas enregistré.
            </p>
            <FormError message={formError(run.error, fieldsKnown)} />
          </CardContent>
          <CardFooter className="flex flex-col items-stretch gap-2 border-t pt-6 sm:flex-row sm:items-center sm:justify-end">
            {report?.dryRun && !previewFresh && (
              <p className="text-xs text-muted-foreground sm:mr-auto">Les réglages ont changé : prévisualisez à nouveau.</p>
            )}
            <Button type="submit" variant="outline" disabled={run.isPending}>
              {run.isPending && run.variables?.dryRun ? <Loader2 className="animate-spin" /> : <Eye />}
              Prévisualiser
            </Button>
            <Button type="button" disabled={!previewFresh || run.isPending || toCreate === 0} onClick={() => setConfirming(true)}>
              <Download /> Importer
            </Button>
          </CardFooter>
        </Card>
      </form>

      {report && <ReportCard report={report} />}

      <ConfirmDialog
        open={confirming}
        onOpenChange={setConfirming}
        title="Importer depuis Technitium ?"
        description={`${toCreate} élément(s) seront créés dans Leazone. Ce qui existe déjà n'est pas modifié. Une confirmation d'identité peut être demandée.`}
        confirmLabel="Importer"
        onConfirm={doImport}
      />
    </div>
  )
}

function ReportCard({ report }: { report: ImportReport }) {
  const items = report.items ?? []
  const dry = !!report.dryRun
  const created = dry ? items.filter((i) => i.action === "create").length : (report.created ?? 0)
  const skipped = report.skipped ?? items.filter((i) => i.action === "skip").length
  const errors = report.errors ?? items.filter((i) => i.action === "error").length
  return (
    <Card aria-live="polite">
      <CardHeader>
        <CardTitle>{dry ? "Aperçu de l'import" : "Rapport d'import"}</CardTitle>
        <CardDescription>
          {report.source ? `Technitium ${report.source}. ` : ""}
          {dry ? "Rien n'a encore été modifié." : "Import terminé."}
        </CardDescription>
        <div className="flex flex-wrap gap-2 pt-1">
          <Badge variant="outline" className={actionClass.create}>
            {created} {dry ? "à créer" : "créé(s)"}
          </Badge>
          <Badge variant="outline" className={actionClass.skip}>
            {skipped} ignoré(s)
          </Badge>
          <Badge variant="outline" className={cn(errors > 0 ? actionClass.error : "text-muted-foreground")}>
            {errors} erreur(s)
          </Badge>
        </div>
      </CardHeader>
      <CardContent className="space-y-6">
        {items.length === 0 && <p className="text-sm text-muted-foreground">Rien à importer.</p>}
        {kinds.map((k) => {
          const group = items.filter((i) => i.kind === k)
          if (group.length === 0) return null
          return (
            <section key={k} className="space-y-2">
              <h3 className="text-sm font-semibold">
                {kindLabel[k]} <span className="font-normal text-muted-foreground">({group.length})</span>
              </h3>
              <div className="rounded-lg border">
                <Table>
                  <TableHeader>
                    <TableRow className="hover:bg-transparent">
                      <TableHead className="text-xs text-muted-foreground">Nom</TableHead>
                      <TableHead className="w-28 text-xs text-muted-foreground">Action</TableHead>
                      <TableHead className="text-xs text-muted-foreground">Détail</TableHead>
                    </TableRow>
                  </TableHeader>
                  <TableBody>
                    {group.map((i, n) => (
                      <TableRow key={`${i.name}-${n}`}>
                        <TableCell className="font-mono text-xs">{i.name}</TableCell>
                        <TableCell>
                          <Badge variant="outline" className={actionClass[i.action ?? "skip"]}>
                            {actionLabel(i.action ?? "skip", dry)}
                          </Badge>
                        </TableCell>
                        <TableCell className="text-sm whitespace-normal text-muted-foreground">{i.detail || "—"}</TableCell>
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>
              </div>
            </section>
          )
        })}
      </CardContent>
    </Card>
  )
}
