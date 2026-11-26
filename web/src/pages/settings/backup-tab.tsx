import * as React from "react"
import { useSearchParams } from "react-router"
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query"
import { Archive, Download, FileCheck2, FileUp, HardDrive, Info, Loader2, RotateCcw, TriangleAlert } from "lucide-react"
import { toast } from "sonner"
import { api, requestFile } from "@/api/client"
import { backupsQuery } from "@/api/queries"
import type { RestoreResult } from "@/api/types"
import { ConfirmDialog } from "@/components/confirm-dialog"
import { CopyButton } from "@/components/copy-button"
import { Field, FormError } from "@/components/form-field"
import { WriteGuard } from "@/components/read-only"
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert"
import { Button } from "@/components/ui/button"
import { Card, CardContent, CardDescription, CardFooter, CardHeader, CardTitle } from "@/components/ui/card"
import { Input } from "@/components/ui/input"
import { Skeleton } from "@/components/ui/skeleton"
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table"
import { usePermissions } from "@/hooks/use-cluster"
import { downloadBlob } from "@/lib/download"
import { errorMessage, fieldError, formError, toastError } from "@/lib/errors"
import { formatDateTime } from "@/lib/format"
import { fmtInt, formatSize } from "@/lib/logs"
import { cn } from "@/lib/utils"

const MIN_PASSWORD = 12
const MAX_FILE = 32 * 1024 * 1024
const DATA_BACKUP_CMD = "docker run --rm -v leazone_leazone-data:/d -v $PWD:/b alpine tar czf /b/leazone-data.tgz -C /d ."

export function BackupTab() {
  return (
    <div className="space-y-6">
      <DownloadCard />
      <RestoreCard />
      <AutoBackupsCard />
      <DataVolumeCard />
    </div>
  )
}

/** Rough strength of a password, for a hint only (the server checks the length). */
function strength(pw: string): { label: string; tone: "bad" | "weak" | "ok" | "good"; score: number } {
  if (pw.length < MIN_PASSWORD) return { label: `trop court (${pw.length}/${MIN_PASSWORD} caractères)`, tone: "bad", score: 0 }
  let score = 1
  if (pw.length >= 16) score++
  if (pw.length >= 20) score++
  const classes = [/[a-z]/, /[A-Z]/, /\d/, /[^A-Za-z0-9]/].filter((r) => r.test(pw)).length
  if (classes >= 3) score++
  if (/^(.)\1+$/.test(pw) || /^(?:0123|1234|abcd|azer|qwer|password|motdepasse)/i.test(pw)) score = 1
  if (score <= 1) return { label: "faible : allongez-le ou mélangez lettres, chiffres et signes", tone: "weak", score }
  if (score === 2) return { label: "correct", tone: "ok", score }
  return { label: "solide", tone: "good", score: Math.min(score, 4) }
}

function StrengthHint({ password }: { password: string }) {
  if (!password) return <span>Au moins {MIN_PASSWORD} caractères. Une phrase de plusieurs mots est idéale.</span>
  const s = strength(password)
  const color = { bad: "bg-destructive", weak: "bg-warning", ok: "bg-brand", good: "bg-success" }[s.tone]
  return (
    <span className="flex items-center gap-2" data-testid="password-strength">
      <span className="flex gap-0.5" aria-hidden>
        {[1, 2, 3, 4].map((i) => (
          <span key={i} className={cn("h-1 w-5 rounded-full", i <= Math.max(1, s.score) ? color : "bg-muted")} />
        ))}
      </span>
      <span>Force : {s.label}</span>
    </span>
  )
}

function DownloadCard() {
  const [params, setParams] = useSearchParams()
  const inputRef = React.useRef<HTMLInputElement>(null)
  const cardRef = React.useRef<HTMLDivElement>(null)
  const [password, setPassword] = React.useState("")
  const [confirm, setConfirm] = React.useState("")
  const [local, setLocal] = React.useState<Record<string, string>>({})

  // ⌘K "Télécharger une sauvegarde" lands here with ?download=1.
  React.useEffect(() => {
    if (params.get("download") !== "1") return
    cardRef.current?.scrollIntoView({ block: "start" })
    inputRef.current?.focus()
    setParams(
      (p) => {
        const n = new URLSearchParams(p)
        n.delete("download")
        return n
      },
      { replace: true },
    )
  }, [params, setParams])

  const backup = useMutation({
    mutationFn: (pw: string) => requestFile("post", "/backup", { body: { password: pw } }),
    meta: { silent: true },
    onSuccess: ({ blob, filename }) => {
      const stamp = new Date().toISOString().slice(0, 16).replace(/[-:]/g, "").replace("T", "-")
      downloadBlob(filename || `leazone-backup-${stamp}.yaml`, blob)
      setPassword("")
      setConfirm("")
      toast.success("Sauvegarde téléchargée.", { description: "Gardez le mot de passe en lieu sûr : sans lui, le fichier ne peut pas être restauré." })
    },
  })

  const submit = (e: React.FormEvent) => {
    e.preventDefault()
    const errs: Record<string, string> = {}
    if (password.length < MIN_PASSWORD) errs.password = `Au moins ${MIN_PASSWORD} caractères.`
    else if (confirm !== password) errs.confirm = "Les deux mots de passe ne sont pas identiques."
    setLocal(errs)
    if (Object.keys(errs).length === 0) backup.mutate(password)
  }

  return (
    <form onSubmit={submit} noValidate>
      <Card ref={cardRef} data-testid="backup-card">
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <Download className="size-5 text-muted-foreground" /> Télécharger une sauvegarde
          </CardTitle>
          <CardDescription>
            Toute la configuration dans un fichier YAML. Les secrets (TOTP, clés DNSSEC, clé du certificat) restent chiffrés ; le mot de passe protège leur
            clé. Sans ce mot de passe, le fichier ne peut pas être restauré.
          </CardDescription>
        </CardHeader>
        <CardContent className="grid gap-4 sm:grid-cols-2">
          <Field
            label="Mot de passe de la sauvegarde"
            htmlFor="bk-password"
            help={<StrengthHint password={password} />}
            error={local.password ?? fieldError(backup.error, "password")}
          >
            <Input
              ref={inputRef}
              id="bk-password"
              type="password"
              autoComplete="new-password"
              value={password}
              onChange={(e) => {
                setPassword(e.target.value)
                setLocal({})
              }}
            />
          </Field>
          <Field label="Confirmation" htmlFor="bk-confirm" error={local.confirm}>
            <Input
              id="bk-confirm"
              type="password"
              autoComplete="new-password"
              value={confirm}
              onChange={(e) => {
                setConfirm(e.target.value)
                setLocal({})
              }}
            />
          </Field>
          {formError(backup.error, ["password"]) && (
            <div className="sm:col-span-2">
              <FormError message={formError(backup.error, ["password"])} />
            </div>
          )}
        </CardContent>
        <CardFooter className="justify-end">
          <Button type="submit" disabled={backup.isPending}>
            {backup.isPending ? <Loader2 className="animate-spin" /> : <Download />}
            Télécharger
          </Button>
        </CardFooter>
      </Card>
    </form>
  )
}

/** French names of the tables of a backup (unknown ones keep their name). */
const tableLabels: [string, string][] = [
  ["users", "utilisateurs"],
  ["webauthn_credentials", "passkeys"],
  ["totp", "TOTP"],
  ["recovery_codes", "codes de secours"],
  ["api_tokens", "jetons d'API"],
  ["zones", "zones"],
  ["records", "enregistrements"],
  ["forwarders", "redirecteurs"],
  ["dhcp_scopes", "étendues"],
  ["dhcp_reservations", "réservations"],
  ["dhcp_leases", "baux"],
  ["vlans", "VLAN"],
  ["interface_settings", "interfaces"],
  ["block_lists", "listes de blocage"],
  ["block_rules", "règles de blocage"],
  ["block_policies", "où bloquer"],
  ["dnssec_keys", "clés DNSSEC"],
  ["certificates", "certificats"],
  ["settings", "réglages"],
  ["audit_log", "journal d'audit"],
]
const labelOf = new Map(tableLabels)
const orderOf = new Map(tableLabels.map(([k], i) => [k, i]))

function sortedTables(tables?: Record<string, number>) {
  return Object.entries(tables ?? {}).sort(
    ([a], [b]) => (orderOf.get(a) ?? 999) - (orderOf.get(b) ?? 999) || a.localeCompare(b),
  )
}

function RestoreCard() {
  const qc = useQueryClient()
  const perms = usePermissions()
  const fileRef = React.useRef<HTMLInputElement>(null)
  const [file, setFile] = React.useState<{ name: string; size: number; content: string } | null>(null)
  const [fileError, setFileError] = React.useState("")
  const [password, setPassword] = React.useState("")
  const [checked, setChecked] = React.useState<RestoreResult | null>(null)
  const [confirming, setConfirming] = React.useState(false)

  const check = useMutation({
    mutationFn: (v: { content: string; password: string }) => api.post("/restore", { body: { ...v, dryRun: true } }),
    meta: { silent: true },
    onSuccess: (r) => setChecked(r ?? {}),
  })
  const restore = useMutation({
    mutationFn: (v: { content: string; password: string }) => api.post("/restore", { body: { ...v, dryRun: false } }),
    meta: { silent: true },
    onSuccess: () => {
      toast.success("Configuration restaurée.", { description: "Toutes les pages sont rechargées avec la nouvelle configuration." })
      setFile(null)
      setPassword("")
      setChecked(null)
      if (fileRef.current) fileRef.current.value = ""
      // Everything may have changed: reload every query.
      void qc.invalidateQueries()
    },
  })

  const reset = () => {
    setChecked(null)
    check.reset()
    restore.reset()
  }

  const onFile = async (e: React.ChangeEvent<HTMLInputElement>) => {
    reset()
    setFileError("")
    const f = e.target.files?.[0]
    if (!f) return setFile(null)
    if (f.size > MAX_FILE) {
      setFile(null)
      setFileError("Fichier trop gros (32 Mo au plus).")
      return
    }
    setFile({ name: f.name, size: f.size, content: await f.text() })
  }

  const submitCheck = (e: React.FormEvent) => {
    e.preventDefault()
    if (!file) return setFileError("Choisissez un fichier de sauvegarde.")
    if (!password) return
    check.mutate({ content: file.content, password })
  }

  const err = check.error ?? restore.error
  const tables = sortedTables(checked?.tables)

  const body = (
    <form onSubmit={submitCheck} noValidate className="space-y-4">
      <div className="grid gap-4 sm:grid-cols-2">
        <Field label="Fichier de sauvegarde (.yaml)" htmlFor="rs-file" error={fileError}>
          <div className="flex items-center gap-2">
            <Button type="button" variant="outline" onClick={() => fileRef.current?.click()}>
              <FileUp /> Choisir…
            </Button>
            <span className="min-w-0 truncate text-sm text-muted-foreground" data-testid="restore-file">
              {file ? `${file.name} (${formatSize(file.size)})` : "Aucun fichier"}
            </span>
            <input
              ref={fileRef}
              id="rs-file"
              type="file"
              accept=".yaml,.yml,application/yaml,text/yaml"
              className="sr-only"
              onChange={onFile}
              tabIndex={-1}
            />
          </div>
        </Field>
        <Field label="Mot de passe de la sauvegarde" htmlFor="rs-password" error={fieldError(err, "password")}>
          <Input
            id="rs-password"
            type="password"
            autoComplete="off"
            value={password}
            onChange={(e) => {
              setPassword(e.target.value)
              reset()
            }}
          />
        </Field>
      </div>
      <FormError message={formError(err, ["password"])} />

      {checked ? (
        <div className="space-y-3 rounded-lg border bg-muted/30 p-4" data-testid="restore-summary">
          <p className="flex items-center gap-2 text-sm font-medium">
            <FileCheck2 className="size-4 text-success" /> Fichier valide, mot de passe correct.
          </p>
          <dl className="grid gap-x-6 gap-y-1 text-sm sm:grid-cols-3">
            <div>
              <dt className="text-xs text-muted-foreground">Faite le</dt>
              <dd>{formatDateTime(checked.createdAt)}</dd>
            </div>
            <div>
              <dt className="text-xs text-muted-foreground">Version</dt>
              <dd>{checked.version || "—"}</dd>
            </div>
            <div>
              <dt className="text-xs text-muted-foreground">Nœud</dt>
              <dd>{checked.node || "—"}</dd>
            </div>
          </dl>
          {tables.length > 0 && (
            <ul className="grid grid-cols-2 gap-x-6 gap-y-0.5 text-sm sm:grid-cols-3">
              {tables.map(([k, n]) => (
                <li key={k} className="flex justify-between gap-2">
                  <span className="truncate text-muted-foreground" title={k}>
                    {labelOf.get(k) ?? k}
                  </span>
                  <span className="tabular-nums">{fmtInt.format(n)}</span>
                </li>
              ))}
            </ul>
          )}
          <div className="flex flex-wrap justify-end gap-2 pt-1">
            <Button type="button" variant="outline" onClick={reset}>
              Annuler
            </Button>
            <Button type="button" variant="destructive" onClick={() => setConfirming(true)}>
              <RotateCcw /> Remplacer toute la configuration…
            </Button>
          </div>
        </div>
      ) : (
        <div className="flex justify-end">
          <Button type="submit" variant="outline" disabled={check.isPending || !file || !password}>
            {check.isPending ? <Loader2 className="animate-spin" /> : <FileCheck2 />}
            Vérifier le fichier
          </Button>
        </div>
      )}
    </form>
  )

  return (
    <Card data-testid="restore-card">
      <CardHeader>
        <CardTitle className="flex items-center gap-2">
          <RotateCcw className="size-5 text-muted-foreground" /> Restaurer
        </CardTitle>
        <CardDescription>
          Remplace toute la configuration par celle du fichier. Les sessions ouvertes restent ouvertes ; les utilisateurs, passkeys et TOTP viennent de la
          sauvegarde. Le fichier est d'abord vérifié, rien n'est changé avant votre confirmation.
        </CardDescription>
      </CardHeader>
      <CardContent>{perms.can("admin") ? body : <WriteGuard block>{body}</WriteGuard>}</CardContent>
      <ConfirmDialog
        open={confirming}
        onOpenChange={setConfirming}
        title="Remplacer toute la configuration ?"
        description={
          <>
            Zones, enregistrements, étendues, réservations, redirecteurs, utilisateurs et réglages actuels sont remplacés par ceux de la sauvegarde
            {checked?.createdAt ? ` du ${formatDateTime(checked.createdAt)}` : ""}. Cette action ne peut pas être annulée : téléchargez d'abord une sauvegarde
            de la configuration actuelle si besoin.
          </>
        }
        confirmLabel="Remplacer toute la configuration"
        destructive
        onConfirm={() => (file ? restore.mutateAsync({ content: file.content, password }) : undefined)}
      />
    </Card>
  )
}

function AutoBackupsCard() {
  const list = useQuery(backupsQuery)
  const [busy, setBusy] = React.useState("")
  const download = async (name: string) => {
    setBusy(name)
    try {
      const { blob, filename } = await requestFile("get", "/backups/{name}", { params: { name } })
      downloadBlob(filename || name, blob)
    } catch (e) {
      toastError(e, "Téléchargement impossible")
    } finally {
      setBusy("")
    }
  }
  const items = [...(list.data?.items ?? [])].sort((a, b) => (b.createdAt ?? "").localeCompare(a.createdAt ?? ""))

  return (
    <Card data-testid="auto-backups">
      <CardHeader>
        <CardTitle className="flex items-center gap-2">
          <Archive className="size-5 text-muted-foreground" /> Sauvegardes automatiques
        </CardTitle>
        <CardDescription>Une sauvegarde par jour dans /data/backups sur ce nœud, les 7 dernières sont gardées.</CardDescription>
      </CardHeader>
      <CardContent>
        {list.isPending ? (
          <Skeleton className="h-16 w-full" />
        ) : list.isError ? (
          <p className="text-sm text-destructive">{errorMessage(list.error)}</p>
        ) : !list.data?.enabled ? (
          <Alert data-testid="auto-backups-off">
            <Info />
            <AlertTitle>Désactivées</AlertTitle>
            <AlertDescription>
              <p>
                Ajoutez <code className="rounded bg-muted px-1 py-0.5 font-mono text-xs">LEAZONE_BACKUP_PASSWORD_FILE</code> pour une sauvegarde automatique
                chaque jour dans /data/backups (7 gardées).
              </p>
            </AlertDescription>
          </Alert>
        ) : items.length === 0 ? (
          <p className="text-sm text-muted-foreground">Aucune sauvegarde pour l'instant : la première sera faite dans la journée.</p>
        ) : (
          <div className="rounded-lg border">
            <Table>
              <TableHeader>
                <TableRow className="hover:bg-transparent">
                  <TableHead>Fichier</TableHead>
                  <TableHead>Date</TableHead>
                  <TableHead className="text-right">Taille</TableHead>
                  <TableHead>
                    <span className="sr-only">Télécharger</span>
                  </TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {items.map((b) => (
                  <TableRow key={b.name}>
                    <TableCell className="font-mono text-xs">{b.name}</TableCell>
                    <TableCell className="whitespace-nowrap">{formatDateTime(b.createdAt)}</TableCell>
                    <TableCell className="text-right tabular-nums">{formatSize(b.size)}</TableCell>
                    <TableCell className="text-right">
                      <Button
                        variant="ghost"
                        size="icon-sm"
                        aria-label={`Télécharger ${b.name}`}
                        onClick={() => download(b.name ?? "")}
                        disabled={!!busy}
                      >
                        {busy === b.name ? <Loader2 className="animate-spin" /> : <Download />}
                      </Button>
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </div>
        )}
      </CardContent>
    </Card>
  )
}

function DataVolumeCard() {
  return (
    <Card>
      <CardHeader>
        <CardTitle className="flex items-center gap-2">
          <HardDrive className="size-5 text-muted-foreground" /> Copie complète du volume /data
        </CardTitle>
        <CardDescription>
          Pour tout garder (base, certificats, journaux), copiez aussi le volume Docker, de préférence serveur arrêté :
        </CardDescription>
      </CardHeader>
      <CardContent className="space-y-2">
        <div className="flex items-start gap-2">
          <pre className="min-w-0 flex-1 overflow-x-auto rounded-md bg-muted px-3 py-2 font-mono text-xs" data-testid="data-cmd">
            {DATA_BACKUP_CMD}
          </pre>
          <CopyButton value={DATA_BACKUP_CMD} iconOnly label="Copier la commande" />
        </div>
        <p className="flex items-center gap-1.5 text-xs text-muted-foreground">
          <TriangleAlert className="size-3.5 shrink-0" /> Cette archive contient aussi la clé maîtresse qui déchiffre les secrets : rangez-la comme un mot de passe.
        </p>
      </CardContent>
    </Card>
  )
}
