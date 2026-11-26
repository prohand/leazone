import * as React from "react"
import { Link, useParams } from "react-router"
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query"
import {
  ArrowLeft,
  ChevronDown,
  CircleCheck,
  Download,
  Globe,
  KeyRound,
  Loader2,
  PenLine,
  PowerOff,
  RefreshCw,
  ShieldCheck,
  TriangleAlert,
} from "lucide-react"
import { toast } from "sonner"
import { api, isApiError, ProblemType } from "@/api/client"
import { dnssecZoneQuery, qk } from "@/api/queries"
import type { DnssecKey, DnssecZone } from "@/api/types"
import { ConfirmDialog } from "@/components/confirm-dialog"
import { CopyButton } from "@/components/copy-button"
import { EmptyState } from "@/components/empty-state"
import { WriteGuard } from "@/components/read-only"
import { BlockSpinner } from "@/components/spinner"
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert"
import { Badge } from "@/components/ui/badge"
import { Button } from "@/components/ui/button"
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle } from "@/components/ui/dialog"
import { Label } from "@/components/ui/label"
import { RadioGroup, RadioGroupItem } from "@/components/ui/radio-group"
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table"
import { usePermissions } from "@/hooks/use-cluster"
import { algorithmLabel, keyStateClass, keyStateLabel, nsecLabel } from "@/lib/dnssec"
import { downloadText } from "@/lib/download"
import { errorMessage, toastError } from "@/lib/errors"
import { formatDate, formatDateTime, formatRelativeShort } from "@/lib/format"
import { cn } from "@/lib/utils"
import { DsPendingBadge, SignedBadge } from "./badges"

type Confirm = "zsk" | "ksk" | "disable" | null

export default function DnssecZonePage() {
  const { id = "" } = useParams()
  const qc = useQueryClient()
  const perms = usePermissions()
  const zone = useQuery(dnssecZoneQuery(id))
  const [signing, setSigning] = React.useState(false)
  const [confirm, setConfirm] = React.useState<Confirm>(null)
  const [exporting, setExporting] = React.useState(false)

  const update = (z?: DnssecZone) => {
    if (z) qc.setQueryData(qk.dnssecZone(id), z)
    void qc.invalidateQueries({ queryKey: qk.dnssec })
  }

  const rollover = useMutation({
    mutationFn: (type: "zsk" | "ksk") => api.post("/dnssec/zones/{id}/rollover", { params: { id }, body: { type } }),
    onSuccess: (z, type) => {
      update(z)
      toast.success(
        type === "ksk" ? "Nouvelle KSK créée. Donnez le nouveau DS à votre registrar." : "Changement de ZSK lancé.",
      )
    },
  })
  const dsPublished = useMutation({
    mutationFn: () => api.post("/dnssec/zones/{id}/ds-published", { params: { id } }),
    onSuccess: (z) => {
      update(z)
      toast.success("Merci ! L'ancienne clé sera retirée.")
    },
  })
  const disable = useMutation({
    mutationFn: () => api.post("/dnssec/zones/{id}/disable", { params: { id } }),
    onSuccess: (z) => {
      update(z)
      toast.success("Signature arrêtée.")
    },
  })

  const exportKeys = async () => {
    setExporting(true)
    try {
      // GET text/plain; a step-up problem runs the step-up dialog, then retries (api client).
      const text = await api.get("/dnssec/zones/{id}/export", { params: { id } })
      const name = (zone.data?.name ?? "zone").replace(/\.$/, "")
      downloadText(`${name}.keys.txt`, typeof text === "string" ? text : "")
      toast.success("Clés exportées. Gardez ce fichier en lieu sûr : il contient les clés privées.")
    } catch (e) {
      toastError(e, "Export impossible")
    } finally {
      setExporting(false)
    }
  }

  if (zone.isPending) return <BlockSpinner />
  if (zone.isError) {
    const notFound = isApiError(zone.error, ProblemType.notFound)
    return (
      <EmptyState
        icon={ShieldCheck}
        title={notFound ? "Zone introuvable" : "Erreur"}
        description={notFound ? "Elle a peut-être été supprimée, ou ce n'est pas une zone directe." : errorMessage(zone.error)}
        action={
          <Button asChild variant="outline">
            <Link to="/dnssec">
              <ArrowLeft /> Retour
            </Link>
          </Button>
        }
      />
    )
  }

  const z = zone.data
  const keys = [...(z.keys ?? [])].sort((a, b) => (a.role === b.role ? (a.createdAt ?? "").localeCompare(b.createdAt ?? "") : a.role === "ksk" ? -1 : 1))
  const canConfig = perms.allowed("config.write")

  return (
    <>
      <Link
        to="/dnssec"
        className="mb-3 inline-flex items-center gap-1 text-sm text-muted-foreground transition-colors hover:text-foreground"
      >
        <ArrowLeft className="size-4" /> DNSSEC
      </Link>
      <div className="mb-6 flex flex-col gap-3 sm:flex-row sm:items-end sm:justify-between">
        <div className="min-w-0 space-y-1.5">
          <h1 className="truncate text-2xl font-semibold tracking-tight">{z.name}</h1>
          <div className="flex flex-wrap items-center gap-2 text-sm text-muted-foreground">
            <SignedBadge enabled={z.enabled} />
            {z.enabled && z.dsPending && <DsPendingBadge />}
            {z.enabled && (
              <>
                <span>{algorithmLabel(z.algorithm)}</span>
                {z.nsecMode && (
                  <>
                    <span aria-hidden>·</span>
                    <span>{nsecLabel[z.nsecMode]}</span>
                  </>
                )}
                {z.nextZskRollover && (
                  <>
                    <span aria-hidden>·</span>
                    <span title={formatDateTime(z.nextZskRollover)}>prochaine ZSK {formatRelativeShort(z.nextZskRollover)}</span>
                  </>
                )}
              </>
            )}
          </div>
        </div>
        <Button asChild variant="outline">
          <Link to={`/dns/zones/${encodeURIComponent(id)}`}>
            <Globe /> Enregistrements
          </Link>
        </Button>
      </div>

      {!z.enabled ? (
        <Card className="max-w-2xl" data-testid="not-signed">
          <CardHeader>
            <CardTitle>Cette zone n'est pas signée</CardTitle>
            <CardDescription>
              Leazone crée les clés, signe la zone et la re-signe à chaque changement. Les clés sont copiées (chiffrées) sur
              l'autre nœud. Vous donnerez ensuite un enregistrement DS à votre registrar.
            </CardDescription>
          </CardHeader>
          {canConfig && (
            <CardContent>
              <WriteGuard>
                <Button onClick={() => setSigning(true)}>
                  <PenLine /> Signer la zone
                </Button>
              </WriteGuard>
            </CardContent>
          )}
        </Card>
      ) : (
        <div className="space-y-6">
          {z.dsPending && (
            <Alert className="border-warning/50 bg-warning/5" data-testid="ds-pending">
              <TriangleAlert className="text-warning" />
              <AlertTitle>Nouveau DS à publier</AlertTitle>
              <AlertDescription className="space-y-3">
                <p>
                  Une nouvelle KSK attend son DS. Donnez le DS ci-dessous à votre registrar, attendez qu'il soit en ligne, puis
                  confirmez.
                </p>
                {canConfig && (
                  <WriteGuard>
                    <Button size="sm" onClick={() => dsPublished.mutate()} disabled={dsPublished.isPending}>
                      {dsPublished.isPending ? <Loader2 className="animate-spin" /> : <CircleCheck />} J'ai publié le DS
                    </Button>
                  </WriteGuard>
                )}
              </AlertDescription>
            </Alert>
          )}

          <Card data-testid="ds-card">
            <CardHeader>
              <CardTitle>Enregistrement DS</CardTitle>
              <CardDescription>
                À donner à votre registrar (bureau d'enregistrement). Tant que le DS n'est pas publié, la zone reste valide mais
                non sécurisée.
              </CardDescription>
            </CardHeader>
            <CardContent>
              {(z.ds ?? []).length === 0 ? (
                <p className="text-sm text-muted-foreground">Pas encore de DS : les clés sont en cours de création.</p>
              ) : (
                <ul className="space-y-2">
                  {(z.ds ?? []).map((ds) => (
                    <li key={ds} className="flex items-start gap-2 rounded-lg border bg-muted/30 p-2 pl-3">
                      <code className="min-w-0 flex-1 py-1.5 font-mono text-xs break-all">{ds}</code>
                      <CopyButton value={ds} iconOnly size="icon-sm" variant="ghost" label="Copier le DS" />
                    </li>
                  ))}
                </ul>
              )}
            </CardContent>
          </Card>

          <Card className="gap-4">
            <CardHeader>
              <CardTitle>Clés</CardTitle>
              <CardDescription>
                La KSK signe les clés et correspond au DS. La ZSK signe les enregistrements et change toute seule
                régulièrement.
              </CardDescription>
            </CardHeader>
            <CardContent>
              <KeysTable keys={keys} />
            </CardContent>
          </Card>

          <Card className="gap-4">
            <CardHeader>
              <CardTitle>Actions</CardTitle>
            </CardHeader>
            <CardContent className="flex flex-wrap gap-2">
              {canConfig && (
                <WriteGuard className="flex-wrap gap-2">
                  <Button variant="outline" onClick={() => setConfirm("zsk")}>
                    <RefreshCw /> Changer la ZSK
                  </Button>
                  <Button variant="outline" onClick={() => setConfirm("ksk")} disabled={z.dsPending}>
                    <KeyRound /> Changer la KSK
                  </Button>
                </WriteGuard>
              )}
              {perms.allowed("admin") && (
                <Button variant="outline" onClick={exportKeys} disabled={exporting}>
                  {exporting ? <Loader2 className="animate-spin" /> : <Download />} Exporter les clés
                </Button>
              )}
              {canConfig && (
                <WriteGuard>
                  <Button variant="outline" className="text-destructive hover:text-destructive" onClick={() => setConfirm("disable")}>
                    <PowerOff /> Arrêter la signature
                  </Button>
                </WriteGuard>
              )}
              {!canConfig && !perms.allowed("admin") && (
                <p className="text-sm text-muted-foreground">Seul un administrateur peut changer les clés.</p>
              )}
            </CardContent>
          </Card>
        </div>
      )}

      <SignDialog zone={z} open={signing} onOpenChange={setSigning} onSigned={update} />
      <ConfirmDialog
        open={confirm === "zsk"}
        onOpenChange={(o) => !o && setConfirm(null)}
        title="Changer la ZSK maintenant ?"
        description="Une nouvelle clé de signature est publiée puis prend le relais. Rien à faire chez le registrar. Ce changement est aussi fait automatiquement."
        confirmLabel="Changer la ZSK"
        onConfirm={() => rollover.mutateAsync("zsk")}
      />
      <ConfirmDialog
        open={confirm === "ksk"}
        onOpenChange={(o) => !o && setConfirm(null)}
        title="Changer la KSK ?"
        description="Une nouvelle KSK est créée, avec un nouveau DS. Vous devrez donner ce nouveau DS à votre registrar, puis cliquer sur « J'ai publié le DS ». L'ancienne clé reste active jusque-là."
        confirmLabel="Changer la KSK"
        onConfirm={() => rollover.mutateAsync("ksk")}
      />
      <ConfirmDialog
        open={confirm === "disable"}
        onOpenChange={(o) => !o && setConfirm(null)}
        title={`Arrêter la signature de ${z.name} ?`}
        description="Retirez d'abord le DS chez le registrar, sinon la zone devient injoignable pour les résolveurs qui valident."
        confirmLabel="Arrêter la signature"
        destructive
        onConfirm={() => disable.mutateAsync()}
      />
    </>
  )
}

function KeysTable({ keys }: { keys: DnssecKey[] }) {
  const [open, setOpen] = React.useState<string | null>(null)
  if (keys.length === 0) return <p className="text-sm text-muted-foreground">Aucune clé.</p>
  return (
    <div className="rounded-lg border">
      <Table>
        <TableHeader>
          <TableRow className="hover:bg-transparent">
            <TableHead className="text-xs text-muted-foreground">Rôle</TableHead>
            <TableHead className="text-xs text-muted-foreground">Tag</TableHead>
            <TableHead className="text-xs text-muted-foreground">Algorithme</TableHead>
            <TableHead className="text-xs text-muted-foreground">État</TableHead>
            <TableHead className="text-xs text-muted-foreground">Créée</TableHead>
            <TableHead className="text-xs text-muted-foreground">Active depuis</TableHead>
            <TableHead className="text-xs text-muted-foreground">Retrait</TableHead>
            <TableHead className="w-0" />
          </TableRow>
        </TableHeader>
        <TableBody>
          {keys.map((k) => {
            const id = k.id ?? `${k.role}-${k.keyTag}`
            const expanded = open === id
            return (
              <React.Fragment key={id}>
                <TableRow className={cn(k.state === "retired" && "text-muted-foreground")} data-testid={`key-${k.keyTag}`}>
                  <TableCell>
                    <Badge variant={k.role === "ksk" ? "default" : "secondary"}>{k.role === "ksk" ? "KSK" : "ZSK"}</Badge>
                  </TableCell>
                  <TableCell className="font-mono tabular-nums">{k.keyTag ?? "—"}</TableCell>
                  <TableCell className="whitespace-nowrap">{algorithmLabel(k.algorithm)}</TableCell>
                  <TableCell>
                    {k.state && (
                      <Badge variant="outline" className={keyStateClass[k.state]}>
                        {keyStateLabel[k.state]}
                      </Badge>
                    )}
                  </TableCell>
                  <TableCell className="whitespace-nowrap" title={formatDateTime(k.createdAt)}>
                    {formatDate(k.createdAt)}
                  </TableCell>
                  <TableCell className="whitespace-nowrap" title={k.activeAt ? formatDateTime(k.activeAt) : undefined}>
                    {k.activeAt ? formatDate(k.activeAt) : "—"}
                  </TableCell>
                  <TableCell className="whitespace-nowrap" title={k.retireAt ? formatDateTime(k.retireAt) : undefined}>
                    {k.retireAt ? formatRelativeShort(k.retireAt) : "—"}
                  </TableCell>
                  <TableCell className="text-right">
                    {k.dnskey && (
                      <Button
                        variant="ghost"
                        size="sm"
                        aria-expanded={expanded}
                        onClick={() => setOpen(expanded ? null : id)}
                        className="whitespace-nowrap"
                      >
                        DNSKEY <ChevronDown className={cn("transition-transform", expanded && "rotate-180")} />
                      </Button>
                    )}
                  </TableCell>
                </TableRow>
                {expanded && k.dnskey && (
                  <TableRow className="hover:bg-transparent">
                    <TableCell colSpan={8} className="bg-muted/30">
                      <div className="flex items-start gap-2">
                        <code className="min-w-0 flex-1 font-mono text-xs break-all whitespace-pre-wrap">{k.dnskey}</code>
                        <CopyButton value={k.dnskey} iconOnly size="icon-sm" variant="ghost" label="Copier la DNSKEY" />
                      </div>
                    </TableCell>
                  </TableRow>
                )}
              </React.Fragment>
            )
          })}
        </TableBody>
      </Table>
    </div>
  )
}

function Choice({ value, id, label, help }: { value: string; id: string; label: string; help: string }) {
  return (
    <div className="flex items-start gap-3">
      <RadioGroupItem value={value} id={id} className="mt-0.5" />
      <Label htmlFor={id} className="flex flex-col items-start gap-0.5 font-normal">
        <span className="font-medium">{label}</span>
        <span className="text-xs text-muted-foreground">{help}</span>
      </Label>
    </div>
  )
}

function SignDialog({
  zone,
  open,
  onOpenChange,
  onSigned,
}: {
  zone: DnssecZone
  open: boolean
  onOpenChange: (o: boolean) => void
  onSigned: (z?: DnssecZone) => void
}) {
  const [algorithm, setAlgorithm] = React.useState<"13" | "15">("13")
  const [nsecMode, setNsecMode] = React.useState<"nsec3" | "nsec">("nsec3")
  const enable = useMutation({
    mutationFn: () =>
      api.post("/dnssec/zones/{id}/enable", {
        params: { id: zone.zoneId ?? "" },
        body: { algorithm: algorithm === "15" ? 15 : 13, nsecMode },
      }),
    onSuccess: (z) => {
      onSigned(z)
      toast.success("Zone signée. Donnez maintenant le DS à votre registrar.")
      onOpenChange(false)
    },
  })

  React.useEffect(() => {
    if (open) {
      setAlgorithm("13")
      setNsecMode("nsec3")
      enable.reset()
    }
    // Reset only when the dialog opens.
  }, [open])

  return (
    <Dialog open={open} onOpenChange={(o) => !enable.isPending && onOpenChange(o)}>
      <DialogContent className="sm:max-w-lg">
        <DialogHeader>
          <DialogTitle>Signer {zone.name}</DialogTitle>
          <DialogDescription>Les valeurs recommandées conviennent dans presque tous les cas.</DialogDescription>
        </DialogHeader>
        <div className="space-y-5">
          <div className="space-y-3">
            <p className="text-sm font-medium">Algorithme</p>
            <RadioGroup value={algorithm} onValueChange={(v) => setAlgorithm(v as "13" | "15")}>
              <Choice value="13" id="alg-13" label="ECDSA P-256 (recommandé)" help="Compris par tous les résolveurs." />
              <Choice value="15" id="alg-15" label="Ed25519" help="Plus récent et plus compact, mais pas encore compris partout." />
            </RadioGroup>
          </div>
          <div className="space-y-3">
            <p className="text-sm font-medium">Preuve d'absence d'un nom</p>
            <RadioGroup value={nsecMode} onValueChange={(v) => setNsecMode(v as "nsec3" | "nsec")}>
              <Choice value="nsec3" id="nsec3" label="NSEC3 (recommandé)" help="Cache la liste des noms de la zone." />
              <Choice value="nsec" id="nsec" label="NSEC" help="Plus simple, mais permet de lister tous les noms de la zone." />
            </RadioGroup>
          </div>
        </div>
        <DialogFooter>
          <Button type="button" variant="outline" onClick={() => onOpenChange(false)} disabled={enable.isPending}>
            Annuler
          </Button>
          <Button onClick={() => enable.mutate()} disabled={enable.isPending}>
            {enable.isPending ? <Loader2 className="animate-spin" /> : <ShieldCheck />} Signer la zone
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  )
}
