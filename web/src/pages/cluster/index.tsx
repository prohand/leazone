import * as React from "react"
import { useLocation, useNavigate } from "react-router"
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query"
import {
  ArrowLeftRight,
  CircleCheck,
  Crown,
  FileDiff,
  Layers,
  Network,
  Radar,
  RefreshCw,
  Server,
  Tag,
  TriangleAlert,
  type LucideIcon,
} from "lucide-react"
import { toast } from "sonner"
import { api } from "@/api/client"
import { clusterQuery, qk } from "@/api/queries"
import type { ClusterGap, ClusterNode, ClusterTerm, ClusterView, ClusterWitness } from "@/api/types"
import { ClusterRoleBadge } from "@/components/cluster"
import { ConfirmDialog } from "@/components/confirm-dialog"
import { PageHeader } from "@/components/page-header"
import { BlockSpinner } from "@/components/spinner"
import { StatusDot } from "@/components/status-dot"
import { Badge } from "@/components/ui/badge"
import { Button } from "@/components/ui/button"
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"
import { usePermissions } from "@/hooks/use-cluster"
import { errorMessage } from "@/lib/errors"
import { formatAgo, formatDateTime } from "@/lib/format"
import { cn } from "@/lib/utils"
import { ConflictsCard } from "./conflicts-card"
import { SettingsCard } from "./settings-card"

type Confirm = "resync" | "failback" | "promote" | null

export default function ClusterPage() {
  const qc = useQueryClient()
  // Same cache entry as the read-only banner, refreshed faster while this page
  // is open, but only when HA is on (otherwise nothing moves on its own).
  const query = useQuery({ ...clusterQuery, refetchInterval: (q) => (q.state.data?.enabled ? 2_000 : false) })
  const perms = usePermissions()
  const isAdmin = perms.allowed("admin")
  const [confirm, setConfirm] = React.useState<Confirm>(null)
  const [showConflicts, setShowConflicts] = React.useState(false)
  const location = useLocation()
  const navigate = useNavigate()

  const view = query.data
  const isPrimary = view?.role === "primary"

  // ⌘K actions land here with the navigation state { confirm: "resync" | "failback" }:
  // open the confirmation once. Only the in-app navigation state is read, never a
  // URL parameter: an outside link must not open this dialog for a signed-in admin.
  const requested = (location.state as { confirm?: unknown } | null)?.confirm
  React.useEffect(() => {
    if (!requested || !view) return
    if (isAdmin && view.enabled && (requested === "resync" || (requested === "failback" && isPrimary))) {
      setConfirm(requested)
    }
    navigate({ pathname: location.pathname, search: location.search, hash: location.hash }, { replace: true, state: null })
  }, [requested, view, isAdmin, isPrimary, navigate, location.pathname, location.search, location.hash])

  const onView = (v: ClusterView | undefined) => {
    if (v) qc.setQueryData(qk.cluster, v)
    void qc.invalidateQueries({ queryKey: qk.cluster })
  }
  const resync = useMutation({
    mutationFn: () => api.post("/cluster/resync"),
    onSuccess: (v) => {
      onView(v)
      toast.success(isPrimary ? "Resynchro demandée aux nœuds secondaires." : "Resynchro lancée : ce nœud recopie la configuration du primaire.")
    },
  })
  const failback = useMutation({
    mutationFn: () => api.post("/cluster/failback"),
    onSuccess: (v) => {
      onView(v)
      toast.success("Rebascule effectuée : l'autre nœud est maintenant primaire.")
    },
  })
  const promote = useMutation({
    mutationFn: () => api.post("/cluster/promote"),
    onSuccess: (v) => {
      onView(v)
      toast.success("Ce nœud est maintenant primaire.")
    },
  })

  if (query.isPending) return <BlockSpinner />
  if (query.isError || !view) {
    return (
      <>
        <PageHeader title="Cluster" />
        <p className="text-sm text-destructive">{errorMessage(query.error)}</p>
      </>
    )
  }

  if (!view.enabled) {
    return (
      <>
        <PageHeader title="Cluster" description="Haute disponibilité : deux nœuds Leazone et un témoin." />
        <StandaloneCard />
      </>
    )
  }

  const nodes = view.nodes ?? []
  const self = nodes.find((n) => n.self)
  const other = nodes.find((n) => !n.self)
  const gaps = view.gaps ?? []
  const pending = view.conflicts ?? 0

  return (
    <>
      <PageHeader
        title="Cluster"
        description="Haute disponibilité : état des nœuds, du témoin et de la synchro. Mise à jour toutes les 2 s."
        actions={
          isAdmin && (
            <>
              <Button variant="outline" onClick={() => setConfirm("resync")}>
                <RefreshCw /> Forcer la resynchro
              </Button>
              {isPrimary ? (
                <Button variant="outline" onClick={() => setConfirm("failback")}>
                  <ArrowLeftRight /> Rebasculer
                </Button>
              ) : (
                <Button variant="destructive" onClick={() => setConfirm("promote")}>
                  <Crown /> Promouvoir ce nœud
                </Button>
              )}
            </>
          )
        }
      />

      <SummaryCard view={view} />

      <h2 className="mt-8 mb-3 text-sm font-medium text-muted-foreground">Nœuds</h2>
      <div className="grid gap-4 md:grid-cols-2">
        {nodes.map((n) => (
          <NodeCard key={n.id || n.name} node={n} selfSeq={self?.seq} />
        ))}
        {nodes.length < 2 && (
          <Card className="justify-center border-dashed py-10 text-center text-sm text-muted-foreground">
            <CardContent>L'autre nœud n'a pas encore été vu.</CardContent>
          </Card>
        )}
      </div>

      <div className="mt-4 grid gap-4 md:grid-cols-2">
        <WitnessCard witness={view.witness} />
        {view.vip ? <VipCard vip={view.vip} /> : <GapsCard gaps={gaps} />}
      </div>
      {view.vip && (
        <div className="mt-4">
          <GapsCard gaps={gaps} />
        </div>
      )}

      {(pending > 0 || showConflicts) && (
        <div className="mt-4">
          <ConflictsCard pending={pending} isAdmin={isAdmin} onClose={pending > 0 ? undefined : () => setShowConflicts(false)} />
        </div>
      )}
      {pending === 0 && !showConflicts && isAdmin && (
        <p className="mt-3 text-xs text-muted-foreground">
          Aucun conflit en attente.{" "}
          <button type="button" className="underline underline-offset-4 hover:text-foreground" onClick={() => setShowConflicts(true)}>
            Voir les conflits déjà traités
          </button>
        </p>
      )}

      <div className="mt-4 grid items-start gap-4 lg:grid-cols-2">
        <HistoryCard history={view.history ?? []} epoch={view.epoch} />
        <SettingsCard view={view} isAdmin={isAdmin} />
      </div>

      <ConfirmDialog
        open={confirm === "resync"}
        onOpenChange={(o) => !o && setConfirm(null)}
        title="Forcer la resynchro ?"
        description={
          isPrimary
            ? "Les nœuds secondaires vont recopier toute la configuration depuis ce nœud. DNS et DHCP continuent de fonctionner pendant la copie."
            : "Ce nœud va recopier toute la configuration depuis le primaire. DNS et DHCP continuent de fonctionner pendant la copie."
        }
        confirmLabel="Forcer la resynchro"
        onConfirm={() => resync.mutateAsync()}
      />
      <ConfirmDialog
        open={confirm === "failback"}
        onOpenChange={(o) => !o && setConfirm(null)}
        title="Rebasculer vers l'autre nœud ?"
        description={
          <>
            Le rôle primaire passe à {other?.name ? <strong>{other.name}</strong> : "l'autre nœud"}. Les modifications sont
            gelées quelques secondes, le temps de tout copier. Ensuite, la configuration se modifie sur l'autre nœud.
          </>
        }
        confirmLabel="Rebasculer"
        onConfirm={() => failback.mutateAsync()}
      />
      <ConfirmDialog
        open={confirm === "promote"}
        onOpenChange={(o) => !o && setConfirm(null)}
        destructive
        title="Promouvoir ce nœud en primaire ?"
        description={
          <span className="block space-y-2">
            <span className="block">
              À faire seulement si le primaire est vraiment arrêté (panne, machine éteinte), quand le cluster ne peut pas
              basculer seul (pas de témoin, ou témoin injoignable).
            </span>
            <span className="block font-medium text-destructive">
              Si l'autre nœud tourne encore (par exemple si seul le lien entre les deux est coupé), vous aurez deux primaires :
              les modifications faites des deux côtés entreront en conflit et le DHCP pourra donner la même adresse deux fois.
            </span>
          </span>
        }
        confirmLabel="Promouvoir ce nœud"
        onConfirm={() => promote.mutateAsync()}
      />
    </>
  )
}

/* ------------------------------------------------------------------ */

function StandaloneCard() {
  const steps: React.ReactNode[] = [
    <>
      Sur le premier serveur, démarrez Leazone avec <Code>compose/ha-node1.yml</Code> (rôle d'origine : primaire).
    </>,
    <>
      Sur le second serveur, démarrez <Code>compose/ha-node2.yml</Code> avec la même clé de cluster.
    </>,
    <>
      Sur une troisième machine (même très petite), démarrez le témoin <Code>compose/witness.yml</Code>. Il évite d'avoir
      deux primaires en même temps.
    </>,
    <>
      Suivez la section <strong>« Haute disponibilité en 5 minutes »</strong> du README : clé de cluster, IP virtuelle et
      vérifications.
    </>,
  ]
  return (
    <Card>
      <CardHeader className="flex flex-row items-start gap-4">
        <div className="flex size-10 shrink-0 items-center justify-center rounded-full border bg-muted/50">
          <Server className="size-5 text-muted-foreground" />
        </div>
        <div className="space-y-1.5">
          <CardTitle>Nœud seul (haute disponibilité non configurée)</CardTitle>
          <CardDescription>
            Avec deux nœuds et un témoin, le DNS et le DHCP continuent de fonctionner si un serveur tombe. La configuration
            est copiée automatiquement d'un nœud à l'autre.
          </CardDescription>
        </div>
      </CardHeader>
      <CardContent>
        <ol className="space-y-3">
          {steps.map((s, i) => (
            <li key={i} className="flex gap-3 text-sm">
              <span className="flex size-6 shrink-0 items-center justify-center rounded-full bg-muted text-xs font-medium tabular-nums">
                {i + 1}
              </span>
              <span className="pt-0.5">{s}</span>
            </li>
          ))}
        </ol>
      </CardContent>
    </Card>
  )
}

function Code({ children }: { children: React.ReactNode }) {
  return <code className="rounded bg-muted px-1.5 py-0.5 font-mono text-xs break-all">{children}</code>
}

/* ------------------------------------------------------------------ */

function Tile({ label, children, hint }: { label: string; children: React.ReactNode; hint?: React.ReactNode }) {
  return (
    <div className="min-w-0 space-y-1">
      <div className="text-xs font-medium text-muted-foreground">{label}</div>
      <div className="text-lg font-semibold tracking-tight">{children}</div>
      {hint && <div className="text-xs text-muted-foreground">{hint}</div>}
    </div>
  )
}

function SummaryCard({ view }: { view: ClusterView }) {
  const writable = view.writable !== false
  return (
    <Card className="py-5">
      <CardContent className="grid grid-cols-2 gap-x-6 gap-y-5 px-5 lg:grid-cols-4">
        <Tile label="Rôle de ce nœud">
          <ClusterRoleBadge role={view.role} className="px-2.5 py-1 text-sm" />
        </Tile>
        <Tile label="Mandat" hint="Augmente à chaque bascule.">
          <span className="tabular-nums">mandat {view.epoch ?? 0}</span>
        </Tile>
        <Tile label="Version de config" hint="Position dans le journal des modifications.">
          <span className="tabular-nums">{view.seq ?? 0}</span>
        </Tile>
        <Tile label="Modifications de configuration">
          {writable ? (
            <span className="flex items-center gap-1.5 text-success">
              <CircleCheck className="size-4" /> autorisées
            </span>
          ) : (
            <span className="block text-sm font-medium text-warning">
              lecture seule
              {view.readOnlyReason && <span className="mt-0.5 block text-xs font-normal text-muted-foreground">{view.readOnlyReason}</span>}
            </span>
          )}
        </Tile>
      </CardContent>
    </Card>
  )
}

/* ------------------------------------------------------------------ */

function Row({ label, children, className }: { label: string; children: React.ReactNode; className?: string }) {
  return (
    <div className={cn("flex items-baseline justify-between gap-3 py-1.5 text-sm", className)}>
      <dt className="text-muted-foreground">{label}</dt>
      <dd className="min-w-0 truncate text-right tabular-nums">{children}</dd>
    </div>
  )
}

function NodeCard({ node: n, selfSeq }: { node: ClusterNode; selfSeq?: number }) {
  const behind = !n.self && n.online && selfSeq !== undefined && (n.seq ?? 0) !== selfSeq
  return (
    <Card className={cn("gap-3", n.self && "ring-1 ring-brand/30")} data-testid={`node-${n.name}`}>
      <CardHeader className="flex flex-row items-start justify-between gap-3">
        <div className="min-w-0 space-y-1">
          <CardTitle className="flex flex-wrap items-center gap-2">
            <Server className="size-4 text-muted-foreground" />
            <span className="truncate">{n.name || n.addr || "nœud"}</span>
            {n.self && <Badge variant="secondary">ce nœud</Badge>}
          </CardTitle>
          <CardDescription className="space-x-2">
            {n.addr && <span className="font-mono text-xs">{n.addr}</span>}
            {n.preferredRole && <span className="text-xs">rôle d'origine : {n.preferredRole === "primary" ? "primaire" : "secondaire"}</span>}
          </CardDescription>
        </div>
        <div className="flex shrink-0 flex-col items-end gap-1.5">
          <ClusterRoleBadge role={n.role} />
          {n.partnerDown && (
            <Badge variant="outline" className="border-warning/50 text-warning">
              sert tous les clients DHCP
            </Badge>
          )}
        </div>
      </CardHeader>
      <CardContent>
        <dl className="divide-y">
          <Row label="État">
            <StatusDot tone={n.online ? "ok" : "off"} label={n.online ? "en ligne" : "hors ligne"} className="justify-end" />
          </Row>
          {!n.self && <Row label="Latence">{n.online && n.latencyMs !== undefined ? `${n.latencyMs.toFixed(1)} ms` : "—"}</Row>}
          {!n.self && <Row label="Dernier contact">{formatAgo(n.lastSeen)}</Row>}
          <Row label="Dernière synchro">{formatAgo(n.lastSync)}</Row>
          <Row label="Mandat">{n.epoch ?? 0}</Row>
          <Row label="Version de config">
            <span className={cn(behind && "font-medium text-warning")}>
              {n.seq ?? 0}
              {behind && selfSeq !== undefined && ` (ici : ${selfSeq})`}
            </span>
          </Row>
          <Row label="Version Leazone">{n.version ? <span className="font-mono text-xs">{n.version}</span> : "—"}</Row>
        </dl>
        {n.error && (
          <p className="mt-3 flex items-start gap-1.5 text-sm text-destructive">
            <TriangleAlert className="mt-0.5 size-4 shrink-0" />
            <span className="min-w-0 break-words">{n.error}</span>
          </p>
        )}
      </CardContent>
    </Card>
  )
}

/* ------------------------------------------------------------------ */

const witnessMode: Record<string, string> = {
  container: "conteneur témoin",
  ping: "IP à pinger",
  none: "aucun",
}

function WitnessCard({ witness: w }: { witness?: ClusterWitness }) {
  const mode = w?.mode ?? "none"
  return (
    <Card className="gap-3" data-testid="witness-card">
      <CardHeader className="flex flex-row items-start justify-between gap-3">
        <div className="space-y-1">
          <CardTitle className="flex items-center gap-2">
            <Radar className="size-4 text-muted-foreground" /> Témoin
          </CardTitle>
          <CardDescription>Arbitre qui décide quel nœud est primaire.</CardDescription>
        </div>
        <Badge variant="outline" className={cn(mode === "ping" && "border-warning/50 text-warning", mode === "none" && "text-muted-foreground")}>
          {witnessMode[mode] ?? mode}
        </Badge>
      </CardHeader>
      <CardContent className="space-y-3">
        {mode !== "none" && (
          <dl className="divide-y">
            <Row label="Adresse">{w?.address ? <span className="font-mono text-xs">{w.address}</span> : "—"}</Row>
            <Row label="Joignable">
              <StatusDot tone={w?.reachable ? "ok" : "error"} label={w?.reachable ? "oui" : "non"} className="justify-end" />
            </Row>
            <Row label="Dernière réponse">{formatAgo(w?.lastOk)}</Row>
            {mode === "container" && (w?.epoch ?? 0) > 0 && (
              <Row label="Connaît">
                mandat {w?.epoch}
                {w?.primary && ` · primaire ${w.primary}`}
              </Row>
            )}
          </dl>
        )}
        {w?.error && (
          <p className="flex items-start gap-1.5 text-sm text-destructive">
            <TriangleAlert className="mt-0.5 size-4 shrink-0" />
            <span className="min-w-0 break-words">{w.error}</span>
          </p>
        )}
        {mode === "ping" && (
          <p className="rounded-md border border-warning/40 bg-warning/10 px-3 py-2 text-sm text-warning">
            Protection partielle : si seul le lien entre les deux nœuds est coupé, les deux peuvent devenir primaires. Préférez le
            conteneur témoin.
          </p>
        )}
        {mode === "none" && (
          <p className="rounded-md border border-warning/40 bg-warning/10 px-3 py-2 text-sm text-warning">
            Pas de bascule automatique : utilisez « Promouvoir ce nœud » si le primaire est perdu.
          </p>
        )}
      </CardContent>
    </Card>
  )
}

function VipCard({ vip }: { vip: NonNullable<ClusterView["vip"]> }) {
  return (
    <Card className="gap-3" data-testid="vip-card">
      <CardHeader>
        <CardTitle className="flex items-center gap-2">
          <Network className="size-4 text-muted-foreground" /> IP virtuelle
        </CardTitle>
        <CardDescription>Adresse unique qui suit le nœud primaire.</CardDescription>
      </CardHeader>
      <CardContent className="space-y-3">
        <dl className="divide-y">
          <Row label="Adresse">
            <span className="font-mono text-xs">{vip.address || "—"}</span>
          </Row>
          <Row label="Interface">
            <span className="font-mono text-xs">{vip.interface || "—"}</span>
          </Row>
          <Row label="Portée par ce nœud">
            <StatusDot tone={vip.heldHere ? "ok" : "off"} label={vip.heldHere ? "oui" : "non"} className="justify-end" />
          </Row>
        </dl>
        {vip.error && (
          <p className="flex items-start gap-1.5 text-sm text-destructive">
            <TriangleAlert className="mt-0.5 size-4 shrink-0" />
            <span className="min-w-0 break-words">{vip.error}</span>
          </p>
        )}
      </CardContent>
    </Card>
  )
}

/* ------------------------------------------------------------------ */

const gapKinds: Record<string, { icon: LucideIcon; label: string }> = {
  config: { icon: FileDiff, label: "Configuration" },
  vlan: { icon: Layers, label: "VLAN" },
  version: { icon: Tag, label: "Versions" },
  sync: { icon: RefreshCw, label: "Synchro" },
}

function GapsCard({ gaps }: { gaps: ClusterGap[] }) {
  return (
    <Card className="gap-3" data-testid="gaps-card">
      <CardHeader>
        <CardTitle>Écarts détectés</CardTitle>
        <CardDescription>Différences entre les nœuds (configuration, VLAN, versions).</CardDescription>
      </CardHeader>
      <CardContent>
        {gaps.length === 0 ? (
          <p className="flex items-center gap-2 text-sm text-success">
            <CircleCheck className="size-4" /> Aucun écart
          </p>
        ) : (
          <ul className="space-y-2.5">
            {gaps.map((g, i) => {
              const k = gapKinds[g.kind ?? ""] ?? { icon: TriangleAlert, label: g.kind ?? "" }
              return (
                <li key={i} className="flex items-start gap-2.5 text-sm">
                  <k.icon className={cn("mt-0.5 size-4 shrink-0", g.kind === "version" ? "text-destructive" : "text-warning")} aria-label={k.label} />
                  <span className="min-w-0">
                    <span className="font-medium">{k.label} : </span>
                    <span className="break-words">{g.detail}</span>
                  </span>
                </li>
              )
            })}
          </ul>
        )}
      </CardContent>
    </Card>
  )
}

/* ------------------------------------------------------------------ */

function HistoryCard({ history, epoch }: { history: ClusterTerm[]; epoch?: number }) {
  const [all, setAll] = React.useState(false)
  const shown = all ? history : history.slice(0, 8)
  return (
    <Card className="gap-3" data-testid="history-card">
      <CardHeader>
        <CardTitle>Historique des bascules</CardTitle>
        <CardDescription>Chaque mandat commence quand un nœud devient primaire. Le plus récent en haut.</CardDescription>
      </CardHeader>
      <CardContent>
        {history.length === 0 ? (
          <p className="text-sm text-muted-foreground">Aucune bascule pour l'instant.</p>
        ) : (
          <ol className="relative space-y-5 border-l pl-5">
            {shown.map((h) => {
              const current = h.epoch === epoch
              return (
                <li key={`${h.epoch}-${h.nodeId}`} className="relative">
                  <span
                    className={cn(
                      "absolute top-1 -left-[25px] size-2.5 rounded-full ring-4 ring-card",
                      current ? "bg-success" : "bg-muted-foreground/40",
                    )}
                    aria-hidden
                  />
                  <div className="flex flex-wrap items-center gap-x-2 gap-y-0.5 text-sm">
                    <span className="font-medium tabular-nums">Mandat {h.epoch}</span>
                    <span className="text-muted-foreground">·</span>
                    <span className="font-medium">{h.name || h.nodeId}</span>
                    {current && (
                      <Badge variant="outline" className="border-success/40 text-success">
                        en cours
                      </Badge>
                    )}
                  </div>
                  <div className="text-xs text-muted-foreground">
                    {formatDateTime(h.at)}
                    {h.startSeq !== undefined && ` · à partir de la version ${h.startSeq}`}
                  </div>
                  {h.reason && <p className="mt-0.5 text-sm break-words">{h.reason}</p>}
                </li>
              )
            })}
          </ol>
        )}
        {history.length > shown.length && (
          <Button variant="link" size="sm" className="mt-2 px-0" onClick={() => setAll(true)}>
            Voir les {history.length} mandats
          </Button>
        )}
      </CardContent>
    </Card>
  )
}
