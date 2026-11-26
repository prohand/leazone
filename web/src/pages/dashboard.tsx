import { Link } from "react-router"
import { useQuery } from "@tanstack/react-query"
import {
  ArrowRight,
  Circle,
  CircleCheck,
  CirclePause,
  DatabaseZap,
  Gauge,
  HeartPulse,
  ShieldBan,
  Timer,
  TriangleAlert,
  Activity,
  type LucideIcon,
} from "lucide-react"
import { dnsStatusQuery, meQuery, systemInfoQuery } from "@/api/queries"
import type { Dashboard, DashboardBlocking, DashboardHa, DashboardScope, TopCount } from "@/api/types"
import { ClusterRoleBadge } from "@/components/cluster"
import { PageHeader } from "@/components/page-header"
import { QueryChart } from "@/components/query-chart"
import { StatusDot } from "@/components/status-dot"
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert"
import { Badge } from "@/components/ui/badge"
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"
import { Skeleton } from "@/components/ui/skeleton"
import { useDashboard } from "@/hooks/use-dashboard"
import { useCurrentUser } from "@/hooks/use-session"
import { humanDuration } from "@/lib/dns"
import { fmtInt, fmtOneDecimal, formatPct } from "@/lib/logs"
import { can } from "@/lib/permissions"
import { cn } from "@/lib/utils"
import type { ClusterRole } from "@/api/types"

/* Dashboard of this node: live figures from the /events stream (polling as a fallback). */

export default function DashboardPage() {
  const dash = useDashboard()
  const d = dash.data
  const blocking = d?.blocking ?? null

  return (
    <>
      <PageHeader
        title="Tableau de bord"
        description={
          d ? (
            <span data-testid="node-note">
              Statistiques de ce nœud ({d.node || "?"}), depuis {humanDuration(d.uptimeSeconds ?? 0) || "quelques secondes"}
            </span>
          ) : (
            "État général du serveur DNS et DHCP."
          )
        }
        actions={<LiveIndicator live={dash.live} hasData={!!d} error={dash.isError && !d} />}
      />
      <ListenerAlert />
      <div className={cn("grid gap-4 sm:grid-cols-2", blocking ? "lg:grid-cols-5" : "lg:grid-cols-4")} data-testid="kpis">
        <Kpi title="Requêtes/s" icon={Gauge} value={d ? fmtOneDecimal.format(d.dns?.qps ?? 0) : undefined} hint="sur la dernière minute" />
        <Kpi
          title="Requêtes 24 h"
          icon={Activity}
          value={d ? fmtInt.format(d.dns?.queries24h ?? 0) : undefined}
          hint={d?.dns?.failed24h ? `dont ${fmtInt.format(d.dns.failed24h)} en échec` : "dernières 24 heures"}
          tone={(d?.dns?.failed24h ?? 0) > 0 ? "warning" : undefined}
        />
        <Kpi title="Taux de cache" icon={DatabaseZap} value={d ? formatPct(d.dns?.cacheHitRate) : undefined} hint="réponses depuis le cache (1 h)" />
        {blocking && (
          <Kpi title="Bloquées 24 h" icon={ShieldBan} value={fmtInt.format(d?.dns?.blocked24h ?? 0)} hint="publicités et traqueurs" to="/blocking" />
        )}
        <Kpi
          title="Baux actifs"
          icon={Timer}
          value={d ? fmtInt.format(d.dhcp?.activeLeases ?? 0) : undefined}
          hint={d ? scopesHint(d) : ""}
          to="/dhcp/leases"
        />
      </div>

      <Card className="mt-6 gap-4" data-testid="queries-chart">
        <CardHeader>
          <CardTitle>Requêtes DNS (dernière heure)</CardTitle>
          <CardDescription>Une valeur par minute.</CardDescription>
        </CardHeader>
        <CardContent>
          {d ? (
            <div className={cn("transition-opacity", dash.isFetching && !dash.live && "opacity-90")}>
              <QueryChart points={d.dns?.series ?? []} showBlocked={!!blocking} />
            </div>
          ) : (
            <Skeleton className="h-[240px] w-full" />
          )}
        </CardContent>
      </Card>

      <div className={cn("mt-6 grid gap-4", blocking ? "lg:grid-cols-3" : "lg:grid-cols-2")}>
        <TopCard
          testId="top-domains"
          title="Top domaines"
          items={d?.dns?.topDomains}
          mono
          linkOf={(t) => `/logs?tab=dns&q=${encodeURIComponent(t.name ?? "")}`}
          linkLabel={(t) => `Voir les requêtes pour ${t.name}`}
          loading={!d}
        />
        <TopCard
          testId="top-clients"
          title="Top clients"
          items={d?.dns?.topClients}
          mono
          linkOf={(t) => `/logs?tab=dns&client=${encodeURIComponent(t.name ?? "")}`}
          linkLabel={(t) => `Voir les requêtes de ${t.name}`}
          loading={!d}
        />
        {blocking && (
          <TopCard
            testId="top-blocked"
            title="Top bloqués"
            items={d?.dns?.topBlocked}
            mono
            barClass="bg-series-2"
            linkOf={(t) => `/logs?tab=dns&source=blocked&q=${encodeURIComponent(t.name ?? "")}`}
            linkLabel={(t) => `Voir les requêtes bloquées pour ${t.name}`}
            loading={!d}
          />
        )}
      </div>

      <div className="mt-6 grid gap-4 lg:grid-cols-[minmax(0,2fr)_minmax(0,1fr)]">
        <ScopesCard scopes={d?.dhcp?.scopes} loading={!d} />
        <div className="grid content-start gap-4">
          {d?.ha && <HaCard ha={d.ha} />}
          {blocking && <BlockingCard b={blocking} />}
        </div>
      </div>

      <GettingStarted dashboard={d} />
    </>
  )
}

function scopesHint(d: Dashboard): string {
  const n = d.dhcp?.scopes?.length ?? 0
  if (n === 0) return "aucune étendue DHCP"
  const full = (d.dhcp?.scopes ?? []).filter((s) => (s.percent ?? 0) > 90).length
  if (full > 0) return `${full} étendue${full > 1 ? "s" : ""} presque pleine${full > 1 ? "s" : ""}`
  return `dans ${n} étendue${n > 1 ? "s" : ""}`
}

function LiveIndicator({ live, hasData, error }: { live: boolean; hasData: boolean; error: boolean }) {
  return (
    <span className="inline-flex items-center gap-2 text-xs text-muted-foreground" data-testid="live-indicator" data-live={live}>
      <span className="relative flex size-2">
        {live && <span className="absolute inline-flex size-full animate-ping rounded-full bg-success opacity-60 motion-reduce:hidden" />}
        <span className={cn("relative inline-flex size-2 rounded-full", live ? "bg-success" : error ? "bg-destructive" : "bg-muted-foreground/40")} />
      </span>
      {live ? "en direct" : error ? "indisponible" : hasData ? "mise à jour toutes les 5 s" : "connexion…"}
    </span>
  )
}

function Kpi({
  title,
  icon: Icon,
  value,
  hint,
  to,
  tone,
}: {
  title: string
  icon: LucideIcon
  value?: string
  hint: string
  to?: string
  tone?: "warning"
}) {
  const card = (
    <Card className={cn("h-full gap-2 py-5", to && "transition-colors hover:bg-muted/40")}>
      <CardHeader className="flex flex-row items-center justify-between px-5">
        <CardDescription className="text-sm font-medium">{title}</CardDescription>
        <Icon className="size-4 text-muted-foreground" />
      </CardHeader>
      <CardContent className="px-5">
        {value === undefined ? (
          <Skeleton className="h-9 w-20" />
        ) : (
          <div className="text-3xl font-semibold tracking-tight" data-testid={`kpi-${title}`}>
            {value}
          </div>
        )}
        <p className={cn("mt-1 text-xs", tone === "warning" ? "text-warning" : "text-muted-foreground")}>{hint || " "}</p>
      </CardContent>
    </Card>
  )
  return to ? (
    <Link to={to} className="rounded-xl focus-visible:ring-[3px] focus-visible:ring-ring/50 focus-visible:outline-none">
      {card}
    </Link>
  ) : (
    card
  )
}

/** Ranked list with an inline bar proportional to the count (the first one is the longest). */
function TopCard({
  title,
  items,
  linkOf,
  linkLabel,
  mono,
  barClass = "bg-series-1",
  loading,
  testId,
}: {
  title: string
  items?: TopCount[]
  linkOf: (t: TopCount) => string
  linkLabel: (t: TopCount) => string
  mono?: boolean
  barClass?: string
  loading?: boolean
  testId: string
}) {
  const list = (items ?? []).slice(0, 10)
  const max = Math.max(1, ...list.map((t) => t.count ?? 0))
  return (
    <Card className="min-w-0 gap-3" data-testid={testId}>
      <CardHeader>
        <CardTitle className="text-base">{title}</CardTitle>
      </CardHeader>
      <CardContent>
        {loading ? (
          <div className="space-y-2">
            {Array.from({ length: 5 }).map((_, i) => (
              <Skeleton key={i} className="h-5 w-full" />
            ))}
          </div>
        ) : list.length === 0 ? (
          <p className="text-sm text-muted-foreground">Rien pour l'instant.</p>
        ) : (
          <ol className="-mx-2 space-y-0.5">
            {list.map((t, i) => (
              <li key={t.name ?? i}>
                <Link
                  to={linkOf(t)}
                  aria-label={linkLabel(t)}
                  className="group flex items-center gap-2 rounded-md px-2 py-1 text-sm transition-colors hover:bg-muted/60 focus-visible:ring-[3px] focus-visible:ring-ring/50 focus-visible:outline-none"
                >
                  <span className="w-4 shrink-0 text-right text-xs text-muted-foreground tabular-nums">{i + 1}</span>
                  <span className="min-w-0 flex-1">
                    <span className={cn("block truncate", mono && "font-mono text-xs")} title={t.name}>
                      {t.name}
                    </span>
                    <span className="mt-0.5 block h-1 w-full rounded-full bg-muted" aria-hidden>
                      <span className={cn("block h-1 rounded-full", barClass)} style={{ width: `${((t.count ?? 0) / max) * 100}%` }} />
                    </span>
                  </span>
                  <span className="shrink-0 text-xs text-muted-foreground tabular-nums">{fmtInt.format(t.count ?? 0)}</span>
                </Link>
              </li>
            ))}
          </ol>
        )}
      </CardContent>
    </Card>
  )
}

const fillClass = (p: number) => (p > 90 ? "bg-destructive" : p >= 70 ? "bg-warning" : "bg-success")

function ScopesCard({ scopes, loading }: { scopes?: DashboardScope[]; loading: boolean }) {
  const list = [...(scopes ?? [])].sort((a, b) => (b.percent ?? 0) - (a.percent ?? 0))
  return (
    <Card className="min-w-0 gap-4" data-testid="scopes-card">
      <CardHeader className="flex flex-row items-start justify-between gap-2">
        <div className="space-y-1.5">
          <CardTitle>Étendues DHCP</CardTitle>
          <CardDescription>Remplissage : vert sous 70 %, orange jusqu'à 90 %, rouge au-delà.</CardDescription>
        </div>
        <Link to="/dhcp/scopes" className="inline-flex shrink-0 items-center gap-1 text-sm text-muted-foreground hover:text-foreground">
          Étendues <ArrowRight className="size-4" />
        </Link>
      </CardHeader>
      <CardContent>
        {loading ? (
          <Skeleton className="h-16 w-full" />
        ) : list.length === 0 ? (
          <p className="text-sm text-muted-foreground">Aucune étendue DHCP pour l'instant.</p>
        ) : (
          <ul className="-mx-2 space-y-1">
            {list.map((s) => {
              const p = Math.max(0, Math.min(100, s.percent ?? 0))
              return (
                <li key={s.id}>
                  <Link
                    to={`/dhcp/leases?scope=${encodeURIComponent(s.id ?? "")}`}
                    className="block space-y-1.5 rounded-md px-2 py-1.5 transition-colors hover:bg-muted/50 focus-visible:ring-[3px] focus-visible:ring-ring/50 focus-visible:outline-none"
                    data-testid={`scope-${s.id}`}
                  >
                    <div className="flex items-center gap-2 text-sm">
                      {p > 90 && <TriangleAlert className="size-3.5 shrink-0 text-destructive" aria-label="Presque pleine" />}
                      <span className="min-w-0 truncate font-medium">{s.name}</span>
                      {s.vlanId != null && (
                        <Badge variant="outline" className="shrink-0">
                          VLAN {s.vlanId}
                        </Badge>
                      )}
                      <span className="hidden min-w-0 truncate font-mono text-xs text-muted-foreground sm:inline">{s.network}</span>
                      <span className="ml-auto shrink-0 text-xs text-muted-foreground tabular-nums">
                        {fmtInt.format(s.used ?? 0)} / {fmtInt.format(s.size ?? 0)}
                      </span>
                      <span className={cn("w-11 shrink-0 text-right text-sm tabular-nums", p > 90 ? "font-medium text-destructive" : "text-muted-foreground")}>
                        {formatPct(s.percent)}
                      </span>
                    </div>
                    <div
                      role="progressbar"
                      aria-valuemin={0}
                      aria-valuemax={100}
                      aria-valuenow={Math.round(p)}
                      aria-label={`Remplissage de ${s.name}`}
                      className="h-2 w-full overflow-hidden rounded-full bg-muted"
                    >
                      <div className={cn("h-full rounded-full transition-[width]", fillClass(p))} style={{ width: `${p}%` }} />
                    </div>
                  </Link>
                </li>
              )
            })}
          </ul>
        )}
      </CardContent>
    </Card>
  )
}

function HaCard({ ha }: { ha: DashboardHa }) {
  const gaps = ha.gaps ?? 0
  return (
    <Link to="/cluster" data-testid="ha-card" className="block rounded-xl focus-visible:ring-[3px] focus-visible:ring-ring/50 focus-visible:outline-none">
      <Card className="gap-3 transition-colors hover:bg-muted/40">
        <CardHeader className="flex flex-row items-center justify-between gap-2">
          <CardTitle className="flex items-center gap-2 text-base">
            <HeartPulse className="size-4 text-muted-foreground" /> Haute disponibilité
          </CardTitle>
          <ClusterRoleBadge role={(ha.role as ClusterRole) || undefined} />
        </CardHeader>
        <CardContent>
          <ul className="space-y-1 text-sm">
            <li>
              <StatusDot tone={ha.peerOnline ? "ok" : "error"} label={ha.peerOnline ? "Autre nœud en ligne" : "Autre nœud hors ligne"} />
            </li>
            <li>
              <StatusDot tone={ha.witnessReachable ? "ok" : "error"} label={ha.witnessReachable ? "Témoin joignable" : "Témoin injoignable"} />
            </li>
            <li className={cn(gaps > 0 && "text-warning")}>
              <StatusDot tone={gaps > 0 ? "warning" : "ok"} label={gaps === 0 ? "Aucun écart" : `${gaps} écart${gaps > 1 ? "s" : ""}`} />
            </li>
          </ul>
        </CardContent>
      </Card>
    </Link>
  )
}

function BlockingCard({ b }: { b: DashboardBlocking }) {
  return (
    <Link to="/blocking" data-testid="blocking-card" className="block rounded-xl focus-visible:ring-[3px] focus-visible:ring-ring/50 focus-visible:outline-none">
      <Card className="gap-3 transition-colors hover:bg-muted/40">
        <CardHeader className="flex flex-row items-center justify-between gap-2">
          <CardTitle className="flex items-center gap-2 text-base">
            <ShieldBan className="size-4 text-muted-foreground" /> Blocage
          </CardTitle>
          {b.paused ? (
            <Badge variant="outline" className="border-warning/50 text-warning">
              <CirclePause /> en pause
            </Badge>
          ) : (
            <Badge variant="outline" className="border-success/40 text-success">
              <ShieldBan /> actif
            </Badge>
          )}
        </CardHeader>
        <CardContent>
          <div className="text-3xl font-semibold tracking-tight">{formatPct(b.percent)}</div>
          <p className="mt-1 text-xs text-muted-foreground">
            {fmtInt.format(b.blocked ?? 0)} bloquées sur {fmtInt.format(b.queries ?? 0)} requêtes
          </p>
        </CardContent>
      </Card>
    </Link>
  )
}

/** Red line when some DNS listening addresses failed (port already used...). */
function ListenerAlert() {
  const dns = useQuery(dnsStatusQuery)
  const failed = (dns.data?.listeners ?? []).filter((l) => l.state !== "listening")
  if (failed.length === 0) return null
  return (
    <Alert variant="destructive" className="mb-4" data-testid="listener-alert">
      <TriangleAlert />
      <AlertTitle>
        {failed.length} écoute{failed.length > 1 ? "s" : ""} DNS en erreur
      </AlertTitle>
      <AlertDescription>
        <p>
          {failed[0].error || `${failed[0].address} (${failed[0].protocol})`}{" "}
          <Link to="/interfaces" className="underline underline-offset-4">
            Voir les interfaces
          </Link>
        </p>
      </AlertDescription>
    </Alert>
  )
}

type Step = { label: string; done: boolean; to?: string; note?: string }

/** First steps checklist; hidden once everything is done. */
function GettingStarted({ dashboard }: { dashboard?: Dashboard }) {
  const user = useCurrentUser()
  const me = useQuery(meQuery)
  const info = useQuery(systemInfoQuery)
  const dns = useQuery(dnsStatusQuery)
  const isAdmin = can(user?.role, "admin")
  if (!me.data || !info.data || !dns.data || !dashboard) return null

  const listening = (dns.data.listeners ?? []).some((l) => l.state === "listening")
  const forwarders = (dns.data.forwarders?.length ?? 0) > 0
  const scopes = (dashboard.dhcp?.scopes?.length ?? 0) > 0
  const adminStep = (label: string, done: boolean, to: string): Step => ({
    label,
    done,
    to: isAdmin ? to : undefined,
    note: !isAdmin && !done ? "Administrateur" : undefined,
  })
  const steps: Step[] = [
    { label: "Configurer le MFA", done: !!me.data.totpEnabled || (me.data.passkeyCount ?? 0) > 0, to: "/account?tab=passkeys" },
    adminStep("Importer un certificat", !info.data.selfSignedCertificate, "/settings?tab=https"),
    adminStep("Activer le DNS sur une interface", listening, "/interfaces"),
    adminStep("Ajouter un redirecteur (ex. : Quad9)", forwarders, "/dns/forwarders?new=1"),
    adminStep("Créer une étendue DHCP", scopes, "/dhcp/scopes?new=1"),
  ]
  if (steps.every((s) => s.done)) return null

  return (
    <Card className="mt-6">
      <CardHeader>
        <CardTitle>Bien démarrer{user?.username ? `, ${user.username}` : ""}</CardTitle>
        <CardDescription>Quelques étapes pour finir l'installation de Leazone.</CardDescription>
      </CardHeader>
      <CardContent>
        <ul className="divide-y rounded-lg border">
          {steps.map((s) => {
            const Icon = s.done ? CircleCheck : Circle
            const body = (
              <>
                <Icon className={cn("size-5 shrink-0", s.done ? "text-success" : "text-muted-foreground")} />
                <span className={cn("flex-1 text-sm", s.done && "text-muted-foreground line-through")}>{s.label}</span>
                {s.note && <Badge variant="secondary">{s.note}</Badge>}
                {s.to && !s.done && <ArrowRight className="size-4 text-muted-foreground" />}
              </>
            )
            return (
              <li key={s.label}>
                {s.to && !s.done ? (
                  <Link to={s.to} className="flex items-center gap-3 px-4 py-3 transition-colors hover:bg-muted/50">
                    {body}
                  </Link>
                ) : (
                  <div className="flex items-center gap-3 px-4 py-3">{body}</div>
                )}
              </li>
            )
          })}
        </ul>
      </CardContent>
    </Card>
  )
}
