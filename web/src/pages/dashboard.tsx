import { Link } from "react-router"
import { useQuery } from "@tanstack/react-query"
import { ArrowRight, CircleCheck, Circle, DatabaseZap, HeartPulse, Radio, Timer, TriangleAlert, type LucideIcon } from "lucide-react"
import { dnsStatusQuery, meQuery, systemInfoQuery, vlansQuery } from "@/api/queries"
import type { ScopeUsage } from "@/api/types"
import { clusterRoleLabel } from "@/components/cluster"
import { UsageBar } from "@/components/dhcp"
import { StatusDot } from "@/components/status-dot"
import { PageHeader } from "@/components/page-header"
import { Badge } from "@/components/ui/badge"
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"
import { useClusterView } from "@/hooks/use-cluster"
import { useCurrentUser } from "@/hooks/use-session"
import { fmtInt, formatPercent } from "@/lib/dhcp"
import { hitRate, percent } from "@/lib/dns"
import { can } from "@/lib/permissions"
import { cn } from "@/lib/utils"

function StatCard({
  title,
  icon: Icon,
  hint,
  value = "—",
  to,
  tone,
}: {
  title: string
  icon: LucideIcon
  hint: string
  value?: string
  to?: string
  tone?: "error"
}) {
  const card = (
    <Card className={cn("h-full gap-2 py-5", to && "transition-colors hover:bg-muted/40")}>
      <CardHeader className="flex flex-row items-center justify-between px-5">
        <CardDescription className="text-sm font-medium">{title}</CardDescription>
        <Icon className="size-4 text-muted-foreground" />
      </CardHeader>
      <CardContent className="px-5">
        <div className="text-3xl font-semibold tracking-tight tabular-nums">{value}</div>
        <p className={cn("mt-1 text-xs", tone === "error" ? "text-destructive" : "text-muted-foreground")}>{hint}</p>
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

type Step = { label: string; done: boolean; to?: string; note?: string }

function Checklist({ steps }: { steps: Step[] }) {
  return (
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
  )
}

export default function DashboardPage() {
  const user = useCurrentUser()
  const me = useQuery(meQuery)
  const info = useQuery(systemInfoQuery)
  const dns = useQuery(dnsStatusQuery)
  const vlans = useQuery(vlansQuery)
  const isAdmin = can(user?.role, "admin")

  // All scopes with their VLAN label, fullest first.
  const scopes: (ScopeUsage & { vlan: string })[] = [
    ...(vlans.data?.items ?? []).flatMap((v) => (v.scopes ?? []).map((s) => ({ ...s, vlan: `VLAN ${v.vlanId}` }))),
    ...(vlans.data?.untaggedScopes ?? []).map((s) => ({ ...s, vlan: "Sans VLAN" })),
  ].sort((a, b) => (b.percent ?? 0) - (a.percent ?? 0))
  const activeLeases = scopes.reduce((n, s) => n + (s.activeLeases ?? 0), 0)
  const alerts = scopes.filter((s) => s.alert).length

  const listeners = dns.data?.listeners ?? []
  const listening = listeners.filter((l) => l.state === "listening")
  const failed = listeners.length - listening.length
  const addresses = new Set(listening.map((l) => l.address)).size
  const rate = hitRate(dns.data?.cache?.hits, dns.data?.cache?.misses)
  const forwarderCount = dns.data?.forwarders?.length ?? 0

  const mfaDone = !!me.data && (me.data.totpEnabled || (me.data.passkeyCount ?? 0) > 0)
  const certDone = info.data ? !info.data.selfSignedCertificate : false

  const steps: Step[] = [
    { label: "Configurer le MFA", done: mfaDone, to: "/account?tab=passkeys" },
    {
      label: "Importer un certificat",
      done: certDone,
      to: isAdmin ? "/settings?tab=https" : undefined,
      note: !isAdmin && !certDone ? "Administrateur" : undefined,
    },
    {
      label: "Activer le DNS sur une interface",
      done: listening.length > 0,
      to: isAdmin ? "/interfaces" : undefined,
      note: !isAdmin && listening.length === 0 ? "Administrateur" : undefined,
    },
    {
      label: "Ajouter un redirecteur (ex. : Quad9)",
      done: forwarderCount > 0,
      to: isAdmin ? "/dns/forwarders?new=1" : undefined,
      note: !isAdmin && forwarderCount === 0 ? "Administrateur" : undefined,
    },
    {
      label: "Créer une étendue DHCP",
      done: scopes.length > 0,
      to: isAdmin ? "/dhcp/scopes?new=1" : undefined,
      note: !isAdmin && scopes.length === 0 ? "Administrateur" : undefined,
    },
  ]

  return (
    <>
      <PageHeader title="Tableau de bord" description="État général du serveur DNS et DHCP." />
      <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-4">
        <StatCard
          title="Écoute DNS"
          icon={Radio}
          to="/interfaces"
          value={dns.data ? String(addresses) : "—"}
          tone={failed > 0 ? "error" : undefined}
          hint={
            !dns.data
              ? dns.isError ? "Indisponible" : "Chargement…"
              : failed > 0
                ? `${failed} écoute(s) en erreur`
                : addresses === 0
                  ? "Aucune adresse : activez une interface"
                  : `${addresses > 1 ? "adresses" : "adresse"} · port ${dns.data.port ?? 53}`
          }
        />
        <StatCard
          title="Taux de cache"
          icon={DatabaseZap}
          value={rate === null ? "—" : percent(rate)}
          hint={dns.data ? `${new Intl.NumberFormat("fr-FR").format(dns.data.cache?.entries ?? 0)} entrées en cache` : dns.isError ? "Indisponible" : "Chargement…"}
        />
        <StatCard
          title="Baux actifs"
          icon={Timer}
          to="/dhcp/leases"
          value={vlans.data ? fmtInt.format(activeLeases) : "—"}
          tone={alerts > 0 ? "error" : undefined}
          hint={
            !vlans.data
              ? vlans.isError ? "Indisponible" : "Chargement…"
              : scopes.length === 0
                ? "Aucune étendue DHCP"
                : alerts > 0
                  ? `${alerts} étendue(s) presque pleine(s)`
                  : `dans ${scopes.length} étendue${scopes.length > 1 ? "s" : ""}`
          }
        />
        <HaCard />
      </div>
      {scopes.length > 0 && <ScopeFillCard scopes={scopes} />}
      <Card className="mt-6">
        <CardHeader>
          <CardTitle>Bienvenue{user?.username ? `, ${user.username}` : ""}</CardTitle>
          <CardDescription>Quelques étapes pour bien démarrer avec Leazone.</CardDescription>
        </CardHeader>
        <CardContent>
          <Checklist steps={steps} />
        </CardContent>
      </Card>
    </>
  )
}

/** Compact list of the fullest scopes (from /vlans). */
function ScopeFillCard({ scopes }: { scopes: (ScopeUsage & { vlan: string })[] }) {
  const top = scopes.slice(0, 6)
  return (
    <Card className="mt-6 gap-4">
      <CardHeader className="flex flex-row items-start justify-between gap-2">
        <div className="space-y-1.5">
          <CardTitle>Remplissage des étendues</CardTitle>
          <CardDescription>Les plus remplies d'abord. En rouge au-dessus du seuil d'alerte.</CardDescription>
        </div>
        <Link to="/vlans" className="inline-flex shrink-0 items-center gap-1 text-sm text-muted-foreground hover:text-foreground">
          Vue VLAN <ArrowRight className="size-4" />
        </Link>
      </CardHeader>
      <CardContent>
        <ul className="grid gap-x-8 gap-y-3 md:grid-cols-2">
          {top.map((s) => (
            <li key={s.id}>
              <Link
                to={`/dhcp/leases?scope=${encodeURIComponent(s.id ?? "")}`}
                className="block space-y-1.5 rounded-md p-1 -m-1 transition-colors hover:bg-muted/50"
              >
                <div className="flex items-center gap-2 text-sm">
                  {s.alert && <TriangleAlert className="size-3.5 shrink-0 text-destructive" aria-label="Alerte" />}
                  <span className="min-w-0 flex-1 truncate font-medium">{s.name}</span>
                  <span className="hidden text-xs text-muted-foreground sm:inline">{s.vlan}</span>
                  <span className={cn("w-12 text-right text-sm tabular-nums", s.alert ? "font-medium text-destructive" : "text-muted-foreground")}>
                    {formatPercent(s.percent)}
                  </span>
                </div>
                <UsageBar percent={s.percent} alert={s.alert} label={`Remplissage de ${s.name}`} />
              </Link>
            </li>
          ))}
        </ul>
        {scopes.length > top.length && (
          <p className="mt-3 text-xs text-muted-foreground">et {scopes.length - top.length} autre(s) étendue(s)</p>
        )}
      </CardContent>
    </Card>
  )
}

/** Compact high availability state (from the shared /cluster query). */
function HaCard() {
  const { data: v, isError } = useClusterView()
  const other = v?.nodes?.find((n) => !n.self)
  const gaps = v?.gaps?.length ?? 0
  const conflicts = v?.conflicts ?? 0
  const mode = v?.witness?.mode ?? "none"
  const roleTone =
    v?.role === "primary" ? "text-success" : v?.role === "secondary" ? "text-brand" : v?.role === "isolated" || v?.role === "incompatible" ? "text-warning" : ""
  const label = v ? (v.enabled ? clusterRoleLabel[v.role ?? "joining"] : "nœud seul") : "—"
  return (
    <Link
      to="/cluster"
      data-testid="ha-card"
      className="rounded-xl focus-visible:ring-[3px] focus-visible:ring-ring/50 focus-visible:outline-none"
    >
      <Card className="h-full gap-2 py-5 transition-colors hover:bg-muted/40">
        <CardHeader className="flex flex-row items-center justify-between px-5">
          <CardDescription className="text-sm font-medium">Haute disponibilité</CardDescription>
          <HeartPulse className="size-4 text-muted-foreground" />
        </CardHeader>
        <CardContent className="px-5">
          <div className={cn("text-3xl font-semibold tracking-tight first-letter:uppercase", roleTone)}>{label}</div>
          {!v ? (
            <p className="mt-1 text-xs text-muted-foreground">{isError ? "Indisponible" : "Chargement…"}</p>
          ) : !v.enabled ? (
            <p className="mt-1 text-xs text-muted-foreground">Non configurée : un seul serveur</p>
          ) : (
            <ul className="mt-1.5 space-y-0.5 text-xs text-muted-foreground">
              <li>
                <StatusDot
                  tone={other?.online ? "ok" : "error"}
                  label={other ? `${other.name} ${other.online ? "en ligne" : "hors ligne"}` : "Autre nœud jamais vu"}
                />
              </li>
              <li>
                <StatusDot
                  tone={mode === "none" ? "warning" : v.witness?.reachable ? "ok" : "error"}
                  label={mode === "none" ? "Sans témoin" : v.witness?.reachable ? "Témoin joignable" : "Témoin injoignable"}
                />
              </li>
              <li className={cn((gaps > 0 || conflicts > 0) && "text-warning")}>
                <StatusDot
                  tone={gaps > 0 || conflicts > 0 ? "warning" : "ok"}
                  label={
                    gaps === 0 && conflicts === 0
                      ? "Aucun écart"
                      : [gaps > 0 && `${gaps} écart${gaps > 1 ? "s" : ""}`, conflicts > 0 && `${conflicts} conflit${conflicts > 1 ? "s" : ""}`]
                          .filter(Boolean)
                          .join(" · ")
                  }
                />
              </li>
            </ul>
          )}
        </CardContent>
      </Card>
    </Link>
  )
}
