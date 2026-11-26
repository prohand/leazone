import { Link } from "react-router"
import { useQuery } from "@tanstack/react-query"
import { ArrowRight, CircleCheck, Circle, DatabaseZap, HeartPulse, Radio, Timer, type LucideIcon } from "lucide-react"
import { dnsStatusQuery, meQuery, systemInfoQuery } from "@/api/queries"
import { PageHeader } from "@/components/page-header"
import { Badge } from "@/components/ui/badge"
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"
import { useCurrentUser } from "@/hooks/use-session"
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
  const isAdmin = can(user?.role, "admin")

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
        <StatCard title="Baux actifs" icon={Timer} hint="Disponible avec le module DHCP" />
        <StatCard title="État HA" icon={HeartPulse} hint="Disponible avec le cluster" />
      </div>
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
