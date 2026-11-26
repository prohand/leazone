import * as React from "react"
import { useNavigate, useSearchParams } from "react-router"
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query"
import type { ColumnDef } from "@tanstack/react-table"
import { BookmarkPlus, MoreHorizontal, Unplug } from "lucide-react"
import { toast } from "sonner"
import { api } from "@/api/client"
import { leasesQuery, qk, scopesQuery, type LeaseFilters } from "@/api/queries"
import type { Lease, LeaseState } from "@/api/types"
import { ConfirmDialog } from "@/components/confirm-dialog"
import { DataTable, SortHeader } from "@/components/data-table"
import { LeaseStateBadge } from "@/components/dhcp"
import { PageHeader } from "@/components/page-header"
import { Badge } from "@/components/ui/badge"
import { Button } from "@/components/ui/button"
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuLabel,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu"
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select"
import { Switch } from "@/components/ui/switch"
import { Tooltip, TooltipContent, TooltipTrigger } from "@/components/ui/tooltip"
import { useCurrentUser } from "@/hooks/use-session"
import { ipToInt, leaseStateLabel, leaseStates, vlanLabel } from "@/lib/dhcp"
import { errorMessage } from "@/lib/errors"
import { formatDateTime, formatRelativeShort } from "@/lib/format"
import { can } from "@/lib/permissions"
import { cn } from "@/lib/utils"

const leaseKey = (l: Lease) => `${l.scopeId}/${l.ip}`
const isLive = (l: Lease) => l.state === "bound" || l.state === "offered"

function Option82({ l }: { l: Lease }) {
  if (!l.circuitId && !l.remoteId) return null
  const text = [l.circuitId && `circuit ${l.circuitId}`, l.remoteId && `remote ${l.remoteId}`].filter(Boolean).join(" · ")
  return (
    <Tooltip>
      <TooltipTrigger asChild>
        <span tabIndex={0} className="block max-w-48 cursor-help truncate font-mono text-xs text-muted-foreground">
          {text}
        </span>
      </TooltipTrigger>
      <TooltipContent className="max-w-xs">
        <p className="font-medium">Option 82 (infos du relais)</p>
        {l.circuitId && <p className="font-mono">circuit-id : {l.circuitId}</p>}
        {l.remoteId && <p className="font-mono">remote-id : {l.remoteId}</p>}
      </TooltipContent>
    </Tooltip>
  )
}

export default function LeasesPage() {
  const qc = useQueryClient()
  const navigate = useNavigate()
  const user = useCurrentUser()
  const canWrite = can(user?.role, "leases.write")
  const [params, setParams] = useSearchParams()
  // ⌘K "Rechercher un bail" lands here with ?search=1: focus the search box once.
  const [focusSearch] = React.useState(() => params.get("search") === "1")
  React.useEffect(() => {
    if (params.has("search")) setParam("search", undefined)
  }, [])

  const scope = params.get("scope") ?? ""
  const vlanParam = Number(params.get("vlan"))
  const vlan = Number.isInteger(vlanParam) && vlanParam > 0 ? vlanParam : undefined
  const stateParam = params.get("state") as LeaseState | null
  const state = stateParam && leaseStates.includes(stateParam) ? stateParam : undefined
  const showOld = params.get("all") === "1"
  const q = params.get("q") ?? ""

  const setParam = (key: string, value: string | undefined) =>
    setParams(
      (p) => {
        const n = new URLSearchParams(p)
        n.delete("search")
        if (value) n.set(key, value)
        else n.delete(key)
        return n
      },
      { replace: true },
    )

  // Released and expired leases are only returned with all=true.
  const filters: LeaseFilters = {
    scope: scope || undefined,
    vlan,
    state,
    all: showOld || state === "released" || state === "expired",
  }
  const list = useQuery(leasesQuery(filters))
  const scopes = useQuery(scopesQuery)

  const [releasing, setReleasing] = React.useState<Lease | null>(null)

  const refresh = () => {
    void qc.invalidateQueries({ queryKey: qk.dhcp })
    void qc.invalidateQueries({ queryKey: qk.vlans })
  }
  const release = useMutation({
    mutationFn: (l: Lease) => api.delete("/dhcp/leases/{scope}/{ip}", { params: { scope: l.scopeId ?? "", ip: l.ip ?? "" } }),
    onSuccess: (_, l) => {
      toast.success(`Bail ${l.ip} libéré.`, { description: "Le client redemandera une adresse à son prochain renouvellement." })
      refresh()
    },
  })
  const reserve = useMutation({
    mutationFn: (l: Lease) =>
      api.post("/dhcp/leases/{scope}/{ip}/reserve", { params: { scope: l.scopeId ?? "", ip: l.ip ?? "" } }),
    onSuccess: (r, l) => {
      toast.success(`${l.ip} est maintenant réservée`, {
        description: `Pour ${r.mac || r.clientId || l.mac}${r.hostname ? ` (${r.hostname})` : ""}.`,
        action: {
          label: "Voir",
          onClick: () => navigate(`/dhcp/reservations?scope=${encodeURIComponent(l.scopeId ?? "")}`),
        },
      })
      refresh()
    },
  })
  const reserveMutate = reserve.mutate

  const scopeItems = scopes.data?.items ?? []
  const vlanOptions = React.useMemo(() => {
    const m = new Map<number, string>()
    for (const s of scopeItems) if (s.vlanId != null) m.set(s.vlanId, s.vlanName ?? "")
    return [...m.entries()].sort((a, b) => a[0] - b[0])
  }, [scopeItems])

  const columns = React.useMemo<ColumnDef<Lease, unknown>[]>(
    () => [
      {
        accessorKey: "ip",
        header: ({ column }) => <SortHeader column={column} title="IP" />,
        sortingFn: (a, b) => (ipToInt(a.original.ip ?? "") ?? 0) - (ipToInt(b.original.ip ?? "") ?? 0),
        cell: ({ row }) => (
          <div className="flex items-center gap-1.5">
            <span className="font-mono text-sm">{row.original.ip}</span>
            {row.original.reserved && (
              <Badge variant="outline" className="border-brand/40 text-brand">
                réservé
              </Badge>
            )}
          </div>
        ),
      },
      {
        id: "mac",
        accessorFn: (l) => `${l.mac ?? ""} ${l.clientId ?? ""}`,
        header: "MAC",
        enableSorting: false,
        cell: ({ row }) => (
          <div>
            <span className="font-mono text-xs">{row.original.mac || "—"}</span>
            {row.original.clientId && (
              <span className="block max-w-40 truncate font-mono text-xs text-muted-foreground" title={`Identifiant client : ${row.original.clientId}`}>
                id {row.original.clientId}
              </span>
            )}
          </div>
        ),
      },
      {
        id: "hostname",
        accessorFn: (l) => l.hostname ?? "",
        header: ({ column }) => <SortHeader column={column} title="Nom d'hôte" />,
        cell: ({ row }) => (row.original.hostname ? <span>{row.original.hostname}</span> : <span className="text-muted-foreground">—</span>),
      },
      {
        id: "state",
        accessorFn: (l) => leaseStateLabel[l.state ?? "bound"],
        header: ({ column }) => <SortHeader column={column} title="État" />,
        cell: ({ row }) => <LeaseStateBadge state={row.original.state} />,
      },
      {
        id: "scope",
        accessorFn: (l) => `${l.scopeName ?? ""} ${l.vlanId ?? ""}`,
        header: ({ column }) => <SortHeader column={column} title="Étendue" />,
        cell: ({ row }) => (
          <div className="text-sm">
            <span>{row.original.scopeName || "—"}</span>
            <span className="block text-xs text-muted-foreground">{vlanLabel(row.original.vlanId)}</span>
          </div>
        ),
      },
      {
        id: "ends",
        accessorFn: (l) => (l.ends ? new Date(l.ends).getTime() : 0),
        header: ({ column }) => <SortHeader column={column} title="Expire" />,
        enableGlobalFilter: false,
        cell: ({ row }) => {
          const l = row.original
          return (
            <span
              className={cn("text-sm whitespace-nowrap", !isLive(l) && "text-muted-foreground")}
              title={`Début : ${formatDateTime(l.starts)}\nFin : ${formatDateTime(l.ends)}`}
            >
              {formatRelativeShort(l.ends)}
            </span>
          )
        },
      },
      {
        id: "relay",
        accessorFn: (l) => `${l.giaddr ?? ""} ${l.circuitId ?? ""} ${l.remoteId ?? ""}`,
        header: "Relais",
        enableSorting: false,
        cell: ({ row }) => (
          <div>
            {row.original.giaddr ? (
              <span className="font-mono text-xs">{row.original.giaddr}</span>
            ) : (
              <span className="text-xs text-muted-foreground">direct</span>
            )}
            <Option82 l={row.original} />
          </div>
        ),
      },
      {
        id: "dnsName",
        accessorFn: (l) => l.dnsName ?? "",
        header: "Nom DNS",
        enableSorting: false,
        cell: ({ row }) =>
          row.original.dnsName ? (
            <span className="font-mono text-xs">{row.original.dnsName.replace(/\.$/, "")}</span>
          ) : (
            <span className="text-muted-foreground">—</span>
          ),
      },
      ...(canWrite
        ? [
            {
              id: "actions",
              header: () => <span className="sr-only">Actions</span>,
              enableSorting: false,
              enableGlobalFilter: false,
              cell: ({ row }) => {
                const l = row.original
                if (!isLive(l) && l.reserved) return null
                return (
                  <div className="flex justify-end">
                    <DropdownMenu>
                      <DropdownMenuTrigger asChild>
                        <Button variant="ghost" size="icon-sm" aria-label={`Actions pour ${l.ip}`}>
                          <MoreHorizontal />
                        </Button>
                      </DropdownMenuTrigger>
                      <DropdownMenuContent align="end" className="w-56">
                        <DropdownMenuLabel className="font-mono">{l.ip}</DropdownMenuLabel>
                        <DropdownMenuSeparator />
                        {!l.reserved && (
                          <DropdownMenuItem onSelect={() => reserveMutate(l)}>
                            <BookmarkPlus /> Convertir en réservation
                          </DropdownMenuItem>
                        )}
                        {isLive(l) && (
                          <DropdownMenuItem variant="destructive" onSelect={() => setReleasing(l)}>
                            <Unplug /> Libérer
                          </DropdownMenuItem>
                        )}
                      </DropdownMenuContent>
                    </DropdownMenu>
                  </div>
                )
              },
            } satisfies ColumnDef<Lease, unknown>,
          ]
        : []),
    ],
    [canWrite, reserveMutate],
  )

  const updated = list.dataUpdatedAt ? new Date(list.dataUpdatedAt).toLocaleTimeString("fr-FR") : ""

  return (
    <>
      <PageHeader
        title="Baux"
        description="Adresses données aux clients, en temps réel."
        actions={
          <span className="inline-flex items-center gap-2 text-xs text-muted-foreground" title={updated ? `Mis à jour à ${updated}` : undefined}>
            <span className="relative flex size-2">
              <span
                className={cn(
                  "absolute inline-flex size-full rounded-full opacity-75 motion-safe:animate-ping",
                  list.isError ? "bg-destructive" : "bg-success",
                )}
              />
              <span className={cn("relative inline-flex size-2 rounded-full", list.isError ? "bg-destructive" : "bg-success")} />
            </span>
            {list.isError ? "Mise à jour en échec" : "Temps réel · toutes les 5 s"}
          </span>
        }
      />
      {list.isError && <p className="mb-3 text-sm text-destructive">{errorMessage(list.error)}</p>}
      <DataTable
        columns={columns}
        data={list.data?.items}
        loading={list.isPending}
        getRowId={leaseKey}
        search={q}
        onSearchChange={(v) => setParam("q", v || undefined)}
        searchAutoFocus={focusSearch}
        searchPlaceholder="IP, MAC, nom, circuit-id…"
        initialSorting={[{ id: "ip", desc: false }]}
        empty={
          scopes.data && scopeItems.length === 0 ? "Aucune étendue : créez-en une pour distribuer des adresses." : "Aucun bail pour ces filtres."
        }
        rowClassName={(l) => (isLive(l) ? undefined : "opacity-60")}
        toolbar={
          <>
            <Select value={scope || "all"} onValueChange={(v) => setParam("scope", v === "all" ? undefined : v)}>
              <SelectTrigger className="w-48" aria-label="Filtrer par étendue">
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="all">Toutes les étendues</SelectItem>
                {scope && !scopeItems.some((s) => s.id === scope) && <SelectItem value={scope}>Étendue {scope}</SelectItem>}
                {scopeItems.map((s) => (
                  <SelectItem key={s.id} value={s.id ?? ""}>
                    {s.name}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
            <Select value={vlan ? String(vlan) : "all"} onValueChange={(v) => setParam("vlan", v === "all" ? undefined : v)}>
              <SelectTrigger className="w-40" aria-label="Filtrer par VLAN">
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="all">Tous les VLAN</SelectItem>
                {vlan && !vlanOptions.some(([id]) => id === vlan) && <SelectItem value={String(vlan)}>VLAN {vlan}</SelectItem>}
                {vlanOptions.map(([id, name]) => (
                  <SelectItem key={id} value={String(id)}>
                    {vlanLabel(id, name)}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
            <Select value={state ?? "all"} onValueChange={(v) => setParam("state", v === "all" ? undefined : v)}>
              <SelectTrigger className="w-36" aria-label="Filtrer par état">
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="all">Tous les états</SelectItem>
                {leaseStates.map((s) => (
                  <SelectItem key={s} value={s}>
                    {leaseStateLabel[s]}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
            <label className="flex items-center gap-2 text-sm whitespace-nowrap">
              <Switch checked={showOld} onCheckedChange={(v) => setParam("all", v ? "1" : undefined)} aria-label="Afficher les anciens baux" />
              Anciens baux
            </label>
          </>
        }
      />
      {showOld && <p className="mt-2 text-xs text-muted-foreground">Les baux libérés ou expirés restent visibles 24 h.</p>}
      {releasing && (
        <ConfirmDialog
          open={!!releasing}
          onOpenChange={(o) => !o && setReleasing(null)}
          title={`Libérer ${releasing.ip} ?`}
          description={
            <>
              {releasing.hostname || releasing.mac} perd cette adresse : à son prochain renouvellement, il reçoit un refus et redemande une
              adresse.
              {releasing.reserved && " La réservation reste en place."}
            </>
          }
          confirmLabel="Libérer"
          destructive
          onConfirm={() => release.mutateAsync(releasing)}
        />
      )}
    </>
  )
}
