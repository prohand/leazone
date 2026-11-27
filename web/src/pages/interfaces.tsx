import * as React from "react"
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query"
import type { ColumnDef } from "@tanstack/react-table"
import { toast } from "sonner"
import { api } from "@/api/client"
import { interfacesQuery, qk } from "@/api/queries"
import type { DnsListener, InterfaceType, NetInterface } from "@/api/types"
import { DataTable, SortHeader } from "@/components/data-table"
import { DhcpStatusBanner } from "@/components/dhcp"
import { PageHeader } from "@/components/page-header"
import { StatusDot } from "@/components/status-dot"
import { Badge } from "@/components/ui/badge"
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select"
import { Switch } from "@/components/ui/switch"
import { Tooltip, TooltipContent, TooltipTrigger } from "@/components/ui/tooltip"
import { usePermissions } from "@/hooks/use-cluster"
import { interfaceTypeLabel } from "@/lib/dns"
import { errorMessage } from "@/lib/errors"

/** IPv4 first, then IPv6; keep the server order inside a family. */
function sortedAddresses(i: NetInterface) {
  const list = i.addresses ?? []
  return [...list.filter((a) => a.family !== "ipv6"), ...list.filter((a) => a.family === "ipv6")]
}

function Listener({ l }: { l: DnsListener }) {
  const ok = l.state === "listening"
  return (
    <div className="text-xs">
      <div className="flex items-center gap-2">
        <StatusDot tone={ok ? "ok" : "error"} />
        <span className="font-mono">{l.address}</span>
        <span className="text-muted-foreground uppercase">{l.protocol}</span>
        {ok && <span className="text-success">écoute</span>}
      </div>
      {!ok && <p className="max-w-64 pl-4 whitespace-normal text-destructive">{l.error || "erreur"}</p>}
    </div>
  )
}

/** Tooltip around a disabled control (disabled elements do not fire pointer events). */
function WithTooltip({ text, children }: { text?: string; children: React.ReactNode }) {
  if (!text) return <>{children}</>
  return (
    <Tooltip>
      <TooltipTrigger asChild>
        <span className="inline-flex" tabIndex={0}>
          {children}
        </span>
      </TooltipTrigger>
      <TooltipContent>{text}</TooltipContent>
    </Tooltip>
  )
}

export default function InterfacesPage() {
  const qc = useQueryClient()
  const perms = usePermissions()
  const canEdit = perms.can("config.write")
  // Why the switches are disabled: role first, then a read-only cluster node.
  const lockHint = !perms.allowed("config.write") ? "Réservé aux administrateurs" : canEdit ? undefined : perms.hint
  const list = useQuery(interfacesQuery)
  const [typeFilter, setTypeFilter] = React.useState<"all" | InterfaceType>("all")
  // Names whose DNS / DHCP switch has a request in flight (several can run at once).
  const [pendingDns, setPendingDns] = React.useState<ReadonlySet<string>>(() => new Set())
  const [pendingDhcp, setPendingDhcp] = React.useState<ReadonlySet<string>>(() => new Set())
  const addPending = (set: typeof setPendingDns, name: string) => set((s) => new Set(s).add(name))
  const dropPending = (set: typeof setPendingDns, name: string) =>
    set((s) => {
      const n = new Set(s)
      n.delete(name)
      return n
    })

  const toggleDns = useMutation({
    mutationFn: (v: { name: string; enabled: boolean }) =>
      api.patch("/interfaces/{name}", { params: { name: v.name }, body: { dnsEnabled: v.enabled } }),
    onMutate: (v) => addPending(setPendingDns, v.name),
    onSettled: (_, __, v) => dropPending(setPendingDns, v.name),
    onSuccess: (iface, v) => {
      qc.setQueryData(qk.interfaces, (old: { items?: NetInterface[] } | undefined) =>
        old ? { ...old, items: (old.items ?? []).map((i) => (i.name === v.name ? iface : i)) } : old,
      )
      void qc.invalidateQueries({ queryKey: qk.interfaces })
      void qc.invalidateQueries({ queryKey: qk.dnsStatus })
      if (!v.enabled) return void toast.success(`DNS désactivé sur ${v.name}.`)
      const listeners = iface.dnsListeners ?? []
      const failed = listeners.filter((l) => l.state !== "listening")
      if (listeners.length === 0) {
        toast.warning(`DNS activé sur ${v.name}, mais rien n'écoute encore`, {
          description: "L'interface n'a pas d'adresse IP. Leazone écoutera dès qu'elle en aura une.",
        })
      } else if (failed.length > 0) {
        toast.warning(`DNS activé sur ${v.name}, avec des erreurs`, {
          description: failed.map((l) => `${l.address} ${l.protocol?.toUpperCase()} : ${l.error || "erreur"}`).join("\n"),
        })
      } else {
        toast.success(`DNS activé sur ${v.name}.`)
      }
    },
  })

  const toggleDhcp = useMutation({
    mutationFn: (v: { name: string; enabled: boolean }) =>
      api.patch("/interfaces/{name}", { params: { name: v.name }, body: { dhcpEnabled: v.enabled } }),
    onMutate: (v) => addPending(setPendingDhcp, v.name),
    onSettled: (_, __, v) => dropPending(setPendingDhcp, v.name),
    onSuccess: (iface, v) => {
      qc.setQueryData(qk.interfaces, (old: { items?: NetInterface[] } | undefined) =>
        old ? { ...old, items: (old.items ?? []).map((i) => (i.name === v.name ? iface : i)) } : old,
      )
      void qc.invalidateQueries({ queryKey: qk.interfaces })
      void qc.invalidateQueries({ queryKey: qk.dhcpStatus })
      void qc.invalidateQueries({ queryKey: qk.vlans })
      if (!v.enabled) return void toast.success(`DHCP désactivé sur ${v.name}.`)
      const hasV4 = (iface.addresses ?? []).some((a) => a.family !== "ipv6")
      if (!hasV4)
        toast.warning(`DHCP activé sur ${v.name}, sans adresse IPv4`, {
          description: "Leazone ne peut répondre en direct que sur une interface qui a une IP dans le réseau de l'étendue.",
        })
      else toast.success(`DHCP activé sur ${v.name}.`, { description: "Les étendues en mode direct sur cette interface répondent aux clients." })
    },
  })

  const mutate = toggleDns.mutate
  const mutateDhcp = toggleDhcp.mutate

  const columns = React.useMemo<ColumnDef<NetInterface, unknown>[]>(
    () => [
      {
        accessorKey: "name",
        header: ({ column }) => <SortHeader column={column} title="Nom" />,
        cell: ({ row }) => {
          const i = row.original
          return (
            <div className="space-y-1">
              <div className="flex items-center gap-2">
                <span className="font-medium">{i.name}</span>
                {i.type === "vlan" && i.vlanId != null && <Badge variant="secondary">VLAN {i.vlanId}</Badge>}
              </div>
              {(i.parent || i.present === false) && (
                <div className="flex items-center gap-2">
                  {i.parent && <span className="text-xs text-muted-foreground">sur {i.parent}</span>}
                  {i.present === false && (
                    <Badge variant="outline" className="border-warning/50 text-warning">
                      absente de l'hôte
                    </Badge>
                  )}
                </div>
              )}
            </div>
          )
        },
      },
      {
        id: "type",
        accessorFn: (i) => interfaceTypeLabel[i.type ?? "other"],
        header: ({ column }) => <SortHeader column={column} title="Type" />,
        cell: ({ getValue }) => <Badge variant="outline">{getValue() as string}</Badge>,
      },
      {
        id: "up",
        accessorFn: (i) => (i.up ? "active" : "inactive"),
        header: ({ column }) => <SortHeader column={column} title="État" />,
        enableGlobalFilter: false,
        cell: ({ row }) => (
          <StatusDot
            tone={row.original.up ? "ok" : "off"}
            label={<span className="text-sm">{row.original.up ? "Active" : "Inactive"}</span>}
          />
        ),
      },
      {
        accessorKey: "mac",
        header: "MAC",
        cell: ({ row }) => <span className="font-mono text-xs text-muted-foreground">{row.original.mac || "—"}</span>,
      },
      {
        id: "addresses",
        accessorFn: (i) => sortedAddresses(i).map((a) => `${a.address} ${a.network}`).join(" "),
        header: "Adresses",
        enableSorting: false,
        cell: ({ row }) => {
          const addrs = sortedAddresses(row.original)
          if (addrs.length === 0) return <span className="text-sm text-muted-foreground">aucune IP</span>
          return (
            <div className="space-y-0.5">
              {addrs.map((a) => (
                <div key={`${a.address}/${a.prefixLength}`} className="text-sm">
                  <span className="font-mono">{a.address}</span>
                  {a.network && <span className="ml-2 font-mono text-xs text-muted-foreground">{a.network}</span>}
                </div>
              ))}
            </div>
          )
        },
      },
      {
        id: "dns",
        accessorFn: (i) => (i.dnsEnabled ? 1 : 0),
        header: ({ column }) => <SortHeader column={column} title="DNS" />,
        enableGlobalFilter: false,
        cell: ({ row }) => {
          const i = row.original
          return (
            <WithTooltip text={lockHint}>
              <Switch
                checked={!!i.dnsEnabled}
                disabled={!canEdit || (!!i.name && pendingDns.has(i.name))}
                onCheckedChange={(v) => i.name && mutate({ name: i.name, enabled: v })}
                aria-label={`DNS sur ${i.name}`}
              />
            </WithTooltip>
          )
        },
      },
      {
        id: "dhcp",
        accessorFn: (i) => (i.dhcpEnabled ? 1 : 0),
        header: ({ column }) => <SortHeader column={column} title="DHCP" />,
        enableGlobalFilter: false,
        cell: ({ row }) => {
          const i = row.original
          return (
            <WithTooltip text={lockHint}>
              <Switch
                checked={!!i.dhcpEnabled}
                disabled={!canEdit || (!!i.name && pendingDhcp.has(i.name)) || i.type === "loopback"}
                onCheckedChange={(v) => i.name && mutateDhcp({ name: i.name, enabled: v })}
                aria-label={`DHCP sur ${i.name}`}
              />
            </WithTooltip>
          )
        },
      },
      {
        id: "listeners",
        header: "Écoute DNS",
        enableSorting: false,
        enableGlobalFilter: false,
        cell: ({ row }) => {
          const i = row.original
          if (!i.dnsEnabled) return <span className="text-sm text-muted-foreground">—</span>
          if (i.present === false) return <span className="text-xs text-muted-foreground">interface absente</span>
          const ls = i.dnsListeners ?? []
          if (ls.length === 0)
            return <span className="text-xs text-warning">aucune écoute (pas d'adresse IP)</span>
          return (
            <div className="space-y-1">
              {ls.map((l) => (
                <Listener key={`${l.address}-${l.protocol}`} l={l} />
              ))}
            </div>
          )
        },
      },
    ],
    [canEdit, lockHint, pendingDns, mutate, pendingDhcp, mutateDhcp],
  )

  const all = list.data?.items
  const types = React.useMemo(() => [...new Set((all ?? []).map((i) => i.type ?? "other"))].sort(), [all])
  // A filter on a type that no longer exists (interface removed) falls back to "all".
  const filter = typeFilter !== "all" && all && !types.includes(typeFilter) ? "all" : typeFilter
  React.useEffect(() => {
    if (filter !== typeFilter) setTypeFilter(filter)
  }, [filter, typeFilter])
  const data = React.useMemo(
    () => (all ?? []).filter((i) => filter === "all" || (i.type ?? "other") === filter),
    [all, filter],
  )

  return (
    <>
      <PageHeader
        title="Interfaces"
        description="Les VLAN se créent sur l'hôte (netplan ou systemd-networkd) ; Leazone ne fait que les détecter, en quelques secondes."
      />
      <DhcpStatusBanner />
      {list.isError && <p className="mb-3 text-sm text-destructive">{errorMessage(list.error)}</p>}
      <DataTable
        columns={columns}
        data={data}
        loading={list.isPending}
        getRowId={(i) => i.name ?? String(i.index)}
        searchPlaceholder="Rechercher une interface, une IP…"
        initialSorting={[{ id: "name", desc: false }]}
        empty="Aucune interface détectée."
        rowClassName={(i) => (i.present === false ? "opacity-60" : undefined)}
        toolbar={
          <Select value={filter} onValueChange={(v) => setTypeFilter(v as "all" | InterfaceType)}>
            <SelectTrigger className="w-44" aria-label="Filtrer par type">
              <SelectValue />
            </SelectTrigger>
            <SelectContent>
              <SelectItem value="all">Tous les types</SelectItem>
              {types.map((t) => (
                <SelectItem key={t} value={t}>
                  {interfaceTypeLabel[t]}
                </SelectItem>
              ))}
            </SelectContent>
          </Select>
        }
      />
    </>
  )
}
