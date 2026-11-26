import * as React from "react"
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query"
import type { ColumnDef } from "@tanstack/react-table"
import { toast } from "sonner"
import { api } from "@/api/client"
import { interfacesQuery, qk } from "@/api/queries"
import type { DnsListener, InterfaceType, NetInterface } from "@/api/types"
import { DataTable, SortHeader } from "@/components/data-table"
import { PageHeader } from "@/components/page-header"
import { StatusDot } from "@/components/status-dot"
import { Badge } from "@/components/ui/badge"
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select"
import { Switch } from "@/components/ui/switch"
import { Tooltip, TooltipContent, TooltipTrigger } from "@/components/ui/tooltip"
import { useCurrentUser } from "@/hooks/use-session"
import { interfaceTypeLabel } from "@/lib/dns"
import { errorMessage } from "@/lib/errors"
import { can } from "@/lib/permissions"

/** IPv4 first, then IPv6; keep the server order inside a family. */
function sortedAddresses(i: NetInterface) {
  const list = i.addresses ?? []
  return [...list.filter((a) => a.family !== "ipv6"), ...list.filter((a) => a.family === "ipv6")]
}

function Listener({ l }: { l: DnsListener }) {
  const ok = l.state === "listening"
  return (
    <div className="flex items-center gap-2 text-xs">
      <StatusDot tone={ok ? "ok" : "error"} />
      <span className="font-mono">{l.address}</span>
      <span className="text-muted-foreground uppercase">{l.protocol}</span>
      {ok ? (
        <span className="text-success">écoute</span>
      ) : (
        <span className="max-w-72 truncate text-destructive" title={l.error}>
          {l.error || "erreur"}
        </span>
      )}
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
  const user = useCurrentUser()
  const canEdit = can(user?.role, "config.write")
  const list = useQuery(interfacesQuery)
  const [typeFilter, setTypeFilter] = React.useState<"all" | InterfaceType>("all")

  const toggleDns = useMutation({
    mutationFn: (v: { name: string; enabled: boolean }) =>
      api.patch("/interfaces/{name}", { params: { name: v.name }, body: { dnsEnabled: v.enabled } }),
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

  const pendingName = toggleDns.isPending ? toggleDns.variables?.name : undefined
  const mutate = toggleDns.mutate

  const columns = React.useMemo<ColumnDef<NetInterface, unknown>[]>(
    () => [
      {
        accessorKey: "name",
        header: ({ column }) => <SortHeader column={column} title="Nom" />,
        cell: ({ row }) => {
          const i = row.original
          return (
            <div className="flex flex-wrap items-center gap-x-2 gap-y-1">
              <span className="font-medium">{i.name}</span>
              {i.type === "vlan" && i.vlanId != null && <Badge variant="secondary">VLAN {i.vlanId}</Badge>}
              {i.parent && <span className="text-xs text-muted-foreground">sur {i.parent}</span>}
              {i.present === false && (
                <Badge variant="outline" className="border-warning/50 text-warning">
                  absente de l'hôte
                </Badge>
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
            <WithTooltip text={canEdit ? undefined : "Réservé aux administrateurs"}>
              <Switch
                checked={!!i.dnsEnabled}
                disabled={!canEdit || pendingName === i.name}
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
        header: "DHCP",
        enableSorting: false,
        enableGlobalFilter: false,
        cell: ({ row }) => (
          <WithTooltip text="Disponible en phase 3">
            <Switch checked={!!row.original.dhcpEnabled} disabled aria-label={`DHCP sur ${row.original.name}`} />
          </WithTooltip>
        ),
      },
      {
        id: "listeners",
        header: "Écoute DNS",
        enableSorting: false,
        enableGlobalFilter: false,
        cell: ({ row }) => {
          const i = row.original
          if (!i.dnsEnabled) return <span className="text-sm text-muted-foreground">—</span>
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
    [canEdit, pendingName, mutate],
  )

  const all = list.data?.items
  const types = React.useMemo(() => [...new Set((all ?? []).map((i) => i.type ?? "other"))].sort(), [all])
  const data = React.useMemo(
    () => (all ?? []).filter((i) => typeFilter === "all" || (i.type ?? "other") === typeFilter),
    [all, typeFilter],
  )

  return (
    <>
      <PageHeader
        title="Interfaces"
        description="Les VLAN se créent sur l'hôte (netplan ou systemd-networkd) ; Leazone ne fait que les détecter, en quelques secondes."
      />
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
          <Select value={typeFilter} onValueChange={(v) => setTypeFilter(v as "all" | InterfaceType)}>
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
