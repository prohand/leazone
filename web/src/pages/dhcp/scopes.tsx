import * as React from "react"
import { useNavigate, useSearchParams } from "react-router"
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query"
import type { ColumnDef } from "@tanstack/react-table"
import { BookmarkCheck, MoreHorizontal, Network, Pencil, Plus, Timer, Trash2 } from "lucide-react"
import { toast } from "sonner"
import { api } from "@/api/client"
import { qk, scopesQuery } from "@/api/queries"
import type { Scope } from "@/api/types"
import { ConfirmDialog } from "@/components/confirm-dialog"
import { DataTable, SortHeader } from "@/components/data-table"
import { DhcpStatusBanner, ModeBadge, ScopeUsageLine } from "@/components/dhcp"
import { EmptyState } from "@/components/empty-state"
import { PageHeader } from "@/components/page-header"
import { Badge } from "@/components/ui/badge"
import { Button } from "@/components/ui/button"
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu"
import { Switch } from "@/components/ui/switch"
import { useCurrentUser } from "@/hooks/use-session"
import { fmtInt, scopeInputOf } from "@/lib/dhcp"
import { errorMessage } from "@/lib/errors"
import { can } from "@/lib/permissions"
import { ScopeDialog } from "./scope-dialog"

/** "192.168.20.100 – 192.168.20.199" -> ".100 – .199" when both share the first three octets. */
function shortRange(a = "", b = "") {
  const pa = a.split(".")
  const pb = b.split(".")
  if (pa.length === 4 && pb.length === 4 && pa.slice(0, 3).join(".") === pb.slice(0, 3).join("."))
    return `.${pa[3]} – .${pb[3]}`
  return `${a} – ${b}`
}

export default function ScopesPage() {
  const qc = useQueryClient()
  const navigate = useNavigate()
  const user = useCurrentUser()
  const canConfig = can(user?.role, "config.write")
  const [params, setParams] = useSearchParams()
  const list = useQuery(scopesQuery)
  const [editing, setEditing] = React.useState<{ scope: Scope | null; vlanId?: number } | null>(null)
  const [deleting, setDeleting] = React.useState<Scope | null>(null)

  // ⌘K "Nouvelle étendue" and the VLAN cards land here with ?new=1 (&vlan=20).
  React.useEffect(() => {
    if (params.get("new") === "1") {
      const v = Number(params.get("vlan"))
      if (canConfig) setEditing({ scope: null, vlanId: Number.isInteger(v) && v > 0 ? v : undefined })
      setParams({}, { replace: true })
    }
  }, [params, setParams, canConfig])

  const refresh = () => {
    void qc.invalidateQueries({ queryKey: qk.dhcp })
    void qc.invalidateQueries({ queryKey: qk.vlans })
  }
  const toggle = useMutation({
    mutationFn: (v: { s: Scope; enabled: boolean }) =>
      api.put("/dhcp/scopes/{id}", { params: { id: v.s.id ?? "" }, body: scopeInputOf(v.s, { enabled: v.enabled }) }),
    onSuccess: (_, v) => toast.success(v.enabled ? `Étendue « ${v.s.name} » activée.` : `Étendue « ${v.s.name} » désactivée.`),
    onSettled: refresh,
  })
  const remove = useMutation({
    mutationFn: (id: string) => api.delete("/dhcp/scopes/{id}", { params: { id } }),
    onSuccess: () => {
      toast.success("Étendue supprimée.")
      refresh()
      void qc.invalidateQueries({ queryKey: qk.zones })
    },
  })

  const pendingId = toggle.isPending ? toggle.variables?.s.id : undefined
  const mutateToggle = toggle.mutate

  const columns = React.useMemo<ColumnDef<Scope, unknown>[]>(
    () => [
      {
        accessorKey: "name",
        header: ({ column }) => <SortHeader column={column} title="Nom" />,
        cell: ({ row }) => <span className="font-medium">{row.original.name}</span>,
      },
      {
        id: "vlan",
        accessorFn: (s) => (s.vlanId == null ? "" : `${s.vlanId} ${s.vlanName ?? ""}`),
        // Scopes without a VLAN go last.
        sortingFn: (a, b) => (a.original.vlanId ?? 10000) - (b.original.vlanId ?? 10000),
        header: ({ column }) => <SortHeader column={column} title="VLAN" />,
        cell: ({ row }) =>
          row.original.vlanId == null ? (
            <span className="text-sm text-muted-foreground">—</span>
          ) : (
            <Badge variant="secondary" title={row.original.vlanName || undefined}>
              VLAN {row.original.vlanId}
            </Badge>
          ),
      },
      {
        accessorKey: "network",
        header: "Réseau",
        cell: ({ row }) => <span className="font-mono text-sm">{row.original.network}</span>,
      },
      {
        id: "range",
        accessorFn: (s) => `${s.rangeStart} ${s.rangeEnd}`,
        header: "Plage",
        enableSorting: false,
        cell: ({ row }) => (
          <span
            className="font-mono text-xs whitespace-nowrap text-muted-foreground"
            title={`${row.original.rangeStart} – ${row.original.rangeEnd}`}
          >
            {shortRange(row.original.rangeStart, row.original.rangeEnd)}
          </span>
        ),
      },
      {
        id: "mode",
        accessorFn: (s) => s.mode ?? "none",
        header: ({ column }) => <SortHeader column={column} title="Mode" />,
        enableGlobalFilter: false,
        cell: ({ row }) => <ModeBadge mode={row.original.mode} />,
      },
      {
        id: "usage",
        accessorFn: (s) => s.usage?.percent ?? 0,
        header: ({ column }) => <SortHeader column={column} title="Remplissage" />,
        enableGlobalFilter: false,
        cell: ({ row }) => <ScopeUsageLine usage={row.original.usage} compact />,
      },
      {
        id: "active",
        accessorFn: (s) => s.usage?.activeLeases ?? 0,
        header: ({ column }) => <SortHeader column={column} title="Baux actifs" />,
        enableGlobalFilter: false,
        cell: ({ getValue }) => <span className="tabular-nums">{fmtInt.format(getValue() as number)}</span>,
      },
      {
        id: "enabled",
        accessorFn: (s) => (s.enabled === false ? 0 : 1),
        header: ({ column }) => <SortHeader column={column} title="Activée" />,
        enableGlobalFilter: false,
        cell: ({ row }) => {
          const s = row.original
          return canConfig ? (
            <Switch
              checked={s.enabled !== false}
              disabled={pendingId === s.id}
              onCheckedChange={(v) => mutateToggle({ s, enabled: v })}
              aria-label={`Étendue ${s.name} activée`}
            />
          ) : s.enabled === false ? (
            <Badge variant="outline">non</Badge>
          ) : (
            <Badge variant="outline" className="border-success/40 text-success">
              oui
            </Badge>
          )
        },
      },
      {
        id: "actions",
        header: () => <span className="sr-only">Actions</span>,
        enableSorting: false,
        enableGlobalFilter: false,
        cell: ({ row }) => {
          const s = row.original
          return (
            <div className="flex justify-end">
              <DropdownMenu>
                <DropdownMenuTrigger asChild>
                  <Button variant="ghost" size="icon-sm" aria-label={`Actions pour ${s.name}`}>
                    <MoreHorizontal />
                  </Button>
                </DropdownMenuTrigger>
                <DropdownMenuContent align="end" className="w-52">
                  {canConfig && (
                    <DropdownMenuItem onSelect={() => setEditing({ scope: s })}>
                      <Pencil /> Modifier
                    </DropdownMenuItem>
                  )}
                  <DropdownMenuItem onSelect={() => navigate(`/dhcp/leases?scope=${encodeURIComponent(s.id ?? "")}`)}>
                    <Timer /> Voir les baux
                  </DropdownMenuItem>
                  <DropdownMenuItem onSelect={() => navigate(`/dhcp/reservations?scope=${encodeURIComponent(s.id ?? "")}`)}>
                    <BookmarkCheck /> Réservations
                  </DropdownMenuItem>
                  {canConfig && (
                    <>
                      <DropdownMenuSeparator />
                      <DropdownMenuItem variant="destructive" onSelect={() => setDeleting(s)}>
                        <Trash2 /> Supprimer
                      </DropdownMenuItem>
                    </>
                  )}
                </DropdownMenuContent>
              </DropdownMenu>
            </div>
          )
        },
      },
    ],
    [canConfig, pendingId, mutateToggle, navigate],
  )

  const empty = !list.isPending && !list.isError && (list.data?.items ?? []).length === 0

  return (
    <>
      <PageHeader
        title="Étendues"
        description="Une étendue = un réseau et la plage d'adresses que Leazone y distribue."
        actions={
          canConfig && (
            <Button onClick={() => setEditing({ scope: null })}>
              <Plus /> Nouvelle étendue
            </Button>
          )
        }
      />
      <DhcpStatusBanner />
      {list.isError && <p className="mb-3 text-sm text-destructive">{errorMessage(list.error)}</p>}
      {empty ? (
        <EmptyState
          icon={Network}
          title="Aucune étendue"
          description="Créez une étendue pour que Leazone donne des adresses IP aux appareils d'un réseau ou d'un VLAN."
          action={
            canConfig && (
              <Button onClick={() => setEditing({ scope: null })}>
                <Plus /> Nouvelle étendue
              </Button>
            )
          }
        />
      ) : (
        <DataTable
          columns={columns}
          data={list.data?.items}
          loading={list.isPending}
          getRowId={(s) => s.id ?? s.name ?? ""}
          searchPlaceholder="Rechercher une étendue, un réseau…"
          initialSorting={[{ id: "vlan", desc: false }]}
          empty="Aucune étendue."
          onRowClick={(s) =>
            canConfig ? setEditing({ scope: s }) : navigate(`/dhcp/leases?scope=${encodeURIComponent(s.id ?? "")}`)
          }
          rowClassName={(s) => (s.enabled === false ? "opacity-60" : undefined)}
        />
      )}

      <ScopeDialog
        open={!!editing}
        onOpenChange={(o) => !o && setEditing(null)}
        scope={editing?.scope ?? null}
        defaultVlanId={editing?.vlanId}
      />
      {deleting && (
        <ConfirmDialog
          open={!!deleting}
          onOpenChange={(o) => !o && setDeleting(null)}
          title={`Supprimer l'étendue « ${deleting.name} » ?`}
          description={
            <>
              Ses réservations et ses baux sont supprimés aussi ({fmtInt.format(deleting.usage?.activeLeases ?? 0)} bail(s) actif(s)). Les
              clients perdront leur adresse au prochain renouvellement. Une confirmation d'identité est demandée.
            </>
          }
          confirmLabel="Supprimer"
          destructive
          onConfirm={() => remove.mutateAsync(deleting.id ?? "")}
        />
      )}
    </>
  )
}
