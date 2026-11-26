import * as React from "react"
import { useSearchParams } from "react-router"
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query"
import type { ColumnDef } from "@tanstack/react-table"
import { BookmarkCheck, Pencil, Plus, Trash2 } from "lucide-react"
import { toast } from "sonner"
import { api } from "@/api/client"
import { qk, reservationsQuery, scopesQuery } from "@/api/queries"
import type { Reservation } from "@/api/types"
import { ConfirmDialog } from "@/components/confirm-dialog"
import { DataTable, SortHeader } from "@/components/data-table"
import { EmptyState } from "@/components/empty-state"
import { PageHeader } from "@/components/page-header"
import { Button } from "@/components/ui/button"
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select"
import { useCurrentUser } from "@/hooks/use-session"
import { ipToInt } from "@/lib/dhcp"
import { errorMessage } from "@/lib/errors"
import { formatDateTime, formatRelative } from "@/lib/format"
import { can } from "@/lib/permissions"
import { ReservationDialog } from "./reservation-dialog"

export default function ReservationsPage() {
  const qc = useQueryClient()
  const user = useCurrentUser()
  const canWrite = can(user?.role, "leases.write")
  const [params, setParams] = useSearchParams()
  const scope = params.get("scope") ?? ""
  const list = useQuery(reservationsQuery(scope || undefined))
  const scopes = useQuery(scopesQuery)
  const [editing, setEditing] = React.useState<{ r: Reservation | null } | null>(null)
  const [deleting, setDeleting] = React.useState<Reservation | null>(null)

  // ⌘K "Nouvelle réservation" lands here with ?new=1.
  React.useEffect(() => {
    if (params.get("new") === "1") {
      if (canWrite) setEditing({ r: null })
      setParams(
        (p) => {
          const n = new URLSearchParams(p)
          n.delete("new")
          return n
        },
        { replace: true },
      )
    }
  }, [params, setParams, canWrite])

  const remove = useMutation({
    mutationFn: (id: string) => api.delete("/dhcp/reservations/{id}", { params: { id } }),
    onSuccess: () => {
      toast.success("Réservation supprimée.")
      void qc.invalidateQueries({ queryKey: qk.dhcp })
      void qc.invalidateQueries({ queryKey: qk.vlans })
    },
  })

  const columns = React.useMemo<ColumnDef<Reservation, unknown>[]>(
    () => [
      {
        accessorKey: "ip",
        header: ({ column }) => <SortHeader column={column} title="IP" />,
        sortingFn: (a, b) => (ipToInt(a.original.ip) ?? 0) - (ipToInt(b.original.ip) ?? 0),
        cell: ({ row }) => <span className="font-mono text-sm">{row.original.ip}</span>,
      },
      {
        id: "client",
        accessorFn: (r) => `${r.mac ?? ""} ${r.clientId ?? ""}`,
        header: "MAC / identifiant",
        enableSorting: false,
        cell: ({ row }) =>
          row.original.mac ? (
            <span className="font-mono text-xs">{row.original.mac}</span>
          ) : (
            <span className="font-mono text-xs" title="Identifiant client (option 61)">
              id {row.original.clientId}
            </span>
          ),
      },
      {
        id: "hostname",
        accessorFn: (r) => r.hostname ?? "",
        header: ({ column }) => <SortHeader column={column} title="Nom d'hôte" />,
        cell: ({ row }) => row.original.hostname || <span className="text-muted-foreground">—</span>,
      },
      {
        id: "scope",
        accessorFn: (r) => r.scopeName ?? "",
        header: ({ column }) => <SortHeader column={column} title="Étendue" />,
      },
      {
        id: "description",
        accessorFn: (r) => r.description ?? "",
        header: "Description",
        enableSorting: false,
        cell: ({ row }) => (
          <span className="line-clamp-2 max-w-64 text-sm text-muted-foreground">{row.original.description || "—"}</span>
        ),
      },
      {
        id: "createdAt",
        accessorFn: (r) => (r.createdAt ? new Date(r.createdAt).getTime() : 0),
        header: ({ column }) => <SortHeader column={column} title="Créée" />,
        enableGlobalFilter: false,
        cell: ({ row }) => (
          <span className="text-sm whitespace-nowrap text-muted-foreground" title={formatDateTime(row.original.createdAt)}>
            {formatRelative(row.original.createdAt)}
          </span>
        ),
      },
      ...(canWrite
        ? [
            {
              id: "actions",
              header: () => <span className="sr-only">Actions</span>,
              enableSorting: false,
              enableGlobalFilter: false,
              cell: ({ row }) => (
                <div className="flex justify-end gap-1">
                  <Button variant="ghost" size="icon-sm" aria-label={`Modifier ${row.original.ip}`} onClick={() => setEditing({ r: row.original })}>
                    <Pencil />
                  </Button>
                  <Button
                    variant="ghost"
                    size="icon-sm"
                    aria-label={`Supprimer ${row.original.ip}`}
                    className="text-muted-foreground hover:text-destructive"
                    onClick={() => setDeleting(row.original)}
                  >
                    <Trash2 />
                  </Button>
                </div>
              ),
            } satisfies ColumnDef<Reservation, unknown>,
          ]
        : []),
    ],
    [canWrite],
  )

  const scopeItems = scopes.data?.items ?? []
  const empty = !list.isPending && !list.isError && !scope && (list.data?.items ?? []).length === 0

  return (
    <>
      <PageHeader
        title="Réservations"
        description="Appareils qui reçoivent toujours la même adresse IP."
        actions={
          canWrite && (
            <Button onClick={() => setEditing({ r: null })}>
              <Plus /> Nouvelle réservation
            </Button>
          )
        }
      />
      {list.isError && <p className="mb-3 text-sm text-destructive">{errorMessage(list.error)}</p>}
      {empty ? (
        <EmptyState
          icon={BookmarkCheck}
          title="Aucune réservation"
          description="Réservez une adresse pour une imprimante, un NAS ou une caméra. Astuce : depuis la page Baux, « Convertir en réservation » le fait en un clic."
          action={
            canWrite && (
              <Button onClick={() => setEditing({ r: null })}>
                <Plus /> Nouvelle réservation
              </Button>
            )
          }
        />
      ) : (
        <DataTable
          columns={columns}
          data={list.data?.items}
          loading={list.isPending}
          getRowId={(r) => r.id ?? `${r.scopeId}/${r.ip}`}
          searchPlaceholder="IP, MAC, nom…"
          initialSorting={[{ id: "ip", desc: false }]}
          empty="Aucune réservation dans cette étendue."
          onRowClick={canWrite ? (r) => setEditing({ r }) : undefined}
          toolbar={
            <Select
              value={scope || "all"}
              onValueChange={(v) =>
                setParams(
                  (p) => {
                    const n = new URLSearchParams(p)
                    if (v === "all") n.delete("scope")
                    else n.set("scope", v)
                    return n
                  },
                  { replace: true },
                )
              }
            >
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
          }
        />
      )}

      <ReservationDialog
        open={!!editing}
        onOpenChange={(o) => !o && setEditing(null)}
        reservation={editing?.r ?? null}
        defaultScopeId={scope || undefined}
      />
      {deleting && (
        <ConfirmDialog
          open={!!deleting}
          onOpenChange={(o) => !o && setDeleting(null)}
          title={`Supprimer la réservation de ${deleting.ip} ?`}
          description={`${deleting.hostname || deleting.mac || deleting.clientId} pourra recevoir une autre adresse à son prochain renouvellement.`}
          confirmLabel="Supprimer"
          destructive
          onConfirm={() => remove.mutateAsync(deleting.id ?? "")}
        />
      )}
    </>
  )
}
