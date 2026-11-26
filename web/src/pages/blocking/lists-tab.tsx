import * as React from "react"
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query"
import type { ColumnDef } from "@tanstack/react-table"
import { ListPlus, Loader2, Pencil, Plus, RefreshCw, Trash2 } from "lucide-react"
import { toast } from "sonner"
import { api } from "@/api/client"
import { blockListsQuery, qk } from "@/api/queries"
import type { BlockList } from "@/api/types"
import { ConfirmDialog } from "@/components/confirm-dialog"
import { DataTable, SortHeader } from "@/components/data-table"
import { EmptyState } from "@/components/empty-state"
import { WriteGuard } from "@/components/read-only"
import { Badge } from "@/components/ui/badge"
import { Button } from "@/components/ui/button"
import { Switch } from "@/components/ui/switch"
import { safeUrl, usePermissions } from "@/hooks/use-cluster"
import { fmtInt, formatLabel } from "@/lib/blocking"
import { errorMessage } from "@/lib/errors"
import { formatDateTime, formatRelative } from "@/lib/format"
import { cn } from "@/lib/utils"
import { ListDialog } from "./list-dialog"

export function ListsTab() {
  const qc = useQueryClient()
  const perms = usePermissions()
  const canEdit = perms.can("config.write")
  const lists = useQuery(blockListsQuery)
  const [editing, setEditing] = React.useState<{ list: BlockList | null } | null>(null)
  const [deleting, setDeleting] = React.useState<BlockList | null>(null)
  const items = lists.data?.items ?? []

  const refreshAll = () => {
    void qc.invalidateQueries({ queryKey: qk.blockLists })
    void qc.invalidateQueries({ queryKey: qk.blockingStatus })
  }

  const toggle = useMutation({
    mutationFn: (v: { l: BlockList; enabled: boolean }) =>
      api.put("/blocking/lists/{id}", {
        params: { id: v.l.id ?? "" },
        body: { name: v.l.name, url: v.l.url, format: v.l.format ?? "auto", enabled: v.enabled },
      }),
    onSuccess: (_r, v) => toast.success(v.enabled ? "Liste activée." : "Liste désactivée."),
    onSettled: refreshAll,
  })
  const remove = useMutation({
    mutationFn: (id: string) => api.delete("/blocking/lists/{id}", { params: { id } }),
    onSuccess: () => {
      toast.success("Liste supprimée.")
      refreshAll()
    },
  })
  const refresh = useMutation({
    mutationFn: () => api.post("/blocking/refresh"),
    onSuccess: (r) => {
      if (r?.items) qc.setQueryData(qk.blockLists, r)
      void qc.invalidateQueries({ queryKey: qk.blockingStatus })
      const failed = (r?.items ?? []).filter((l) => l.enabled !== false && l.error).length
      if (failed) toast.warning(`Listes mises à jour, ${failed} en erreur.`)
      else toast.success("Listes mises à jour.")
    },
  })

  const columns = React.useMemo<ColumnDef<BlockList, unknown>[]>(
    () => [
      {
        id: "name",
        accessorFn: (l) => `${l.name} ${l.url}`,
        header: ({ column }) => <SortHeader column={column} title="Nom" />,
        sortingFn: (a, b) => a.original.name.localeCompare(b.original.name, "fr"),
        cell: ({ row }) => (
          <div className={cn("min-w-0 space-y-0.5", row.original.enabled === false && "opacity-60")}>
            <div className="font-medium">{row.original.name}</div>
            <a
              href={safeUrl(row.original.url) || undefined}
              target="_blank"
              rel="noopener noreferrer"
              className="block max-w-[18rem] truncate font-mono text-xs text-muted-foreground hover:underline sm:max-w-[26rem]"
              title={row.original.url}
            >
              {row.original.url}
            </a>
          </div>
        ),
      },
      {
        id: "format",
        accessorFn: (l) => formatLabel[l.format ?? "auto"],
        header: ({ column }) => <SortHeader column={column} title="Format" />,
        cell: ({ getValue }) => <Badge variant="outline">{String(getValue())}</Badge>,
      },
      {
        id: "entries",
        accessorFn: (l) => l.entries ?? 0,
        enableGlobalFilter: false,
        header: ({ column }) => <SortHeader column={column} title="Domaines" />,
        cell: ({ row }) => <span className="tabular-nums">{row.original.fetchedAt ? fmtInt.format(row.original.entries ?? 0) : "—"}</span>,
      },
      {
        id: "fetchedAt",
        accessorFn: (l) => l.fetchedAt ?? "",
        enableGlobalFilter: false,
        header: ({ column }) => <SortHeader column={column} title="Téléchargée" />,
        cell: ({ row }) => {
          const l = row.original
          return (
            <div className="max-w-[16rem] space-y-0.5">
              <span className="text-sm" title={l.fetchedAt ? formatDateTime(l.fetchedAt) : undefined}>
                {l.fetchedAt ? formatRelative(l.fetchedAt) : l.error ? "jamais" : "en attente…"}
              </span>
              {l.error && (
                <p className="text-xs whitespace-normal text-destructive" data-testid="list-error">
                  {l.error}
                </p>
              )}
            </div>
          )
        },
      },
      {
        id: "actions",
        enableSorting: false,
        enableGlobalFilter: false,
        cell: ({ row }) => {
          const l = row.original
          if (!canEdit) return l.enabled === false ? <Badge variant="outline">désactivée</Badge> : null
          return (
            <div className="flex items-center justify-end gap-1">
              <Switch
                className="mr-2"
                checked={l.enabled !== false}
                disabled={toggle.isPending}
                onCheckedChange={(v) => toggle.mutate({ l, enabled: v })}
                aria-label={l.enabled === false ? `Activer ${l.name}` : `Désactiver ${l.name}`}
              />
              <Button variant="ghost" size="icon-sm" aria-label={`Modifier ${l.name}`} onClick={() => setEditing({ list: l })}>
                <Pencil />
              </Button>
              <Button
                variant="ghost"
                size="icon-sm"
                className="text-muted-foreground hover:text-destructive"
                aria-label={`Supprimer ${l.name}`}
                onClick={() => setDeleting(l)}
              >
                <Trash2 />
              </Button>
            </div>
          )
        },
      },
    ],
    [canEdit, toggle.isPending, toggle.mutate],
  )

  const addButton = perms.allowed("config.write") && (
    <WriteGuard>
      <Button onClick={() => setEditing({ list: null })}>
        <Plus /> Ajouter une liste
      </Button>
    </WriteGuard>
  )

  return (
    <div className="space-y-3">
      {lists.isError && <p className="text-sm text-destructive">{errorMessage(lists.error)}</p>}
      {!lists.isPending && items.length === 0 ? (
        <EmptyState
          icon={ListPlus}
          title="Aucune liste"
          description="Abonnez-vous à une liste publique (StevenBlack, OISD, HaGeZi…) pour commencer à bloquer."
          action={addButton}
          className="py-10"
        />
      ) : (
        <DataTable
          columns={columns}
          data={items}
          loading={lists.isPending}
          getRowId={(l) => l.id ?? l.url}
          searchPlaceholder="Rechercher une liste…"
          initialSorting={[{ id: "name", desc: false }]}
          toolbar={
            <>
              {perms.allowed("blocking.refresh") && (
                <Button variant="outline" onClick={() => refresh.mutate()} disabled={refresh.isPending}>
                  {refresh.isPending ? <Loader2 className="animate-spin" /> : <RefreshCw />} Mettre à jour maintenant
                </Button>
              )}
              {addButton}
            </>
          }
        />
      )}
      <ListDialog open={!!editing} onOpenChange={(o) => !o && setEditing(null)} list={editing?.list ?? null} existing={items} />
      {deleting && (
        <ConfirmDialog
          open={!!deleting}
          onOpenChange={(o) => !o && setDeleting(null)}
          title={`Supprimer la liste « ${deleting.name} » ?`}
          description="Ses domaines ne seront plus bloqués. Vous pourrez la rajouter plus tard."
          confirmLabel="Supprimer"
          destructive
          onConfirm={() => remove.mutateAsync(deleting.id ?? "")}
        />
      )}
    </div>
  )
}
