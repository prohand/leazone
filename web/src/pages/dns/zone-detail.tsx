import * as React from "react"
import { Link, useNavigate, useParams } from "react-router"
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query"
import type { ColumnDef, SortingFn } from "@tanstack/react-table"
import { ArrowLeft, Download, Globe, Lock, Pencil, Plus, Settings2, Trash2, Upload } from "lucide-react"
import { toast } from "sonner"
import { api, isApiError, ProblemType } from "@/api/client"
import { qk, recordsQuery, zoneQuery } from "@/api/queries"
import type { DnsRecord, RecordType } from "@/api/types"
import { ConfirmDialog } from "@/components/confirm-dialog"
import { DataTable, SortHeader } from "@/components/data-table"
import { EmptyState } from "@/components/empty-state"
import { BlockSpinner } from "@/components/spinner"
import { Badge } from "@/components/ui/badge"
import { Button } from "@/components/ui/button"
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select"
import { Tooltip, TooltipContent, TooltipTrigger } from "@/components/ui/tooltip"
import { WriteGuard } from "@/components/read-only"
import { usePermissions } from "@/hooks/use-cluster"
import { humanDuration, recordTypes } from "@/lib/dns"
import { errorMessage, toastError } from "@/lib/errors"
import { RecordDialog } from "./record-dialog"
import { ZoneDeleteDialog, ZoneImportDialog, ZoneSettingsDialog } from "./zone-dialogs"
import { ZoneKindBadge } from "./zones"

// "@" first, then natural order (host2 before host10).
const nameSort: SortingFn<DnsRecord> = (a, b) => {
  const x = a.original.name ?? ""
  const y = b.original.name ?? ""
  if (x === "@" || y === "@") return x === y ? 0 : x === "@" ? -1 : 1
  return x.localeCompare(y, "fr", { numeric: true })
}

function downloadText(filename: string, text: string) {
  const url = URL.createObjectURL(new Blob([text], { type: "text/plain;charset=utf-8" }))
  const a = document.createElement("a")
  a.href = url
  a.download = filename
  document.body.appendChild(a)
  a.click()
  a.remove()
  window.setTimeout(() => URL.revokeObjectURL(url), 1000)
}

type Dialog = "settings" | "import" | "delete" | null

export default function ZoneDetailPage() {
  const { id = "" } = useParams()
  const navigate = useNavigate()
  const qc = useQueryClient()
  const perms = usePermissions()
  const canRecords = perms.can("records.write")
  const zone = useQuery(zoneQuery(id))
  const records = useQuery(recordsQuery(id))
  const [typeFilter, setTypeFilter] = React.useState<"all" | RecordType>("all")
  const [dialog, setDialog] = React.useState<Dialog>(null)
  const [editing, setEditing] = React.useState<{ record: DnsRecord | null } | null>(null)
  const [deleting, setDeleting] = React.useState<DnsRecord | null>(null)
  const [exporting, setExporting] = React.useState(false)

  const remove = useMutation({
    mutationFn: (rid: string) => api.delete("/dns/zones/{id}/records/{rid}", { params: { id, rid } }),
    onSuccess: () => {
      toast.success("Enregistrement supprimé.")
      void qc.invalidateQueries({ queryKey: qk.records(id) })
      void qc.invalidateQueries({ queryKey: qk.zone(id) })
      void qc.invalidateQueries({ queryKey: qk.zones, exact: true })
    },
  })

  const exportZone = async () => {
    setExporting(true)
    try {
      const text = await api.get("/dns/zones/{id}/export", { params: { id } })
      downloadText(`${(zone.data?.name ?? "zone").replace(/\.$/, "")}.zone`, typeof text === "string" ? text : "")
    } catch (e) {
      toastError(e, "Export impossible")
    } finally {
      setExporting(false)
    }
  }

  const columns = React.useMemo<ColumnDef<DnsRecord, unknown>[]>(
    () => [
      {
        id: "name",
        accessorFn: (r) => `${r.name ?? ""} ${r.fqdn ?? ""}`,
        sortingFn: nameSort,
        header: ({ column }) => <SortHeader column={column} title="Nom" />,
        cell: ({ row }) => (
          <span className="font-medium" title={row.original.fqdn}>
            {row.original.name}
          </span>
        ),
      },
      {
        accessorKey: "type",
        header: ({ column }) => <SortHeader column={column} title="Type" />,
        cell: ({ row }) => (
          <Badge variant="outline" className="font-mono">
            {row.original.type}
          </Badge>
        ),
      },
      {
        accessorKey: "value",
        header: ({ column }) => <SortHeader column={column} title="Valeur" />,
        cell: ({ row }) => (
          <span className="block max-w-[28rem] truncate font-mono text-xs" title={row.original.value}>
            {row.original.value}
          </span>
        ),
      },
      {
        id: "ttl",
        accessorFn: (r) => r.ttl ?? -1,
        header: ({ column }) => <SortHeader column={column} title="TTL" />,
        enableGlobalFilter: false,
        cell: ({ row }) =>
          row.original.ttl === null || row.original.ttl === undefined ? (
            <span className="text-muted-foreground">défaut</span>
          ) : (
            <span className="tabular-nums" title={humanDuration(row.original.ttl)}>
              {row.original.ttl}
            </span>
          ),
      },
      {
        id: "source",
        accessorFn: (r) => (r.source === "dhcp" ? "DHCP" : "manuel"),
        header: ({ column }) => <SortHeader column={column} title="Source" />,
        cell: ({ row }) =>
          row.original.source === "dhcp" ? (
            <Badge variant="secondary">DHCP</Badge>
          ) : (
            <span className="text-xs text-muted-foreground">manuel</span>
          ),
      },
      {
        id: "actions",
        enableSorting: false,
        enableGlobalFilter: false,
        cell: ({ row }) => {
          const r = row.original
          if (r.source === "dhcp")
            return (
              <div className="flex justify-end">
                <Tooltip>
                  <TooltipTrigger asChild>
                    <span className="inline-flex size-8 items-center justify-center text-muted-foreground" tabIndex={0}>
                      <Lock className="size-3.5" aria-label="Lecture seule" />
                    </span>
                  </TooltipTrigger>
                  <TooltipContent>Créé par le DHCP : lecture seule</TooltipContent>
                </Tooltip>
              </div>
            )
          if (!canRecords) return null
          return (
            <div className="flex justify-end gap-1">
              <Button
                variant="ghost"
                size="icon-sm"
                aria-label={`Modifier ${r.name} ${r.type}`}
                onClick={() => setEditing({ record: r })}
              >
                <Pencil />
              </Button>
              <Button
                variant="ghost"
                size="icon-sm"
                className="text-muted-foreground hover:text-destructive"
                aria-label={`Supprimer ${r.name} ${r.type}`}
                onClick={() => setDeleting(r)}
              >
                <Trash2 />
              </Button>
            </div>
          )
        },
      },
    ],
    [canRecords],
  )

  const all = records.data?.items
  const presentTypes = React.useMemo(() => new Set((all ?? []).map((r) => r.type)), [all])
  const data = React.useMemo(
    () => (all ?? []).filter((r) => typeFilter === "all" || r.type === typeFilter),
    [all, typeFilter],
  )

  if (zone.isPending) return <BlockSpinner />
  if (zone.isError) {
    const notFound = isApiError(zone.error, ProblemType.notFound)
    return (
      <EmptyState
        icon={Globe}
        title={notFound ? "Zone introuvable" : "Erreur"}
        description={notFound ? "Elle a peut-être été supprimée." : errorMessage(zone.error)}
        action={
          <Button asChild variant="outline">
            <Link to="/dns/zones">
              <ArrowLeft /> Retour aux zones
            </Link>
          </Button>
        }
      />
    )
  }

  const z = zone.data
  return (
    <>
      <Link
        to="/dns/zones"
        className="mb-3 inline-flex items-center gap-1 text-sm text-muted-foreground transition-colors hover:text-foreground"
      >
        <ArrowLeft className="size-4" /> Zones DNS
      </Link>
      <div className="mb-6 flex flex-col gap-3 sm:flex-row sm:items-end sm:justify-between">
        <div className="min-w-0 space-y-1.5">
          <h1 className="truncate text-2xl font-semibold tracking-tight">{z.name}</h1>
          <div className="flex flex-wrap items-center gap-2 text-sm text-muted-foreground">
            <ZoneKindBadge kind={z.kind} />
            {z.auto && <Badge variant="outline">auto</Badge>}
            <span>
              série <span className="font-mono">{z.serial ?? "—"}</span>
            </span>
            <span aria-hidden>·</span>
            <span>TTL par défaut {z.ttl !== undefined ? humanDuration(z.ttl) : "—"}</span>
          </div>
        </div>
        <div className="flex flex-wrap items-center gap-2">
          <Button variant="outline" onClick={exportZone} disabled={exporting}>
            <Download /> Exporter
          </Button>
          {perms.allowed("records.write") && (
            <WriteGuard>
              <Button variant="outline" onClick={() => setDialog("import")}>
                <Upload /> Importer
              </Button>
            </WriteGuard>
          )}
          {perms.allowed("config.write") && (
            <WriteGuard className="gap-2">
              <Button variant="outline" onClick={() => setDialog("settings")}>
                <Settings2 /> Paramètres
              </Button>
              <Button
                variant="outline"
                className="text-destructive hover:text-destructive"
                onClick={() => setDialog("delete")}
              >
                <Trash2 /> Supprimer la zone
              </Button>
            </WriteGuard>
          )}
        </div>
      </div>

      {records.isError && <p className="mb-3 text-sm text-destructive">{errorMessage(records.error)}</p>}
      <DataTable
        columns={columns}
        data={data}
        loading={records.isPending}
        getRowId={(r) => r.id ?? `${r.name}-${r.type}-${r.value}`}
        searchPlaceholder="Rechercher un nom, une valeur…"
        initialSorting={[{ id: "name", desc: false }]}
        empty={canRecords ? "Aucun enregistrement. Ajoutez-en un ou importez un fichier de zone." : "Aucun enregistrement."}
        toolbar={
          <>
            <Select value={typeFilter} onValueChange={(v) => setTypeFilter(v as "all" | RecordType)}>
              <SelectTrigger className="w-36" aria-label="Filtrer par type">
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="all">Tous les types</SelectItem>
                {recordTypes
                  .filter((t) => presentTypes.has(t))
                  .map((t) => (
                    <SelectItem key={t} value={t}>
                      {t}
                    </SelectItem>
                  ))}
              </SelectContent>
            </Select>
            {perms.allowed("records.write") && (
              <WriteGuard>
                <Button onClick={() => setEditing({ record: null })}>
                  <Plus /> Ajouter
                </Button>
              </WriteGuard>
            )}
          </>
        }
      />

      <RecordDialog
        zone={z}
        record={editing?.record ?? null}
        open={!!editing}
        onOpenChange={(o) => !o && setEditing(null)}
      />
      {deleting && (
        <ConfirmDialog
          open={!!deleting}
          onOpenChange={(o) => !o && setDeleting(null)}
          title={`Supprimer ${deleting.name} ${deleting.type} ?`}
          description={
            <>
              <span className="font-mono">{deleting.fqdn}</span> → <span className="font-mono">{deleting.value}</span>
            </>
          }
          confirmLabel="Supprimer"
          destructive
          onConfirm={() => remove.mutateAsync(deleting.id ?? "")}
        />
      )}
      <ZoneSettingsDialog zone={z} open={dialog === "settings"} onOpenChange={(o) => setDialog(o ? "settings" : null)} />
      <ZoneImportDialog zone={z} open={dialog === "import"} onOpenChange={(o) => setDialog(o ? "import" : null)} />
      <ZoneDeleteDialog
        zone={z}
        open={dialog === "delete"}
        onOpenChange={(o) => setDialog(o ? "delete" : null)}
        onDeleted={() => {
          setDialog(null)
          navigate("/dns/zones", { replace: true })
        }}
      />
    </>
  )
}
