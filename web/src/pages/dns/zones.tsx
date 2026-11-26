import * as React from "react"
import { useNavigate, useSearchParams } from "react-router"
import { useQuery } from "@tanstack/react-query"
import type { ColumnDef } from "@tanstack/react-table"
import { Globe, Plus, SearchCheck } from "lucide-react"
import { zonesQuery } from "@/api/queries"
import type { Zone } from "@/api/types"
import { DataTable, SortHeader } from "@/components/data-table"
import { useDnsLookup } from "@/components/dns-lookup"
import { EmptyState } from "@/components/empty-state"
import { PageHeader } from "@/components/page-header"
import { Badge } from "@/components/ui/badge"
import { Button } from "@/components/ui/button"
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select"
import { WriteGuard } from "@/components/read-only"
import { usePermissions } from "@/hooks/use-cluster"
import { errorMessage } from "@/lib/errors"
import { formatDateTime, formatRelative } from "@/lib/format"
import { CacheFlushPopover } from "./cache-flush"
import { ZoneCreateDialog } from "./zone-dialogs"

export function ZoneKindBadge({ kind }: { kind?: Zone["kind"] }) {
  return kind === "reverse" ? <Badge variant="secondary">inverse</Badge> : <Badge variant="outline">direct</Badge>
}

export default function ZonesPage() {
  const navigate = useNavigate()
  const [params, setParams] = useSearchParams()
  const perms = usePermissions()
  const canConfig = perms.can("config.write")
  const { openLookup } = useDnsLookup()
  const list = useQuery(zonesQuery)
  const [kind, setKind] = React.useState<"all" | "primary" | "reverse">("all")
  const [creating, setCreating] = React.useState(false)

  // ⌘K "Nouvelle zone DNS" lands here with ?new=1.
  React.useEffect(() => {
    if (params.get("new") === "1") {
      if (canConfig) setCreating(true)
      setParams({}, { replace: true })
    }
  }, [params, setParams, canConfig])

  const columns = React.useMemo<ColumnDef<Zone, unknown>[]>(
    () => [
      {
        accessorKey: "name",
        header: ({ column }) => <SortHeader column={column} title="Nom" />,
        cell: ({ row }) => <span className="font-medium">{row.original.name}</span>,
      },
      {
        id: "kind",
        accessorFn: (z) => (z.kind === "reverse" ? "inverse" : "direct"),
        header: ({ column }) => <SortHeader column={column} title="Type" />,
        cell: ({ row }) => (
          <div className="flex items-center gap-1.5">
            <ZoneKindBadge kind={row.original.kind} />
            {row.original.auto && (
              <Badge variant="outline" className="text-muted-foreground" title="Créée à partir d'une étendue DHCP">
                auto
              </Badge>
            )}
          </div>
        ),
      },
      {
        accessorKey: "recordCount",
        header: ({ column }) => <SortHeader column={column} title="Enregistrements" />,
        enableGlobalFilter: false,
        cell: ({ row }) => <span className="tabular-nums">{row.original.recordCount ?? 0}</span>,
      },
      {
        accessorKey: "serial",
        header: ({ column }) => <SortHeader column={column} title="Série" />,
        enableGlobalFilter: false,
        cell: ({ row }) => <span className="font-mono text-xs text-muted-foreground">{row.original.serial ?? "—"}</span>,
      },
      {
        id: "updatedAt",
        accessorFn: (z) => (z.updatedAt ? new Date(z.updatedAt).getTime() : 0),
        header: ({ column }) => <SortHeader column={column} title="Modifiée" />,
        enableGlobalFilter: false,
        cell: ({ row }) => (
          <span className="text-muted-foreground" title={formatDateTime(row.original.updatedAt)}>
            {formatRelative(row.original.updatedAt)}
          </span>
        ),
      },
    ],
    [],
  )

  const all = list.data?.items
  const data = React.useMemo(
    () => (all ?? []).filter((z) => kind === "all" || (z.kind ?? "primary") === kind),
    [all, kind],
  )
  const empty = !list.isPending && !list.isError && (all ?? []).length === 0

  return (
    <>
      <PageHeader
        title="Zones DNS"
        description="Domaines que Leazone sert lui-même. Les autres noms partent vers les redirecteurs."
        actions={
          <>
            <Button variant="outline" onClick={() => openLookup()}>
              <SearchCheck /> Tester une résolution
            </Button>
            {perms.can("cache.flush") && <CacheFlushPopover />}
            {perms.allowed("config.write") && (
              <WriteGuard>
                <Button onClick={() => setCreating(true)}>
                  <Plus /> Nouvelle zone
                </Button>
              </WriteGuard>
            )}
          </>
        }
      />
      {list.isError && <p className="mb-3 text-sm text-destructive">{errorMessage(list.error)}</p>}
      {empty ? (
        <EmptyState
          icon={Globe}
          title="Aucune zone"
          description="Créez une zone (ex. : maison.lan) pour donner des noms aux appareils de votre réseau."
          action={
            canConfig && (
              <Button onClick={() => setCreating(true)}>
                <Plus /> Nouvelle zone
              </Button>
            )
          }
        />
      ) : (
        <DataTable
          columns={columns}
          data={data}
          loading={list.isPending}
          getRowId={(z) => z.id ?? z.name ?? ""}
          searchPlaceholder="Rechercher une zone…"
          initialSorting={[{ id: "name", desc: false }]}
          empty="Aucune zone de ce type."
          onRowClick={(z) => z.id && navigate(`/dns/zones/${encodeURIComponent(z.id)}`)}
          toolbar={
            <Select value={kind} onValueChange={(v) => setKind(v as typeof kind)}>
              <SelectTrigger className="w-40" aria-label="Filtrer par type">
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="all">Toutes les zones</SelectItem>
                <SelectItem value="primary">Directes</SelectItem>
                <SelectItem value="reverse">Inverses</SelectItem>
              </SelectContent>
            </Select>
          }
        />
      )}
      <ZoneCreateDialog
        open={creating}
        onOpenChange={setCreating}
        onCreated={(z) => {
          setCreating(false)
          if (z.id) navigate(`/dns/zones/${encodeURIComponent(z.id)}`)
        }}
      />
    </>
  )
}
