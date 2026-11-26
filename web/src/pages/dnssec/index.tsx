import * as React from "react"
import { Link, useNavigate } from "react-router"
import { useQuery } from "@tanstack/react-query"
import type { ColumnDef } from "@tanstack/react-table"
import { ShieldCheck } from "lucide-react"
import { dnssecZonesQuery } from "@/api/queries"
import type { DnssecZone } from "@/api/types"
import { DataTable, SortHeader } from "@/components/data-table"
import { EmptyState } from "@/components/empty-state"
import { PageHeader } from "@/components/page-header"
import { Badge } from "@/components/ui/badge"
import { DsPendingBadge, SignedBadge } from "./badges"
import { Button } from "@/components/ui/button"
import { useCurrentUser } from "@/hooks/use-session"
import { algorithmLabel, nsecLabel } from "@/lib/dnssec"
import { errorMessage } from "@/lib/errors"
import { formatDateTime, formatRelativeShort } from "@/lib/format"
import { useModules } from "@/lib/modules"
import { can } from "@/lib/permissions"

export default function DnssecPage() {
  const navigate = useNavigate()
  const list = useQuery(dnssecZonesQuery)
  const modules = useModules()
  const user = useCurrentUser()

  const columns = React.useMemo<ColumnDef<DnssecZone, unknown>[]>(
    () => [
      {
        accessorKey: "name",
        header: ({ column }) => <SortHeader column={column} title="Zone" />,
        cell: ({ row }) => <span className="font-medium">{row.original.name}</span>,
      },
      {
        id: "state",
        accessorFn: (z) => (z.enabled ? "signée" : "non signée"),
        header: ({ column }) => <SortHeader column={column} title="État" />,
        cell: ({ row }) => (
          <div className="flex flex-wrap items-center gap-1.5">
            <SignedBadge enabled={row.original.enabled} />
            {row.original.enabled && row.original.dsPending && <DsPendingBadge />}
          </div>
        ),
      },
      {
        id: "algorithm",
        accessorFn: (z) => (z.enabled ? algorithmLabel(z.algorithm) : ""),
        header: ({ column }) => <SortHeader column={column} title="Algorithme" />,
        cell: ({ row }) => (row.original.enabled ? algorithmLabel(row.original.algorithm) : <span className="text-muted-foreground">—</span>),
      },
      {
        id: "nsec",
        accessorFn: (z) => (z.enabled && z.nsecMode ? nsecLabel[z.nsecMode] : ""),
        header: ({ column }) => <SortHeader column={column} title="Preuve d'absence" />,
        cell: ({ getValue }) => (getValue() ? <Badge variant="outline">{String(getValue())}</Badge> : <span className="text-muted-foreground">—</span>),
      },
      {
        id: "next",
        accessorFn: (z) => (z.enabled ? (z.nextZskRollover ?? "") : ""),
        enableGlobalFilter: false,
        header: ({ column }) => <SortHeader column={column} title="Prochain changement de ZSK" />,
        cell: ({ row }) =>
          row.original.enabled && row.original.nextZskRollover ? (
            <span title={formatDateTime(row.original.nextZskRollover)}>{formatRelativeShort(row.original.nextZskRollover)}</span>
          ) : (
            <span className="text-muted-foreground">—</span>
          ),
      },
    ],
    [],
  )

  const items = list.data?.items ?? []
  return (
    <>
      <PageHeader
        title="DNSSEC"
        description="Signature des zones : les résolveurs qui valident peuvent vérifier que les réponses viennent bien de vous."
      />
      <p className="mb-4 text-sm text-muted-foreground">
        Validation des réponses des redirecteurs :{" "}
        <span className={modules.dnssecValidation ? "font-medium text-success" : "font-medium"}>
          {modules.dnssecValidation ? "activée" : "désactivée"}
        </span>
        {can(user?.role, "admin") && (
          <>
            {" "}
            ·{" "}
            <Link to="/settings?tab=modules" className="text-brand hover:underline">
              Modules
            </Link>
          </>
        )}
      </p>
      {list.isError && <p className="mb-3 text-sm text-destructive">{errorMessage(list.error)}</p>}
      {!list.isPending && !list.isError && items.length === 0 ? (
        <EmptyState
          icon={ShieldCheck}
          title="Aucune zone directe"
          description="DNSSEC signe les zones directes (ex. : maison.lan). Créez-en une d'abord."
          action={
            <Button asChild variant="outline">
              <Link to="/dns/zones">Zones DNS</Link>
            </Button>
          }
        />
      ) : (
        <DataTable
          columns={columns}
          data={items}
          loading={list.isPending}
          getRowId={(z) => z.zoneId ?? z.name ?? ""}
          searchPlaceholder="Rechercher une zone…"
          initialSorting={[{ id: "name", desc: false }]}
          onRowClick={(z) => navigate(`/dnssec/${encodeURIComponent(z.zoneId ?? "")}`)}
        />
      )}
    </>
  )
}
