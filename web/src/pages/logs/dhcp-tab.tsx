import { Link } from "react-router"
import { keepPreviousData, useInfiniteQuery, useQuery } from "@tanstack/react-query"
import { api } from "@/api/client"
import { logSettingsQuery, qk, scopesQuery } from "@/api/queries"
import type { DhcpLogEntry } from "@/api/types"
import { Badge } from "@/components/ui/badge"
import { Skeleton } from "@/components/ui/skeleton"
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table"
import { errorMessage } from "@/lib/errors"
import { dhcpEventClass, dhcpEventLabel, dhcpEventShort, dhcpEvents, periodRange } from "@/lib/logs"
import { cn } from "@/lib/utils"
import { LoadMore, PeriodFilter, TimeCell, UrlSelect, UrlTextFilter, useLogParams, usePeriod } from "./shared"

const COLS = 8

export function DhcpTab() {
  const [params, setParam] = useLogParams()
  const { period, from, to } = usePeriod(params)
  const filters = {
    q: params.get("q") ?? "",
    event: params.get("event") ?? "",
    scope: params.get("scope") ?? "",
    period,
    from: period === "custom" ? from : "",
    to: period === "custom" ? to : "",
  }
  const scopes = useQuery({ ...scopesQuery, refetchInterval: false })
  const settings = useQuery(logSettingsQuery)

  const logs = useInfiniteQuery({
    queryKey: qk.dhcpLogs(filters),
    queryFn: ({ pageParam, signal }) =>
      api.get("/logs/dhcp", {
        query: {
          q: filters.q || undefined,
          event: (filters.event || undefined) as DhcpLogEntry["event"],
          scope: filters.scope || undefined,
          ...periodRange(period, from, to),
          before: pageParam,
          limit: 100,
        },
        signal,
      }),
    initialPageParam: undefined as number | undefined,
    getNextPageParam: (last) => last.nextCursor ?? undefined,
    placeholderData: keepPreviousData,
  })

  const rows = logs.data?.pages.flatMap((p) => p.items ?? []) ?? []
  const filtered = !!(filters.q || filters.event || filters.scope) || period !== "1h"
  const loadMore = () => {
    if (!logs.isFetchingNextPage && logs.hasNextPage) void logs.fetchNextPage()
  }

  return (
    <div className="space-y-3">
      <div className="grid grid-cols-2 gap-2 sm:flex sm:flex-wrap sm:items-center">
        <UrlTextFilter name="q" params={params} setParam={setParam} placeholder="MAC, IP ou nom" label="Filtrer par MAC, IP ou nom" className="col-span-2 sm:w-60" />
        <UrlSelect
          name="event"
          params={params}
          setParam={setParam}
          label="Événement"
          allLabel="Tous les événements"
          className="col-span-2"
          options={dhcpEvents.map((e) => ({ value: e, label: dhcpEventLabel[e] }))}
        />
        <UrlSelect
          name="scope"
          params={params}
          setParam={setParam}
          label="Étendue"
          allLabel="Toutes les étendues"
          className="col-span-2"
          options={(scopes.data?.items ?? []).map((s) => ({ value: s.id ?? "", label: s.name ?? s.id ?? "" }))}
        />
        <PeriodFilter params={params} setParam={setParam} className="col-span-2" />
      </div>

      {settings.data && settings.data.dhcpEvents === false && (
        <p className="rounded-md border border-warning/50 bg-warning/10 px-3 py-2 text-sm" data-testid="dhcp-log-off">
          Le journal DHCP est désactivé : rien de nouveau n'est enregistré (voir « Conservation »).
        </p>
      )}

      <div className={cn("rounded-lg border transition-opacity", logs.isPlaceholderData && "opacity-60")} data-testid="dhcp-log">
        <Table>
          <TableHeader>
            <TableRow className="hover:bg-transparent">
              <TableHead>Heure</TableHead>
              <TableHead>Événement</TableHead>
              <TableHead>MAC</TableHead>
              <TableHead>IP</TableHead>
              <TableHead>Nom</TableHead>
              <TableHead>Étendue</TableHead>
              <TableHead>Interface / relais</TableHead>
              <TableHead>Détail</TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {logs.isPending ? (
              Array.from({ length: 6 }).map((_, i) => (
                <TableRow key={i}>
                  {Array.from({ length: COLS }).map((__, j) => (
                    <TableCell key={j}>
                      <Skeleton className="h-4 w-full max-w-24" />
                    </TableCell>
                  ))}
                </TableRow>
              ))
            ) : logs.isError && rows.length === 0 ? (
              <TableRow className="hover:bg-transparent">
                <TableCell colSpan={COLS} className="h-24 text-center text-destructive">
                  {errorMessage(logs.error)}
                </TableCell>
              </TableRow>
            ) : rows.length === 0 ? (
              <TableRow className="hover:bg-transparent">
                <TableCell colSpan={COLS} className="h-24 text-center text-muted-foreground">
                  {filtered ? "Aucun événement pour ces filtres." : "Aucun événement DHCP pour l'instant."}
                </TableCell>
              </TableRow>
            ) : (
              rows.map((e) => <DhcpRow key={e.id} e={e} />)
            )}
          </TableBody>
        </Table>
      </div>

      <LoadMore hasMore={!!logs.hasNextPage} loading={logs.isFetchingNextPage} onLoad={loadMore} auto count={rows.length} />
    </div>
  )
}

function DhcpRow({ e }: { e: DhcpLogEntry }) {
  return (
    <TableRow data-testid="dhcp-row">
      <TableCell className="text-xs">
        <TimeCell value={e.time} />
      </TableCell>
      <TableCell>
        {e.event && (
          <Badge variant="outline" className={dhcpEventClass[e.event]} title={dhcpEventLabel[e.event]}>
            {dhcpEventShort[e.event] ?? e.event}
          </Badge>
        )}
      </TableCell>
      <TableCell className="font-mono text-xs whitespace-nowrap">{e.mac || "—"}</TableCell>
      <TableCell className="font-mono text-xs whitespace-nowrap">{e.ip || "—"}</TableCell>
      <TableCell className="max-w-40 truncate" title={e.hostname}>
        {e.hostname || <span className="text-muted-foreground">—</span>}
      </TableCell>
      <TableCell className="whitespace-nowrap">
        {e.scopeId ? (
          <Link to={`/dhcp/leases?scope=${encodeURIComponent(e.scopeId)}`} className="hover:underline">
            {e.scopeName || e.scopeId}
          </Link>
        ) : (
          <span className="text-muted-foreground">—</span>
        )}
      </TableCell>
      <TableCell className="text-xs whitespace-nowrap">
        {e.interface || "—"}
        {e.relay && <span className="ml-1 font-mono text-muted-foreground">via {e.relay}</span>}
      </TableCell>
      <TableCell className="max-w-64 truncate text-xs text-muted-foreground" title={e.detail}>
        {e.detail || "—"}
      </TableCell>
    </TableRow>
  )
}
