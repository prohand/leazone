import * as React from "react"
import { keepPreviousData, useInfiniteQuery, useQuery, useQueryClient, type InfiniteData } from "@tanstack/react-query"
import { Ban, Filter, MoreHorizontal, Radio, TextSearch } from "lucide-react"
import { api, type ApiResponse } from "@/api/client"
import { logSettingsQuery, qk } from "@/api/queries"
import type { DnsLogEntry } from "@/api/types"
import { ConfirmDialog } from "@/components/confirm-dialog"
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
import { Label } from "@/components/ui/label"
import { Skeleton } from "@/components/ui/skeleton"
import { Switch } from "@/components/ui/switch"
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table"
import { usePermissions } from "@/hooks/use-cluster"
import { cleanDomain, useAddRule } from "@/lib/blocking"
import { errorMessage } from "@/lib/errors"
import { dnsSourceClass, dnsSourceLabel, dnsSources, periodRange, queryTypes, rcodeClass, rcodes } from "@/lib/logs"
import { useModules } from "@/lib/modules"
import { cn } from "@/lib/utils"
import { LoadMore, PeriodFilter, TimeCell, UrlSelect, UrlTextFilter, useLogParams, usePeriod } from "./shared"

type Page = ApiResponse<"/logs/dns", "get">
const COLS = 9

export function DnsTab() {
  const qc = useQueryClient()
  const [params, setParam] = useLogParams()
  const { period, from, to } = usePeriod(params)
  const live = params.get("live") === "1"
  const filters = {
    q: params.get("q") ?? "",
    client: params.get("client") ?? "",
    type: params.get("type") ?? "",
    rcode: params.get("rcode") ?? "",
    source: params.get("source") ?? "",
    period,
    from: period === "custom" ? from : "",
    to: period === "custom" ? to : "",
  }
  const key = qk.dnsLogs(filters)

  const logs = useInfiniteQuery({
    queryKey: key,
    queryFn: ({ pageParam, signal }) =>
      api.get("/logs/dns", {
        query: {
          q: filters.q || undefined,
          client: filters.client || undefined,
          type: filters.type || undefined,
          rcode: filters.rcode || undefined,
          source: (filters.source || undefined) as DnsLogEntry["source"],
          ...periodRange(period, from, to),
          before: pageParam,
          limit: 100,
        },
        signal,
      }),
    initialPageParam: undefined as number | undefined,
    getNextPageParam: (last) => last.nextCursor ?? undefined,
    placeholderData: keepPreviousData,
    // "Suivre en direct": the first page again every 2 s.
    refetchInterval: live ? 2_000 : false,
  })

  // Following live keeps only the first page (refetching older pages is useless).
  React.useEffect(() => {
    if (!live) return
    qc.setQueryData<InfiniteData<Page, number | undefined>>(key, (d) =>
      d && d.pages.length > 1 ? { pages: d.pages.slice(0, 1), pageParams: d.pageParams.slice(0, 1) } : d,
    )
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [live, JSON.stringify(filters)])

  const settings = useQuery(logSettingsQuery)
  const rows = logs.data?.pages.flatMap((p) => p.items ?? []) ?? []
  const loadMore = () => {
    if (logs.isFetchingNextPage || !logs.hasNextPage) return
    if (live) setParam({ live: undefined })
    void logs.fetchNextPage()
  }
  const filtered = Object.entries(filters).some(([k, v]) => v && k !== "period") || period !== "1h"

  return (
    <div className="space-y-3">
      <div className="grid grid-cols-2 gap-2 sm:flex sm:flex-wrap sm:items-center">
        <UrlTextFilter name="q" params={params} setParam={setParam} placeholder="Nom (ex. : google)" label="Filtrer par nom" className="col-span-2 sm:w-56" mono />
        <UrlTextFilter
          name="client"
          params={params}
          setParam={setParam}
          placeholder="Client (IP ou réseau)"
          label="Filtrer par client"
          className="col-span-2 sm:w-60"
          mono
        />
        <UrlSelect name="type" params={params} setParam={setParam} label="Type" allLabel="Tous types" options={queryTypes.map((t) => ({ value: t, label: t }))} />
        <UrlSelect
          name="rcode"
          params={params}
          setParam={setParam}
          label="Réponse"
          allLabel="Toutes réponses"
          options={rcodes.map((r) => ({ value: r, label: r }))}
        />
        <UrlSelect
          name="source"
          params={params}
          setParam={setParam}
          label="Source"
          allLabel="Toutes sources"
          options={dnsSources.map((s) => ({ value: s, label: dnsSourceLabel[s] }))}
        />
        <PeriodFilter params={params} setParam={setParam} />
        <div className="flex items-center gap-2 sm:ml-auto">
          <Switch id="dns-live" checked={live} onCheckedChange={(v) => setParam({ live: v ? "1" : undefined })} />
          <Label htmlFor="dns-live" className="font-normal whitespace-nowrap">
            Suivre en direct
          </Label>
          {live && <Radio className="size-4 animate-pulse text-success motion-reduce:animate-none" aria-hidden />}
        </div>
      </div>

      {settings.data && settings.data.dnsQueries === false && (
        <p className="rounded-md border border-warning/50 bg-warning/10 px-3 py-2 text-sm" data-testid="dns-log-off">
          Le journal des requêtes DNS est désactivé : rien de nouveau n'est enregistré (voir « Conservation »).
        </p>
      )}

      <div className={cn("rounded-lg border transition-opacity", logs.isPlaceholderData && "opacity-60")} data-testid="dns-log">
        <Table>
          <TableHeader>
            <TableRow className="hover:bg-transparent">
              <TableHead>Heure</TableHead>
              <TableHead>Client</TableHead>
              <TableHead>Nom</TableHead>
              <TableHead>Type</TableHead>
              <TableHead>Réponse</TableHead>
              <TableHead>Source</TableHead>
              <TableHead className="text-right">Latence</TableHead>
              <TableHead>Première réponse</TableHead>
              <TableHead>
                <span className="sr-only">Actions</span>
              </TableHead>
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
                  {filtered ? "Aucune requête pour ces filtres." : "Aucune requête pour l'instant."}
                </TableCell>
              </TableRow>
            ) : (
              rows.map((e) => <DnsRow key={e.id} e={e} onFilter={setParam} />)
            )}
          </TableBody>
        </Table>
      </div>

      <LoadMore hasMore={!!logs.hasNextPage} loading={logs.isFetchingNextPage} onLoad={loadMore} auto={!live} count={rows.length} />
    </div>
  )
}

function DnsRow({ e, onFilter }: { e: DnsLogEntry; onFilter: (p: Record<string, string | undefined>) => void }) {
  const perms = usePermissions()
  const modules = useModules()
  const addRule = useAddRule()
  const [confirmBlock, setConfirmBlock] = React.useState(false)
  // Single-label names ("com.", "lan.") are never offered: that would block a whole TLD.
  const domain = cleanDomain(e.name ?? "", { multiLabel: true })
  const canBlock = modules.blocking && perms.can("records.write") && !!domain && e.source !== "blocked"
  return (
    <TableRow data-testid="dns-row">
      <TableCell className="text-xs">
        <TimeCell value={e.time} />
      </TableCell>
      <TableCell className="font-mono text-xs whitespace-nowrap">{e.client || "—"}</TableCell>
      <TableCell className="max-w-72 truncate font-mono text-xs" title={e.name}>
        {e.name}
      </TableCell>
      <TableCell className="text-xs">{e.type}</TableCell>
      <TableCell>
        {e.rcode && (
          <Badge variant="outline" className={cn("font-mono text-[11px]", rcodeClass(e.rcode))}>
            {e.rcode}
          </Badge>
        )}
      </TableCell>
      <TableCell>
        {e.source && (
          <Badge variant="outline" className={dnsSourceClass[e.source]}>
            {dnsSourceLabel[e.source] ?? e.source}
          </Badge>
        )}
      </TableCell>
      <TableCell className="text-right text-xs whitespace-nowrap tabular-nums">
        {typeof e.latencyMs === "number" ? `${e.latencyMs.toLocaleString("fr-FR", { maximumFractionDigits: e.latencyMs < 10 ? 1 : 0 })} ms` : "—"}
      </TableCell>
      <TableCell className="max-w-56 truncate font-mono text-xs text-muted-foreground" title={e.answer}>
        {e.answer || "—"}
      </TableCell>
      <TableCell className="text-right">
        <DropdownMenu>
          <DropdownMenuTrigger asChild>
            <Button variant="ghost" size="icon-sm" aria-label={`Actions pour ${e.name}`}>
              <MoreHorizontal />
            </Button>
          </DropdownMenuTrigger>
          <DropdownMenuContent align="end" className="w-60">
            <DropdownMenuLabel className="truncate font-mono text-xs">{e.name}</DropdownMenuLabel>
            <DropdownMenuSeparator />
            <DropdownMenuItem onSelect={() => onFilter({ client: e.client })} disabled={!e.client}>
              <Filter /> Filtrer sur ce client
            </DropdownMenuItem>
            <DropdownMenuItem onSelect={() => onFilter({ q: (e.name ?? "").replace(/\.$/, "") })}>
              <TextSearch /> Filtrer sur ce nom
            </DropdownMenuItem>
            {canBlock && (
              <>
                <DropdownMenuSeparator />
                <DropdownMenuItem variant="destructive" onSelect={() => setConfirmBlock(true)}>
                  <Ban /> Bloquer ce domaine…
                </DropdownMenuItem>
              </>
            )}
          </DropdownMenuContent>
        </DropdownMenu>
        {canBlock && confirmBlock && (
          <ConfirmDialog
            open={confirmBlock}
            onOpenChange={setConfirmBlock}
            title={`Bloquer ${domain} ?`}
            description={
              <>
                Le domaine <span className="font-mono break-all">{domain}</span> et tous ses sous-domaines (
                <span className="font-mono break-all">*.{domain}</span>) seront ajoutés à la liste noire : ils recevront une réponse vide pour
                tous les clients concernés par le blocage. Vous pourrez le retirer dans Blocage › Liste noire.
              </>
            }
            confirmLabel="Bloquer"
            destructive
            onConfirm={() => addRule.mutateAsync({ domain: domain!, kind: "deny" })}
          />
        )}
      </TableCell>
    </TableRow>
  )
}
