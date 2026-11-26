import * as React from "react"
import { useInfiniteQuery } from "@tanstack/react-query"
import { Info, Loader2, Lock, Search } from "lucide-react"
import { api } from "@/api/client"
import { qk } from "@/api/queries"
import type { AuditEntry } from "@/api/types"
import { EmptyState } from "@/components/empty-state"
import { Badge } from "@/components/ui/badge"
import { Button } from "@/components/ui/button"
import { Input } from "@/components/ui/input"
import { Popover, PopoverContent, PopoverTrigger } from "@/components/ui/popover"
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select"
import { Skeleton } from "@/components/ui/skeleton"
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table"
import { useDebounced } from "@/hooks/use-debounced"
import { useCurrentUser } from "@/hooks/use-session"
import { errorMessage } from "@/lib/errors"
import { formatDateTime } from "@/lib/format"
import { can } from "@/lib/permissions"

const actionFilters = [
  { value: "all", label: "Toutes les actions" },
  { value: "auth.", label: "Connexions (auth.)" },
  { value: "user.", label: "Utilisateurs (user.)" },
  { value: "passkey.", label: "Passkeys (passkey.)" },
  { value: "settings.", label: "Paramètres (settings.)" },
]

export function AuditTab() {
  const user = useCurrentUser()
  const [q, setQ] = React.useState("")
  const [action, setAction] = React.useState("all")
  const search = useDebounced(q.trim(), 300)
  const prefix = action === "all" ? "" : action
  const isAdmin = can(user?.role, "admin")

  const audit = useInfiniteQuery({
    queryKey: qk.audit(search, prefix),
    queryFn: ({ pageParam, signal }) =>
      api.get("/audit", {
        query: { limit: 50, cursor: pageParam || undefined, q: search || undefined, action: prefix || undefined },
        signal,
      }),
    initialPageParam: "",
    getNextPageParam: (last) => last.nextCursor || undefined,
    enabled: isAdmin,
  })

  if (!isAdmin) {
    return <EmptyState icon={Lock} title="Réservé aux administrateurs" description="Le journal d'audit n'est visible que par les administrateurs." />
  }

  const rows = audit.data?.pages.flatMap((p) => p.items ?? []) ?? []

  return (
    <div className="space-y-3">
      <div className="flex flex-col gap-2 sm:flex-row sm:items-center">
        <div className="relative sm:max-w-xs sm:flex-1">
          <Search className="pointer-events-none absolute top-1/2 left-2.5 size-4 -translate-y-1/2 text-muted-foreground" />
          <Input
            value={q}
            onChange={(e) => setQ(e.target.value)}
            placeholder="Acteur, action, cible…"
            className="pl-8"
            aria-label="Rechercher dans le journal"
          />
        </div>
        <Select value={action} onValueChange={setAction}>
          <SelectTrigger className="w-full sm:w-56" aria-label="Filtrer par action">
            <SelectValue />
          </SelectTrigger>
          <SelectContent>
            {actionFilters.map((f) => (
              <SelectItem key={f.value} value={f.value}>
                {f.label}
              </SelectItem>
            ))}
          </SelectContent>
        </Select>
      </div>

      <div className="rounded-lg border">
        <Table>
          <TableHeader>
            <TableRow className="hover:bg-transparent">
              <TableHead>Date</TableHead>
              <TableHead>Acteur</TableHead>
              <TableHead>Action</TableHead>
              <TableHead>Cible</TableHead>
              <TableHead>Adresse IP</TableHead>
              <TableHead>Résultat</TableHead>
              <TableHead />
            </TableRow>
          </TableHeader>
          <TableBody>
            {audit.isPending ? (
              Array.from({ length: 5 }).map((_, i) => (
                <TableRow key={i}>
                  {Array.from({ length: 7 }).map((__, j) => (
                    <TableCell key={j}>
                      <Skeleton className="h-4 w-full max-w-28" />
                    </TableCell>
                  ))}
                </TableRow>
              ))
            ) : audit.isError ? (
              <TableRow className="hover:bg-transparent">
                <TableCell colSpan={7} className="h-24 text-center text-destructive">
                  {errorMessage(audit.error)}
                </TableCell>
              </TableRow>
            ) : rows.length === 0 ? (
              <TableRow className="hover:bg-transparent">
                <TableCell colSpan={7} className="h-24 text-center text-muted-foreground">
                  Aucune entrée.
                </TableCell>
              </TableRow>
            ) : (
              rows.map((e) => <AuditRow key={e.id} entry={e} />)
            )}
          </TableBody>
        </Table>
      </div>

      <div className="flex items-center justify-between">
        <p className="text-xs text-muted-foreground">
          {rows.length} entrée{rows.length > 1 ? "s" : ""}
        </p>
        {audit.hasNextPage && (
          <Button variant="outline" onClick={() => audit.fetchNextPage()} disabled={audit.isFetchingNextPage}>
            {audit.isFetchingNextPage && <Loader2 className="animate-spin" />}
            Charger plus
          </Button>
        )}
      </div>
    </div>
  )
}

function AuditRow({ entry: e }: { entry: AuditEntry }) {
  const hasDetails = e.details && Object.keys(e.details).length > 0
  return (
    <TableRow>
      <TableCell className="whitespace-nowrap">{formatDateTime(e.ts)}</TableCell>
      <TableCell className="font-medium">{e.actor || "—"}</TableCell>
      <TableCell className="font-mono text-xs">{e.action}</TableCell>
      <TableCell className="max-w-48 truncate" title={e.target}>
        {e.target || "—"}
      </TableCell>
      <TableCell className="font-mono text-xs">{e.ip || "—"}</TableCell>
      <TableCell>
        {e.result === "failure" ? (
          <Badge variant="destructive">Échec</Badge>
        ) : (
          <Badge variant="secondary">Succès</Badge>
        )}
      </TableCell>
      <TableCell className="text-right">
        {hasDetails && (
          <Popover>
            <PopoverTrigger asChild>
              <Button variant="ghost" size="icon-sm" aria-label="Détails">
                <Info />
              </Button>
            </PopoverTrigger>
            <PopoverContent align="end" className="w-80">
              <pre className="max-h-64 overflow-auto font-mono text-xs whitespace-pre-wrap">
                {JSON.stringify(e.details, null, 2)}
              </pre>
            </PopoverContent>
          </Popover>
        )}
      </TableCell>
    </TableRow>
  )
}
