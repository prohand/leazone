import * as React from "react"
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query"
import { ChevronRight, RotateCcw, TriangleAlert, X } from "lucide-react"
import { toast } from "sonner"
import { api } from "@/api/client"
import { clusterConflictsQuery, qk } from "@/api/queries"
import type { Conflict } from "@/api/types"
import { ConfirmDialog } from "@/components/confirm-dialog"
import { BlockSpinner } from "@/components/spinner"
import { Badge } from "@/components/ui/badge"
import { Button } from "@/components/ui/button"
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table"
import { errorMessage } from "@/lib/errors"
import { formatDateTime } from "@/lib/format"
import { cn } from "@/lib/utils"

const opLabel: Record<string, string> = { upsert: "ajout / modification", delete: "suppression" }
const statusLabel: Record<string, { label: string; className: string }> = {
  pending: { label: "en attente", className: "border-warning/50 text-warning" },
  reapplied: { label: "réappliquée", className: "border-success/40 text-success" },
  dismissed: { label: "ignorée", className: "text-muted-foreground" },
}

function pretty(row?: string): string {
  if (!row) return ""
  try {
    return JSON.stringify(JSON.parse(row), null, 2)
  } catch {
    return row
  }
}

type Pending = { kind: "reapply" | "dismiss"; c: Conflict } | null

/** Changes lost by this node as a former primary (never applied automatically). */
export function ConflictsCard({ pending, isAdmin, onClose }: { pending: number; isAdmin: boolean; onClose?: () => void }) {
  const qc = useQueryClient()
  const list = useQuery({ ...clusterConflictsQuery, enabled: isAdmin, refetchInterval: 10_000 })
  const [open, setOpen] = React.useState<Record<string, boolean>>({})
  const [confirm, setConfirm] = React.useState<Pending>(null)

  const refresh = () => {
    void qc.invalidateQueries({ queryKey: qk.clusterConflicts })
    void qc.invalidateQueries({ queryKey: qk.cluster, exact: true })
  }
  const reapply = useMutation({
    mutationFn: (id: string) => api.post("/cluster/conflicts/{id}/reapply", { params: { id } }),
    onSuccess: (v) => {
      if (v) qc.setQueryData(qk.cluster, v)
      refresh()
      toast.success("Modification réappliquée sur le primaire.")
    },
  })
  const dismiss = useMutation({
    mutationFn: (id: string) => api.delete("/cluster/conflicts/{id}", { params: { id } }),
    onSuccess: () => {
      refresh()
      toast.success("Conflit ignoré.")
    },
  })

  const items = list.data?.items ?? []
  return (
    <Card className="gap-3 border-warning/50" data-testid="conflicts-card">
      <CardHeader className="flex flex-row items-start justify-between gap-3">
        <div className="space-y-1.5">
          <CardTitle className="flex items-center gap-2">
            <TriangleAlert className="size-4 text-warning" />
            Conflits
            {pending > 0 && (
              <Badge variant="outline" className="border-warning/50 text-warning">
                {pending} en attente
              </Badge>
            )}
          </CardTitle>
          <CardDescription>
            Modifications faites sur ce nœud pendant qu'il était primaire mais jamais transmises avant la bascule. Elles ne sont
            pas appliquées automatiquement.
          </CardDescription>
        </div>
        {onClose && (
          <Button variant="ghost" size="icon-sm" onClick={onClose} aria-label="Masquer les conflits">
            <X />
          </Button>
        )}
      </CardHeader>
      <CardContent>
        {!isAdmin ? (
          <p className="text-sm text-muted-foreground">Un administrateur peut les examiner et les réappliquer.</p>
        ) : list.isPending ? (
          <BlockSpinner />
        ) : list.isError ? (
          <p className="text-sm text-destructive">{errorMessage(list.error)}</p>
        ) : items.length === 0 ? (
          <p className="text-sm text-muted-foreground">Aucun conflit.</p>
        ) : (
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>Table</TableHead>
                <TableHead>Clé</TableHead>
                <TableHead>Opération</TableHead>
                <TableHead>Détectée</TableHead>
                <TableHead>Statut</TableHead>
                <TableHead className="text-right">
                  <span className="sr-only">Actions</span>
                </TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {items.map((c) => {
                const id = c.id ?? ""
                const st = statusLabel[c.status ?? ""] ?? { label: c.status ?? "", className: "" }
                const expanded = !!open[id]
                return (
                  <React.Fragment key={id}>
                    <TableRow className={cn(expanded && "border-b-0")}>
                      <TableCell>
                        <button
                          type="button"
                          className="inline-flex items-center gap-1 font-mono text-xs hover:underline"
                          aria-expanded={expanded}
                          onClick={() => setOpen({ ...open, [id]: !expanded })}
                        >
                          <ChevronRight className={cn("size-3.5 transition-transform", expanded && "rotate-90")} />
                          {c.table}
                        </button>
                      </TableCell>
                      <TableCell className="max-w-48 truncate font-mono text-xs" title={c.pk}>
                        {c.pk}
                      </TableCell>
                      <TableCell className={cn("text-xs", c.op === "delete" && "text-destructive")}>{opLabel[c.op ?? ""] ?? c.op}</TableCell>
                      <TableCell className="text-xs text-muted-foreground">{formatDateTime(c.detectedAt)}</TableCell>
                      <TableCell>
                        <Badge variant="outline" className={st.className}>
                          {st.label}
                        </Badge>
                      </TableCell>
                      <TableCell>
                        {c.status === "pending" && (
                          <div className="flex justify-end gap-1">
                            <Button size="sm" variant="outline" onClick={() => setConfirm({ kind: "reapply", c })}>
                              <RotateCcw /> Réappliquer
                            </Button>
                            <Button size="sm" variant="ghost" onClick={() => setConfirm({ kind: "dismiss", c })}>
                              Ignorer
                            </Button>
                          </div>
                        )}
                      </TableCell>
                    </TableRow>
                    {expanded && (
                      <TableRow className="hover:bg-transparent">
                        <TableCell colSpan={6} className="pt-0">
                          <div className="mb-1 text-xs text-muted-foreground">
                            Mandat {c.epoch} · version {c.seq}
                          </div>
                          <pre className="max-h-64 max-w-full overflow-auto rounded-md bg-muted p-3 font-mono text-xs whitespace-pre-wrap break-all">
                            {pretty(c.row) || "(aucune donnée)"}
                          </pre>
                        </TableCell>
                      </TableRow>
                    )}
                  </React.Fragment>
                )
              })}
            </TableBody>
          </Table>
        )}
      </CardContent>
      <ConfirmDialog
        open={confirm?.kind === "reapply"}
        onOpenChange={(o) => !o && setConfirm(null)}
        title="Réappliquer cette modification ?"
        description={
          <>
            La modification de <strong>{confirm?.c.table}</strong> ({confirm?.c.pk}) sera appliquée sur le primaire et copiée
            sur tous les nœuds. Elle peut remplacer une modification plus récente : vérifiez son contenu avant.
          </>
        }
        confirmLabel="Réappliquer"
        onConfirm={() => reapply.mutateAsync(confirm?.c.id ?? "")}
      />
      <ConfirmDialog
        open={confirm?.kind === "dismiss"}
        onOpenChange={(o) => !o && setConfirm(null)}
        destructive
        title="Ignorer ce conflit ?"
        description="La modification perdue ne sera pas appliquée. Elle reste visible dans la liste comme « ignorée »."
        confirmLabel="Ignorer"
        onConfirm={() => dismiss.mutateAsync(confirm?.c.id ?? "")}
      />
    </Card>
  )
}
