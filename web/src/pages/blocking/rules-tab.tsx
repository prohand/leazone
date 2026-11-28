import * as React from "react"
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query"
import type { ColumnDef } from "@tanstack/react-table"
import { Loader2, Plus, Trash2 } from "lucide-react"
import { toast } from "sonner"
import { api } from "@/api/client"
import { blockRulesQuery, qk } from "@/api/queries"
import type { BlockRule, BlockRuleKind } from "@/api/types"
import { ConfirmDialog } from "@/components/confirm-dialog"
import { DataTable, SortHeader } from "@/components/data-table"
import { FormError } from "@/components/form-field"
import { WriteGuard } from "@/components/read-only"
import { Button } from "@/components/ui/button"
import { Input } from "@/components/ui/input"
import { Label } from "@/components/ui/label"
import { usePermissions } from "@/hooks/use-cluster"
import { cleanDomain, useAddRule } from "@/lib/blocking"
import { errorMessage, fieldError } from "@/lib/errors"
import { formatDateTime, formatRelative } from "@/lib/format"

const text: Record<BlockRuleKind, { hint: string; empty: string; placeholder: string }> = {
  deny: {
    hint: "Bloque aussi les sous-domaines. Utile pour un domaine absent des listes.",
    empty: "Aucun domaine bloqué à la main.",
    placeholder: "pub.example.com",
  },
  allow: {
    hint: "La liste blanche gagne toujours : ces domaines (et leurs sous-domaines) ne sont jamais bloqués.",
    empty: "Aucun domaine autorisé à la main.",
    placeholder: "cdn.example.com",
  },
}

/** Manual blacklist ("deny") or whitelist ("allow"). */
export function RulesTab({ kind }: { kind: BlockRuleKind }) {
  const qc = useQueryClient()
  const perms = usePermissions()
  const canEdit = perms.can("config.write")
  const rules = useQuery(blockRulesQuery)
  // Errors are shown under the form (no global toast on top).
  const add = useAddRule({ silent: true })
  const [domain, setDomain] = React.useState("")
  const [comment, setComment] = React.useState("")
  const [error, setError] = React.useState<string>()
  const [deleting, setDeleting] = React.useState<BlockRule | null>(null)
  const t = text[kind]
  const items = React.useMemo(() => (rules.data?.items ?? []).filter((r) => r.kind === kind), [rules.data, kind])

  const remove = useMutation({
    mutationFn: (id: string) => api.delete("/blocking/rules/{id}", { params: { id } }),
    onSuccess: () => {
      toast.success("Domaine retiré.")
      void qc.invalidateQueries({ queryKey: qk.blockRules })
      void qc.invalidateQueries({ queryKey: qk.blockingStatus })
    },
  })

  const submit = (e: React.FormEvent) => {
    e.preventDefault()
    const d = cleanDomain(domain)
    if (!d) return setError("Nom de domaine non valide (ex. : example.com).")
    if (items.some((r) => r.domain === d)) return setError("Ce domaine est déjà dans la liste.")
    setError(undefined)
    add.mutate(
      { domain: d, kind, comment: comment.trim() || undefined },
      {
        onSuccess: () => {
          setDomain("")
          setComment("")
        },
        onError: (err) => setError(fieldError(err, "domain") ?? errorMessage(err)),
      },
    )
  }

  const columns = React.useMemo<ColumnDef<BlockRule, unknown>[]>(
    () => [
      {
        accessorKey: "domain",
        header: ({ column }) => <SortHeader column={column} title="Domaine" />,
        cell: ({ row }) => <span className="font-mono text-sm">{row.original.domain}</span>,
      },
      {
        accessorKey: "comment",
        header: ({ column }) => <SortHeader column={column} title="Commentaire" />,
        cell: ({ row }) => <span className="text-sm text-muted-foreground">{row.original.comment || "—"}</span>,
      },
      {
        id: "createdAt",
        accessorFn: (r) => r.createdAt ?? "",
        enableGlobalFilter: false,
        header: ({ column }) => <SortHeader column={column} title="Ajouté" />,
        cell: ({ row }) => (
          <span className="text-sm whitespace-nowrap" title={formatDateTime(row.original.createdAt)}>
            {formatRelative(row.original.createdAt)}
          </span>
        ),
      },
      {
        id: "actions",
        enableSorting: false,
        enableGlobalFilter: false,
        cell: ({ row }) =>
          canEdit && (
            <div className="flex justify-end">
              <Button
                variant="ghost"
                size="icon-sm"
                className="text-muted-foreground hover:text-destructive"
                aria-label={`Retirer ${row.original.domain}`}
                onClick={() => setDeleting(row.original)}
              >
                <Trash2 />
              </Button>
            </div>
          ),
      },
    ],
    [canEdit],
  )

  return (
    <div className="space-y-4">
      {perms.allowed("config.write") ? (
        <WriteGuard block>
          <form onSubmit={submit} className="space-y-2 rounded-lg border p-4" data-testid={`rule-form-${kind}`}>
            <div className="grid gap-3 sm:grid-cols-[1fr_1fr_auto] sm:items-end">
              <div className="space-y-2">
                <Label htmlFor={`rule-domain-${kind}`}>Domaine</Label>
                <Input
                  id={`rule-domain-${kind}`}
                  autoCapitalize="none"
                  spellCheck={false}
                  className="font-mono"
                  placeholder={t.placeholder}
                  value={domain}
                  aria-invalid={!!error}
                  onChange={(e) => {
                    setDomain(e.target.value)
                    setError(undefined)
                  }}
                />
              </div>
              <div className="space-y-2">
                <Label htmlFor={`rule-comment-${kind}`}>Commentaire (facultatif)</Label>
                <Input id={`rule-comment-${kind}`} value={comment} onChange={(e) => setComment(e.target.value)} placeholder="Pourquoi ?" />
              </div>
              <Button type="submit" disabled={add.isPending}>
                {add.isPending ? <Loader2 className="animate-spin" /> : <Plus />} Ajouter
              </Button>
            </div>
            <FormError message={error} />
            <p className="text-xs text-muted-foreground">{t.hint}</p>
          </form>
        </WriteGuard>
      ) : (
        <p className="text-sm text-muted-foreground">{t.hint}</p>
      )}
      {rules.isError && <p className="text-sm text-destructive">{errorMessage(rules.error)}</p>}
      <DataTable
        columns={columns}
        data={items}
        loading={rules.isPending}
        getRowId={(r) => r.id ?? r.domain ?? ""}
        searchPlaceholder="Rechercher un domaine…"
        initialSorting={[{ id: "domain", desc: false }]}
        empty={t.empty}
      />
      {deleting && (
        <ConfirmDialog
          open={!!deleting}
          onOpenChange={(o) => !o && setDeleting(null)}
          title={`Retirer ${deleting.domain} ?`}
          description={
            kind === "allow"
              ? "Il pourra de nouveau être bloqué s'il est dans une liste."
              : "Il ne sera plus bloqué, sauf s'il est dans une liste."
          }
          confirmLabel="Retirer"
          destructive
          onConfirm={() => remove.mutateAsync(deleting.id ?? "")}
        />
      )}
    </div>
  )
}
