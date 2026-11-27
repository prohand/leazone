import * as React from "react"
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query"
import { KeySquare, Loader2, Plus } from "lucide-react"
import { toast } from "sonner"
import { api } from "@/api/client"
import { qk } from "@/api/queries"
import type { ApiToken } from "@/api/types"
import { ConfirmDialog } from "@/components/confirm-dialog"
import { EmptyState } from "@/components/empty-state"
import { LoadError } from "@/components/form-field"
import { SecretOnceDialog } from "@/components/secret-once-dialog"
import { BlockSpinner } from "@/components/spinner"
import { Badge } from "@/components/ui/badge"
import { Button } from "@/components/ui/button"
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog"
import { Input } from "@/components/ui/input"
import { Label } from "@/components/ui/label"
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select"
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table"
import { fieldError, formError } from "@/lib/errors"
import { formatDate, formatRelative } from "@/lib/format"

const scopeLabel = { read: "Lecture", write: "Lecture et écriture" } as const

export function TokensTab() {
  const qc = useQueryClient()
  const list = useQuery({ queryKey: qk.tokens, queryFn: () => api.get("/me/tokens") })
  const [creating, setCreating] = React.useState(false)
  const [secret, setSecret] = React.useState<string | null>(null)
  const [revoking, setRevoking] = React.useState<ApiToken | null>(null)

  const revoke = useMutation({
    mutationFn: (id: string) => api.delete("/me/tokens/{id}", { params: { id } }),
    onSuccess: () => {
      toast.success("Jeton révoqué.")
      void qc.invalidateQueries({ queryKey: qk.tokens })
    },
  })

  const items = list.data?.items ?? []
  const expired = (t: ApiToken) => !!t.expiresAt && new Date(t.expiresAt).getTime() < Date.now()

  return (
    <Card>
      <CardHeader className="flex flex-col gap-3 sm:flex-row sm:items-start sm:justify-between">
        <div className="space-y-1.5">
          <CardTitle>Jetons d'API</CardTitle>
          <CardDescription>
            Pour les scripts : en-tête <code className="font-mono text-xs">Authorization: Bearer lz_…</code>. Le droit
            réel est le plus faible entre le jeton et votre rôle.
          </CardDescription>
        </div>
        <Button onClick={() => setCreating(true)}>
          <Plus /> Créer un jeton
        </Button>
      </CardHeader>
      <CardContent>
        {list.isPending ? (
          <BlockSpinner />
        ) : list.isError ? (
          <LoadError error={list.error} onRetry={() => void list.refetch()} retrying={list.isFetching} />
        ) : items.length === 0 ? (
          <EmptyState icon={KeySquare} title="Aucun jeton" description="Créez un jeton pour utiliser l'API depuis un script." />
        ) : (
          <div className="rounded-lg border">
            <Table>
              <TableHeader>
                <TableRow className="hover:bg-transparent">
                  <TableHead>Nom</TableHead>
                  <TableHead className="hidden md:table-cell">Préfixe</TableHead>
                  <TableHead className="hidden sm:table-cell">Droits</TableHead>
                  <TableHead className="hidden lg:table-cell">Créé le</TableHead>
                  <TableHead className="hidden md:table-cell">Expire le</TableHead>
                  <TableHead className="hidden lg:table-cell">Dernière utilisation</TableHead>
                  <TableHead>
                    <span className="sr-only">Actions</span>
                  </TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {items.map((t) => (
                  <TableRow key={t.id}>
                    <TableCell className="font-medium">
                      {t.name}
                      {/* Small screens: the hidden columns that matter, under the name. */}
                      <div className="mt-1 flex flex-wrap items-center gap-1.5 text-xs font-normal text-muted-foreground md:hidden">
                        <span className="sm:hidden">{t.scope ? scopeLabel[t.scope] : "—"}</span>
                        <span className="sm:hidden" aria-hidden>
                          ·
                        </span>
                        <span>Expire : {t.expiresAt ? formatDate(t.expiresAt) : "jamais"}</span>
                        {expired(t) && <Badge variant="destructive">Expiré</Badge>}
                      </div>
                    </TableCell>
                    <TableCell className="hidden font-mono text-xs md:table-cell">lz_{t.prefix}_…</TableCell>
                    <TableCell className="hidden sm:table-cell">
                      <Badge variant={t.scope === "write" ? "default" : "secondary"}>{t.scope ? scopeLabel[t.scope] : "—"}</Badge>
                    </TableCell>
                    <TableCell className="hidden lg:table-cell">{formatDate(t.createdAt)}</TableCell>
                    <TableCell className="hidden md:table-cell">
                      {t.expiresAt ? formatDate(t.expiresAt) : "Jamais"}
                      {expired(t) && (
                        <Badge variant="destructive" className="ml-2">
                          Expiré
                        </Badge>
                      )}
                    </TableCell>
                    <TableCell className="hidden lg:table-cell">{formatRelative(t.lastUsedAt)}</TableCell>
                    <TableCell className="text-right">
                      <Button variant="outline" size="sm" onClick={() => setRevoking(t)}>
                        Révoquer
                      </Button>
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </div>
        )}
      </CardContent>
      <CreateTokenDialog
        open={creating}
        onOpenChange={setCreating}
        onCreated={(token) => {
          setCreating(false)
          setSecret(token)
          void qc.invalidateQueries({ queryKey: qk.tokens })
        }}
      />
      <SecretOnceDialog
        title="Jeton créé"
        description="Utilisez-le dans l'en-tête Authorization: Bearer de vos scripts."
        secret={secret}
        onClose={() => setSecret(null)}
      />
      <ConfirmDialog
        open={!!revoking}
        onOpenChange={(o) => !o && setRevoking(null)}
        title="Révoquer ce jeton ?"
        description={`Les scripts qui utilisent « ${revoking?.name ?? ""} » ne pourront plus accéder à l'API.`}
        confirmLabel="Révoquer"
        destructive
        onConfirm={() => revoking?.id && revoke.mutateAsync(revoking.id)}
      />
    </Card>
  )
}

function CreateTokenDialog({
  open,
  onOpenChange,
  onCreated,
}: {
  open: boolean
  onOpenChange: (o: boolean) => void
  onCreated: (token: string) => void
}) {
  const [name, setName] = React.useState("")
  const [scope, setScope] = React.useState<"read" | "write">("read")
  const [expires, setExpires] = React.useState("")

  const create = useMutation({
    mutationFn: () =>
      api.post("/me/tokens", {
        body: {
          name: name.trim(),
          scope,
          // End of the chosen day, local time.
          expiresAt: expires ? new Date(`${expires}T23:59:59`).toISOString() : null,
        },
      }),
    meta: { silent: true },
    onSuccess: (r) => onCreated(r.token ?? ""),
  })

  // Fresh form on every opening (no error left from the previous attempt).
  const resetCreate = create.reset
  React.useEffect(() => {
    if (open) {
      setName("")
      setScope("read")
      setExpires("")
      resetCreate()
    }
  }, [open, resetCreate])

  const tomorrow = new Date(Date.now() + 86400_000).toISOString().slice(0, 10)

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="sm:max-w-md">
        <form
          className="space-y-4"
          onSubmit={(e) => {
            e.preventDefault()
            if (name.trim()) create.mutate()
          }}
        >
          <DialogHeader>
            <DialogTitle>Créer un jeton d'API</DialogTitle>
            <DialogDescription>Le jeton ne sera affiché qu'une seule fois.</DialogDescription>
          </DialogHeader>
          <div className="space-y-2">
            <Label htmlFor="token-name">Nom</Label>
            <Input
              id="token-name"
              value={name}
              maxLength={64}
              autoFocus
              placeholder="Ex. : sauvegarde nocturne"
              onChange={(e) => setName(e.target.value)}
            />
            {fieldError(create.error, "name") && <p className="text-sm text-destructive">{fieldError(create.error, "name")}</p>}
          </div>
          <div className="space-y-2">
            <Label htmlFor="token-scope">Droits</Label>
            <Select value={scope} onValueChange={(v) => setScope(v as "read" | "write")}>
              <SelectTrigger id="token-scope" className="w-full">
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="read">Lecture</SelectItem>
                <SelectItem value="write">Lecture et écriture</SelectItem>
              </SelectContent>
            </Select>
          </div>
          <div className="space-y-2">
            <Label htmlFor="token-expires">Date d'expiration (facultatif)</Label>
            <Input id="token-expires" type="date" min={tomorrow} value={expires} onChange={(e) => setExpires(e.target.value)} />
            <p className="text-xs text-muted-foreground">Laissez vide pour un jeton sans expiration.</p>
          </div>
          {formError(create.error, ["name"]) && <p className="text-sm text-destructive">{formError(create.error, ["name"])}</p>}
          <DialogFooter>
            <Button type="button" variant="ghost" onClick={() => onOpenChange(false)}>
              Annuler
            </Button>
            <Button type="submit" disabled={!name.trim() || create.isPending}>
              {create.isPending && <Loader2 className="animate-spin" />}
              Créer
            </Button>
          </DialogFooter>
        </form>
      </DialogContent>
    </Dialog>
  )
}
