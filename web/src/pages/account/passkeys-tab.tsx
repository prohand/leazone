import * as React from "react"
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query"
import { Cloud, Fingerprint, KeyRound, Loader2, Pencil, Trash2 } from "lucide-react"
import { toast } from "sonner"
import { api } from "@/api/client"
import { qk } from "@/api/queries"
import type { MfaEnrollResult, Passkey } from "@/api/types"
import { ConfirmDialog } from "@/components/confirm-dialog"
import { EmptyState } from "@/components/empty-state"
import { LoadError } from "@/components/form-field"
import { PasskeyRegister } from "@/components/passkey-register"
import { RecoveryCodesDialog } from "@/components/recovery-codes-dialog"
import { BlockSpinner } from "@/components/spinner"
import { Badge } from "@/components/ui/badge"
import { Button } from "@/components/ui/button"
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"
import {
  Dialog,
  DialogContent,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog"
import { Input } from "@/components/ui/input"
import { Label } from "@/components/ui/label"
import { Tooltip, TooltipContent, TooltipTrigger } from "@/components/ui/tooltip"
import { formatDate, formatRelative } from "@/lib/format"

export function PasskeysTab() {
  const qc = useQueryClient()
  const list = useQuery({ queryKey: qk.passkeys, queryFn: () => api.get("/me/passkeys") })
  const [codes, setCodes] = React.useState<string[] | null>(null)
  const [renaming, setRenaming] = React.useState<Passkey | null>(null)
  const [deleting, setDeleting] = React.useState<Passkey | null>(null)

  const refresh = () => {
    void qc.invalidateQueries({ queryKey: qk.passkeys })
    void qc.invalidateQueries({ queryKey: qk.me })
  }

  const onEnrolled = (r: MfaEnrollResult) => {
    toast.success("Passkey ajoutée.")
    refresh()
    if (r.recoveryCodes?.length) setCodes(r.recoveryCodes)
  }

  const remove = useMutation({
    mutationFn: (id: string) => api.delete("/me/passkeys/{id}", { params: { id } }),
    onSuccess: () => {
      toast.success("Passkey supprimée.")
      refresh()
    },
  })

  const items = list.data?.items ?? []

  return (
    <div className="space-y-6">
      <Card>
        <CardHeader>
          <CardTitle>Ajouter une passkey</CardTitle>
          <CardDescription>
            Une passkey remplace le mot de passe : empreinte, visage, code de l'appareil ou clé de sécurité.
          </CardDescription>
        </CardHeader>
        <CardContent>
          <PasskeyRegister onEnrolled={onEnrolled} submitLabel="Ajouter" />
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle>Mes passkeys</CardTitle>
        </CardHeader>
        <CardContent>
          {list.isPending ? (
            <BlockSpinner />
          ) : list.isError ? (
            <LoadError error={list.error} onRetry={() => void list.refetch()} retrying={list.isFetching} />
          ) : items.length === 0 ? (
            <EmptyState icon={Fingerprint} title="Aucune passkey" description="Ajoutez-en une ci-dessus." />
          ) : (
            <ul className="divide-y rounded-lg border">
              {items.map((p) => (
                <li key={p.id} className="flex flex-col gap-3 p-4 sm:flex-row sm:items-center">
                  <KeyRound className="hidden size-5 shrink-0 text-muted-foreground sm:block" />
                  <div className="min-w-0 flex-1">
                    <div className="flex flex-wrap items-center gap-2">
                      <span className="truncate font-medium">{p.name}</span>
                      {p.backupEligible && (
                        <Tooltip>
                          <TooltipTrigger asChild>
                            <Badge variant="secondary">
                              <Cloud /> Synchronisée
                            </Badge>
                          </TooltipTrigger>
                          <TooltipContent>Copiée dans un gestionnaire de mots de passe ou un compte cloud.</TooltipContent>
                        </Tooltip>
                      )}
                    </div>
                    <p className="text-xs text-muted-foreground">
                      Créée le {formatDate(p.createdAt)} · Dernière utilisation : {formatRelative(p.lastUsedAt)}
                    </p>
                  </div>
                  <div className="flex gap-2">
                    <Button variant="outline" size="sm" onClick={() => setRenaming(p)}>
                      <Pencil /> Renommer
                    </Button>
                    <Button variant="outline" size="sm" onClick={() => setDeleting(p)}>
                      <Trash2 /> Supprimer
                    </Button>
                  </div>
                </li>
              ))}
            </ul>
          )}
        </CardContent>
      </Card>

      <RenameDialog passkey={renaming} onClose={() => setRenaming(null)} onDone={refresh} />
      <ConfirmDialog
        open={!!deleting}
        onOpenChange={(o) => !o && setDeleting(null)}
        title="Supprimer cette passkey ?"
        description={`« ${deleting?.name ?? ""} » ne pourra plus servir à vous connecter.`}
        confirmLabel="Supprimer"
        destructive
        onConfirm={() => deleting?.id && remove.mutateAsync(deleting.id)}
      />
      <RecoveryCodesDialog codes={codes} onDone={() => setCodes(null)} />
    </div>
  )
}

function RenameDialog({ passkey, onClose, onDone }: { passkey: Passkey | null; onClose: () => void; onDone: () => void }) {
  const [name, setName] = React.useState("")
  React.useEffect(() => setName(passkey?.name ?? ""), [passkey])
  const rename = useMutation({
    mutationFn: () => api.patch("/me/passkeys/{id}", { params: { id: passkey?.id ?? "" }, body: { name: name.trim() } }),
    onSuccess: () => {
      toast.success("Passkey renommée.")
      onDone()
      onClose()
    },
  })
  return (
    <Dialog open={!!passkey} onOpenChange={(o) => !o && onClose()}>
      <DialogContent className="sm:max-w-sm">
        <form
          onSubmit={(e) => {
            e.preventDefault()
            if (name.trim()) rename.mutate()
          }}
          className="space-y-4"
        >
          <DialogHeader>
            <DialogTitle>Renommer la passkey</DialogTitle>
          </DialogHeader>
          <div className="space-y-2">
            <Label htmlFor="rename-passkey">Nom</Label>
            <Input id="rename-passkey" value={name} maxLength={64} autoFocus onChange={(e) => setName(e.target.value)} />
          </div>
          <DialogFooter>
            <Button type="button" variant="ghost" onClick={onClose}>
              Annuler
            </Button>
            <Button type="submit" disabled={!name.trim() || rename.isPending}>
              {rename.isPending && <Loader2 className="animate-spin" />}
              Enregistrer
            </Button>
          </DialogFooter>
        </form>
      </DialogContent>
    </Dialog>
  )
}
