import * as React from "react"
import { useMutation, useQuery } from "@tanstack/react-query"
import { Loader2 } from "lucide-react"
import { toast } from "sonner"
import { api, isApiError } from "@/api/client"
import { meQuery } from "@/api/queries"
import { LoadError } from "@/components/form-field"
import { RoleBadge } from "@/components/role-badge"
import { Button } from "@/components/ui/button"
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"
import { Input } from "@/components/ui/input"
import { Label } from "@/components/ui/label"
import { Skeleton } from "@/components/ui/skeleton"
import { errorMessage, fieldError } from "@/lib/errors"
import { formatDate } from "@/lib/format"

export function ProfileTab() {
  const me = useQuery(meQuery)
  return (
    <div className="grid gap-6 lg:grid-cols-2">
      <Card>
        <CardHeader>
          <CardTitle>Profil</CardTitle>
          <CardDescription>Informations de votre compte.</CardDescription>
        </CardHeader>
        <CardContent>
          {me.isPending ? (
            <Skeleton className="h-20 w-full" />
          ) : me.isError ? (
            <LoadError error={me.error} onRetry={() => void me.refetch()} retrying={me.isFetching} />
          ) : (
            <dl className="grid grid-cols-[auto_1fr] gap-x-6 gap-y-3 text-sm">
              <dt className="text-muted-foreground">Identifiant</dt>
              <dd className="font-medium">{me.data?.username}</dd>
              <dt className="text-muted-foreground">Rôle</dt>
              <dd>{me.data?.role && <RoleBadge role={me.data.role} />}</dd>
              <dt className="text-muted-foreground">Créé le</dt>
              <dd>{formatDate(me.data?.createdAt)}</dd>
            </dl>
          )}
        </CardContent>
      </Card>
      <PasswordCard />
    </div>
  )
}

function PasswordCard() {
  const [current, setCurrent] = React.useState("")
  const [next, setNext] = React.useState("")
  const [confirm, setConfirm] = React.useState("")
  const [error, setError] = React.useState<string | null>(null)

  const change = useMutation({
    mutationFn: () => api.post("/me/password", { body: { currentPassword: current, newPassword: next } }),
    meta: { silent: true },
    onSuccess: () => {
      toast.success("Mot de passe modifié.")
      setCurrent("")
      setNext("")
      setConfirm("")
    },
    onError: (e) => {
      if (isApiError(e) && e.status === 401) setError("Mot de passe actuel incorrect.")
      else setError(fieldError(e, "newPassword") ?? fieldError(e, "currentPassword") ?? errorMessage(e))
    },
  })

  const submit = (e: React.FormEvent) => {
    e.preventDefault()
    setError(null)
    if (next.length < 12) return setError("Le nouveau mot de passe doit faire au moins 12 caractères.")
    if (next !== confirm) return setError("Les deux mots de passe ne sont pas identiques.")
    change.mutate()
  }

  return (
    <Card>
      <CardHeader>
        <CardTitle>Changer le mot de passe</CardTitle>
        <CardDescription>Au moins 12 caractères. Une phrase facile à retenir est une bonne idée.</CardDescription>
      </CardHeader>
      <CardContent>
        <form onSubmit={submit} className="space-y-4">
          <div className="space-y-2">
            <Label htmlFor="pw-current">Mot de passe actuel</Label>
            <Input id="pw-current" type="password" autoComplete="current-password" required value={current} onChange={(e) => setCurrent(e.target.value)} />
          </div>
          <div className="space-y-2">
            <Label htmlFor="pw-new">Nouveau mot de passe</Label>
            <Input id="pw-new" type="password" autoComplete="new-password" required minLength={12} value={next} onChange={(e) => setNext(e.target.value)} />
          </div>
          <div className="space-y-2">
            <Label htmlFor="pw-confirm">Confirmer le nouveau mot de passe</Label>
            <Input id="pw-confirm" type="password" autoComplete="new-password" required value={confirm} onChange={(e) => setConfirm(e.target.value)} />
          </div>
          {error && <p className="text-sm text-destructive">{error}</p>}
          <Button type="submit" disabled={change.isPending}>
            {change.isPending && <Loader2 className="animate-spin" />}
            Enregistrer
          </Button>
        </form>
      </CardContent>
    </Card>
  )
}
