import * as React from "react"
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query"
import type { ColumnDef } from "@tanstack/react-table"
import { Fingerprint, Loader2, MoreHorizontal, Smartphone, UserPlus } from "lucide-react"
import { toast } from "sonner"
import { api } from "@/api/client"
import { qk } from "@/api/queries"
import type { Role, User } from "@/api/types"
import { ConfirmDialog } from "@/components/confirm-dialog"
import { DataTable, SortHeader } from "@/components/data-table"
import { LoadError } from "@/components/form-field"
import { PageHeader } from "@/components/page-header"
import { RoleBadge } from "@/components/role-badge"
import { SecretOnceDialog } from "@/components/secret-once-dialog"
import { Badge } from "@/components/ui/badge"
import { Button } from "@/components/ui/button"
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog"
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuLabel,
  DropdownMenuRadioGroup,
  DropdownMenuRadioItem,
  DropdownMenuSeparator,
  DropdownMenuSub,
  DropdownMenuSubContent,
  DropdownMenuSubTrigger,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu"
import { Input } from "@/components/ui/input"
import { Label } from "@/components/ui/label"
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select"
import { WriteGuard } from "@/components/read-only"
import { useWritable } from "@/hooks/use-cluster"
import { useCurrentUser } from "@/hooks/use-session"
import { fieldError, formError } from "@/lib/errors"
import { formatDateTime, formatRelative } from "@/lib/format"
import { roleLabel } from "@/lib/permissions"

const roles: Role[] = ["admin", "operator", "readonly"]

type Pending =
  | { kind: "delete" | "reset-mfa" | "reset-password" | "toggle"; user: User }
  | null

export default function UsersPage() {
  const qc = useQueryClient()
  const me = useCurrentUser()
  // Accounts are replicated config: no changes on a read-only cluster node.
  const { writable } = useWritable()
  const list = useQuery({ queryKey: qk.users, queryFn: () => api.get("/users") })
  const [roleFilter, setRoleFilter] = React.useState<"all" | Role>("all")
  const [creating, setCreating] = React.useState(false)
  const [pending, setPending] = React.useState<Pending>(null)
  const [secret, setSecret] = React.useState<{ title: string; value: string } | null>(null)

  const refresh = () => void qc.invalidateQueries({ queryKey: qk.users })

  const update = useMutation({
    mutationFn: (v: { id: string; role?: Role; disabled?: boolean }) =>
      api.patch("/users/{id}", { params: { id: v.id }, body: { role: v.role, disabled: v.disabled } }),
    onSuccess: () => {
      toast.success("Utilisateur modifié.")
      refresh()
    },
  })
  const remove = useMutation({
    mutationFn: (id: string) => api.delete("/users/{id}", { params: { id } }),
    onSuccess: () => {
      toast.success("Utilisateur supprimé.")
      refresh()
    },
  })
  const resetMfa = useMutation({
    mutationFn: (id: string) => api.post("/users/{id}/reset-mfa", { params: { id } }),
    onSuccess: () => {
      toast.success("MFA réinitialisé. L'utilisateur devra le configurer à nouveau.")
      refresh()
    },
  })
  const resetPassword = useMutation({
    mutationFn: (u: User) => api.post("/users/{id}/reset-password", { params: { id: u.id ?? "" } }),
    onSuccess: (r, u) => {
      setSecret({ title: `Mot de passe temporaire de ${u.username}`, value: r.temporaryPassword ?? "" })
      refresh()
    },
  })

  const mutateUpdate = update.mutate
  const columns = React.useMemo<ColumnDef<User, unknown>[]>(
    () => [
      {
        accessorKey: "username",
        header: ({ column }) => <SortHeader column={column} title="Identifiant" />,
        cell: ({ row }) => (
          <div className="flex items-center gap-2 font-medium">
            {row.original.username}
            {row.original.id === me?.id && <Badge variant="outline">Vous</Badge>}
            {row.original.disabled && (
              <Badge variant="destructive" className="sm:hidden">
                Désactivé
              </Badge>
            )}
          </div>
        ),
      },
      {
        accessorKey: "role",
        header: ({ column }) => <SortHeader column={column} title="Rôle" />,
        cell: ({ row }) => row.original.role && <RoleBadge role={row.original.role} />,
        filterFn: "equals",
      },
      {
        id: "mfa",
        accessorFn: (u) => (u.mfaEnabled ? 1 : 0),
        // Small screens: secondary columns hidden so the actions stay in view.
        meta: { className: "hidden md:table-cell" },
        header: ({ column }) => <SortHeader column={column} title="MFA" />,
        enableGlobalFilter: false,
        cell: ({ row }) => {
          const u = row.original
          if (!u.mfaEnabled) return <Badge variant="outline" className="text-warning">Non configuré</Badge>
          return (
            <div className="flex items-center gap-2 text-muted-foreground">
              {(u.passkeyCount ?? 0) > 0 && (
                <span className="flex items-center gap-1 text-xs" title="Passkeys">
                  <Fingerprint className="size-3.5" /> {u.passkeyCount}
                </span>
              )}
              {u.totpEnabled && (
                <span className="flex items-center gap-1 text-xs" title="TOTP">
                  <Smartphone className="size-3.5" /> TOTP
                </span>
              )}
            </div>
          )
        },
      },
      {
        id: "status",
        accessorFn: (u) => (u.disabled ? "Désactivé" : "Actif"),
        meta: { className: "hidden sm:table-cell" },
        header: ({ column }) => <SortHeader column={column} title="État" />,
        cell: ({ row }) =>
          row.original.disabled ? <Badge variant="destructive">Désactivé</Badge> : <Badge variant="secondary">Actif</Badge>,
      },
      {
        id: "lastLogin",
        accessorFn: (u) => (u.lastLoginAt ? new Date(u.lastLoginAt).getTime() : 0),
        meta: { className: "hidden lg:table-cell" },
        header: ({ column }) => <SortHeader column={column} title="Dernière connexion" />,
        enableGlobalFilter: false,
        cell: ({ row }) => (
          <span title={formatDateTime(row.original.lastLoginAt)}>{formatRelative(row.original.lastLoginAt)}</span>
        ),
      },
      {
        id: "actions",
        header: () => <span className="sr-only">Actions</span>,
        enableSorting: false,
        enableGlobalFilter: false,
        cell: ({ row }) => {
          const u = row.original
          const self = u.id === me?.id
          if (!writable) return null
          return (
            <div className="text-right">
              <DropdownMenu>
                <DropdownMenuTrigger asChild>
                  <Button variant="ghost" size="icon" aria-label={`Actions pour ${u.username}`}>
                    <MoreHorizontal />
                  </Button>
                </DropdownMenuTrigger>
                <DropdownMenuContent align="end" className="w-56">
                  <DropdownMenuLabel>{u.username}</DropdownMenuLabel>
                  <DropdownMenuSeparator />
                  <DropdownMenuSub>
                    <DropdownMenuSubTrigger disabled={self}>Changer le rôle</DropdownMenuSubTrigger>
                    <DropdownMenuSubContent>
                      <DropdownMenuRadioGroup
                        value={u.role}
                        onValueChange={(v) => u.id && mutateUpdate({ id: u.id, role: v as Role })}
                      >
                        {roles.map((r) => (
                          <DropdownMenuRadioItem key={r} value={r}>
                            {roleLabel[r]}
                          </DropdownMenuRadioItem>
                        ))}
                      </DropdownMenuRadioGroup>
                    </DropdownMenuSubContent>
                  </DropdownMenuSub>
                  <DropdownMenuItem disabled={self} onSelect={() => setPending({ kind: "toggle", user: u })}>
                    {u.disabled ? "Réactiver" : "Désactiver"}
                  </DropdownMenuItem>
                  <DropdownMenuSeparator />
                  <DropdownMenuItem onSelect={() => setPending({ kind: "reset-password", user: u })}>
                    Réinitialiser le mot de passe
                  </DropdownMenuItem>
                  <DropdownMenuItem disabled={!u.mfaEnabled} onSelect={() => setPending({ kind: "reset-mfa", user: u })}>
                    Réinitialiser le MFA
                  </DropdownMenuItem>
                  <DropdownMenuSeparator />
                  <DropdownMenuItem
                    variant="destructive"
                    disabled={self}
                    onSelect={() => setPending({ kind: "delete", user: u })}
                  >
                    Supprimer
                  </DropdownMenuItem>
                </DropdownMenuContent>
              </DropdownMenu>
            </div>
          )
        },
      },
    ],
    [me?.id, mutateUpdate, writable],
  )

  const data = React.useMemo(
    () => (list.data?.items ?? []).filter((u) => roleFilter === "all" || u.role === roleFilter),
    [list.data, roleFilter],
  )

  const confirmProps = (() => {
    if (!pending) return null
    const u = pending.user
    const id = u.id ?? ""
    switch (pending.kind) {
      case "delete":
        return {
          title: `Supprimer ${u.username} ?`,
          description: "Le compte, ses passkeys, sessions et jetons seront supprimés. Cette action est définitive.",
          confirmLabel: "Supprimer",
          destructive: true,
          onConfirm: () => remove.mutateAsync(id),
        }
      case "reset-mfa":
        return {
          title: `Réinitialiser le MFA de ${u.username} ?`,
          description: "Toutes ses passkeys, son TOTP et ses codes de secours seront supprimés. Il devra configurer le MFA à sa prochaine connexion.",
          confirmLabel: "Réinitialiser",
          destructive: true,
          onConfirm: () => resetMfa.mutateAsync(id),
        }
      case "reset-password":
        return {
          title: `Réinitialiser le mot de passe de ${u.username} ?`,
          description: "Un mot de passe temporaire sera créé et ses sessions seront fermées.",
          confirmLabel: "Réinitialiser",
          destructive: false,
          onConfirm: () => resetPassword.mutateAsync(u),
        }
      case "toggle":
        return {
          title: u.disabled ? `Réactiver ${u.username} ?` : `Désactiver ${u.username} ?`,
          description: u.disabled
            ? "L'utilisateur pourra de nouveau se connecter."
            : "L'utilisateur ne pourra plus se connecter. Ses jetons d'API ne marcheront plus.",
          confirmLabel: u.disabled ? "Réactiver" : "Désactiver",
          destructive: !u.disabled,
          onConfirm: () => update.mutateAsync({ id, disabled: !u.disabled }),
        }
    }
  })()

  return (
    <>
      <PageHeader
        title="Utilisateurs"
        description="Comptes qui peuvent ouvrir l'interface ou utiliser l'API."
        actions={
          <WriteGuard>
            <Button onClick={() => setCreating(true)}>
              <UserPlus /> Ajouter un utilisateur
            </Button>
          </WriteGuard>
        }
      />
      {list.isError && (
        <LoadError className="mb-3" error={list.error} onRetry={() => void list.refetch()} retrying={list.isFetching} />
      )}
      <DataTable
        columns={columns}
        data={data}
        loading={list.isPending}
        getRowId={(u) => u.id ?? u.username ?? ""}
        searchPlaceholder="Rechercher un utilisateur…"
        initialSorting={[{ id: "username", desc: false }]}
        empty={list.isError ? "Liste indisponible." : "Aucun utilisateur."}
        toolbar={
          <Select value={roleFilter} onValueChange={(v) => setRoleFilter(v as "all" | Role)}>
            <SelectTrigger className="w-44" aria-label="Filtrer par rôle">
              <SelectValue />
            </SelectTrigger>
            <SelectContent>
              <SelectItem value="all">Tous les rôles</SelectItem>
              {roles.map((r) => (
                <SelectItem key={r} value={r}>
                  {roleLabel[r]}
                </SelectItem>
              ))}
            </SelectContent>
          </Select>
        }
      />
      <CreateUserDialog
        open={creating}
        onOpenChange={setCreating}
        onCreated={(username, temp) => {
          setCreating(false)
          refresh()
          toast.success(`Utilisateur ${username} créé.`)
          if (temp) setSecret({ title: `Mot de passe temporaire de ${username}`, value: temp })
        }}
      />
      {confirmProps && (
        <ConfirmDialog open={!!pending} onOpenChange={(o) => !o && setPending(null)} {...confirmProps} />
      )}
      <SecretOnceDialog
        title={secret?.title ?? ""}
        description="Donnez-le à l'utilisateur par un moyen sûr. Il pourra le changer dans « Mon compte »."
        secret={secret?.value ?? null}
        onClose={() => setSecret(null)}
      />
    </>
  )
}

function CreateUserDialog({
  open,
  onOpenChange,
  onCreated,
}: {
  open: boolean
  onOpenChange: (o: boolean) => void
  onCreated: (username: string, temporaryPassword: string | null | undefined) => void
}) {
  const [username, setUsername] = React.useState("")
  const [role, setRole] = React.useState<Role>("readonly")
  const [password, setPassword] = React.useState("")
  const [localError, setLocalError] = React.useState<string | null>(null)

  const create = useMutation({
    mutationFn: () =>
      api.post("/users", { body: { username: username.trim(), role, ...(password ? { password } : {}) } }),
    meta: { silent: true },
    onSuccess: (r) => onCreated(r.item?.username ?? username, r.temporaryPassword),
  })

  // Fresh form on every opening (no error left from the previous attempt).
  const resetCreate = create.reset
  React.useEffect(() => {
    if (open) {
      setUsername("")
      setRole("readonly")
      setPassword("")
      setLocalError(null)
      resetCreate()
    }
  }, [open, resetCreate])

  const submit = (e: React.FormEvent) => {
    e.preventDefault()
    setLocalError(null)
    if (!/^[a-z0-9][a-z0-9._-]{1,31}$/.test(username.trim()))
      return setLocalError("2 à 32 caractères : lettres minuscules, chiffres, « . », « _ » ou « - ».")
    if (password && password.length < 12) return setLocalError("Le mot de passe doit faire au moins 12 caractères.")
    create.mutate()
  }

  const usernameError = localError ?? fieldError(create.error, "username")

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="sm:max-w-md">
        <form onSubmit={submit} className="space-y-4">
          <DialogHeader>
            <DialogTitle>Ajouter un utilisateur</DialogTitle>
            <DialogDescription>Il devra configurer le MFA à sa première connexion si la politique l'exige.</DialogDescription>
          </DialogHeader>
          <div className="space-y-2">
            <Label htmlFor="new-username">Identifiant</Label>
            <Input
              id="new-username"
              autoFocus
              autoCapitalize="none"
              spellCheck={false}
              value={username}
              onChange={(e) => setUsername(e.target.value.toLowerCase())}
              placeholder="ex. : marie.dupont"
            />
            {usernameError && <p className="text-sm text-destructive">{usernameError}</p>}
          </div>
          <div className="space-y-2">
            <Label htmlFor="new-role">Rôle</Label>
            <Select value={role} onValueChange={(v) => setRole(v as Role)}>
              <SelectTrigger id="new-role" className="w-full">
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                {roles.map((r) => (
                  <SelectItem key={r} value={r}>
                    {roleLabel[r]}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
            <p className="text-xs text-muted-foreground">
              Opérateur : enregistrements DNS, baux et réservations. Lecture seule : consultation uniquement.
            </p>
          </div>
          <div className="space-y-2">
            <Label htmlFor="new-password">Mot de passe (facultatif)</Label>
            <Input
              id="new-password"
              type="password"
              autoComplete="new-password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
            />
            <p className="text-xs text-muted-foreground">Laissez vide pour générer un mot de passe temporaire.</p>
            {fieldError(create.error, "password") && (
              <p className="text-sm text-destructive">{fieldError(create.error, "password")}</p>
            )}
          </div>
          {formError(create.error, ["username", "password"]) && (
            <p className="text-sm text-destructive">{formError(create.error, ["username", "password"])}</p>
          )}
          <DialogFooter>
            <Button type="button" variant="ghost" onClick={() => onOpenChange(false)}>
              Annuler
            </Button>
            <Button type="submit" disabled={create.isPending || !username.trim()}>
              {create.isPending && <Loader2 className="animate-spin" />}
              Créer
            </Button>
          </DialogFooter>
        </form>
      </DialogContent>
    </Dialog>
  )
}
