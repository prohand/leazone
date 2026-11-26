import { Link } from "react-router"
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query"
import { ArrowRight, Loader2 } from "lucide-react"
import { toast } from "sonner"
import { api } from "@/api/client"
import { modulesQuery, qk } from "@/api/queries"
import type { Modules } from "@/api/types"
import { BlockSpinner } from "@/components/spinner"
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"
import { Label } from "@/components/ui/label"
import { Switch } from "@/components/ui/switch"
import { useClusterView } from "@/hooks/use-cluster"
import { errorMessage } from "@/lib/errors"
import { modulesOf } from "@/lib/modules"

type Key = keyof Required<Modules>

const items: { key: Key; title: string; help: string; note?: string; link?: { to: string; label: string } }[] = [
  {
    key: "blocking",
    title: "Blocage des publicités et traqueurs",
    help: "Leazone refuse de résoudre les domaines de publicité et de pistage, à partir de listes que vous choisissez.",
    link: { to: "/blocking", label: "Ouvrir le blocage" },
  },
  {
    key: "dnssec",
    title: "DNSSEC : signature des zones",
    help: "Signe vos zones pour que les résolveurs puissent vérifier que les réponses viennent bien de vous.",
    link: { to: "/dnssec", label: "Ouvrir DNSSEC" },
  },
  {
    key: "dnssecValidation",
    title: "DNSSEC : validation des réponses des redirecteurs",
    help: "Vérifie les signatures des réponses venues d'Internet.",
    note: "Les réponses falsifiées sont refusées (SERVFAIL).",
  },
]

/** Optional modules: each switch is saved at once (admin, step-up). */
export function ModulesTab() {
  const qc = useQueryClient()
  const q = useQuery(modulesQuery)
  const cluster = useClusterView()
  const both = !!cluster.data?.enabled

  const save = useMutation({
    mutationFn: (body: Modules) => api.put("/settings/modules", { body }),
    onSuccess: (m, body) => {
      qc.setQueryData(qk.modules, m ?? body)
      // Pages of the module (and the dashboard card) read fresh data.
      void qc.invalidateQueries({ queryKey: qk.blocking })
      void qc.invalidateQueries({ queryKey: qk.dnssec })
    },
  })

  if (q.isPending) return <BlockSpinner />
  const current = modulesOf(q.data)

  const toggle = (key: Key, on: boolean) => {
    save.mutate(
      { ...current, [key]: on },
      {
        onSuccess: () =>
          toast.success(
            `${on ? "Activé" : "Désactivé"} sans redémarrage${both ? ", appliqué sur les deux nœuds" : ""}.`,
          ),
      },
    )
  }

  return (
    <Card>
      <CardHeader>
        <CardTitle>Modules</CardTitle>
        <CardDescription>
          Fonctions facultatives. Elles s'activent et se désactivent sans redémarrer le serveur.
        </CardDescription>
      </CardHeader>
      <CardContent className="space-y-1">
        {q.isError && <p className="mb-3 text-sm text-destructive">{errorMessage(q.error)}</p>}
        <ul className="divide-y rounded-lg border">
          {items.map((it) => {
            const on = current[it.key]
            const busy = save.isPending && save.variables?.[it.key] !== current[it.key]
            const id = `module-${it.key}`
            return (
              <li key={it.key} className="flex items-start gap-4 px-4 py-4">
                <div className="min-w-0 flex-1 space-y-1">
                  <Label htmlFor={id} className="text-sm font-medium">
                    {it.title}
                  </Label>
                  <p className="text-sm text-muted-foreground">
                    {it.help}
                    {it.note && <> {it.note}</>}
                  </p>
                  {on && it.link && (
                    <Link to={it.link.to} className="inline-flex items-center gap-1 text-sm text-brand hover:underline">
                      {it.link.label} <ArrowRight className="size-3.5" />
                    </Link>
                  )}
                </div>
                <div className="flex items-center gap-2 pt-0.5">
                  {busy && <Loader2 className="size-4 animate-spin text-muted-foreground" />}
                  <Switch id={id} checked={on} disabled={save.isPending} onCheckedChange={(v) => toggle(it.key, v)} />
                </div>
              </li>
            )
          })}
        </ul>
      </CardContent>
    </Card>
  )
}
