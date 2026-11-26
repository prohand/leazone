import * as React from "react"
import { useMutation, useQueryClient } from "@tanstack/react-query"
import { Check, Loader2 } from "lucide-react"
import { toast } from "sonner"
import { api } from "@/api/client"
import { qk } from "@/api/queries"
import type { BlockList, BlockListFormat, BlockListInput } from "@/api/types"
import { Field, FormError } from "@/components/form-field"
import { Button } from "@/components/ui/button"
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle } from "@/components/ui/dialog"
import { Input } from "@/components/ui/input"
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select"
import { formatLabel, suggestedLists } from "@/lib/blocking"
import { fieldError, formError } from "@/lib/errors"
import { urlHost } from "@/lib/net"

type Form = { name: string; url: string; format: BlockListFormat }

const formats: { value: BlockListFormat; help: string }[] = [
  { value: "auto", help: "Leazone reconnaît le format tout seul." },
  { value: "hosts", help: "Lignes « 0.0.0.0 domaine »." },
  { value: "domains", help: "Un domaine par ligne." },
  { value: "adblock", help: "Lignes « ||domaine^ »." },
]

/** Add or edit a subscribed list. */
export function ListDialog({
  open,
  onOpenChange,
  list,
  existing,
}: {
  open: boolean
  onOpenChange: (o: boolean) => void
  /** null = new list */
  list: BlockList | null
  /** Lists already subscribed (suggestions already added are marked). */
  existing: BlockList[]
}) {
  const qc = useQueryClient()
  const [form, setForm] = React.useState<Form>({ name: "", url: "", format: "auto" })
  const [local, setLocal] = React.useState<Record<string, string>>({})

  const save = useMutation({
    mutationFn: (body: BlockListInput) =>
      list?.id ? api.put("/blocking/lists/{id}", { params: { id: list.id }, body }) : api.post("/blocking/lists", { body }),
    meta: { silent: true },
    onSuccess: () => {
      void qc.invalidateQueries({ queryKey: qk.blockLists })
      void qc.invalidateQueries({ queryKey: qk.blockingStatus })
      toast.success(list ? "Liste modifiée." : "Liste ajoutée. Téléchargement en cours…")
      onOpenChange(false)
    },
  })

  React.useEffect(() => {
    if (open) {
      setForm(list ? { name: list.name, url: list.url, format: list.format ?? "auto" } : { name: "", url: "", format: "auto" })
      setLocal({})
      save.reset()
    }
    // Reset only when the dialog opens.
  }, [open])

  const set = (patch: Partial<Form>) => {
    setForm((f) => ({ ...f, ...patch }))
    if (save.isError) save.reset()
  }
  const err = (k: string) => local[k] ?? fieldError(save.error, k)
  const urls = new Set(existing.map((l) => l.url))

  const submit = (e: React.FormEvent) => {
    e.preventDefault()
    const errs: Record<string, string> = {}
    const url = form.url.trim()
    if (!form.name.trim()) errs.name = "Obligatoire."
    if (!/^https?:\/\//i.test(url) || !urlHost(url)) errs.url = "Adresse http:// ou https:// complète."
    else if (!list && urls.has(url)) errs.url = "Cette liste est déjà dans vos abonnements."
    setLocal(errs)
    if (Object.keys(errs).length) return
    save.mutate({ name: form.name.trim(), url, format: form.format, enabled: list ? list.enabled !== false : true })
  }

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="max-h-[90svh] overflow-y-auto sm:max-w-lg">
        <form onSubmit={submit} className="space-y-4">
          <DialogHeader>
            <DialogTitle>{list ? "Modifier la liste" : "Ajouter une liste"}</DialogTitle>
            <DialogDescription>
              Liste publique de domaines à bloquer. Elle est téléchargée tout de suite, puis mise à jour régulièrement.
            </DialogDescription>
          </DialogHeader>

          {!list && (
            <div className="space-y-2">
              <p className="text-xs font-medium text-muted-foreground">Suggestions</p>
              <div className="flex flex-wrap gap-2">
                {suggestedLists.map((s) => {
                  const added = urls.has(s.url)
                  return (
                    <Button
                      key={s.url}
                      type="button"
                      variant="outline"
                      size="sm"
                      disabled={added}
                      title={added ? "Déjà ajoutée" : s.url}
                      onClick={() => {
                        set({ name: s.name, url: s.url, format: s.format })
                        setLocal({})
                      }}
                    >
                      {added && <Check />} {s.label}
                    </Button>
                  )
                })}
              </div>
            </div>
          )}

          <Field label="Nom" htmlFor="bl-name" error={err("name")}>
            <Input id="bl-name" value={form.name} onChange={(e) => set({ name: e.target.value })} placeholder="Publicités" />
          </Field>
          <Field label="Adresse (URL)" htmlFor="bl-url" error={err("url")}>
            <Input
              id="bl-url"
              autoCapitalize="none"
              spellCheck={false}
              className="font-mono"
              value={form.url}
              onChange={(e) => set({ url: e.target.value })}
              placeholder="https://…"
            />
          </Field>
          <Field label="Format" htmlFor="bl-format" help={formats.find((f) => f.value === form.format)?.help} error={err("format")}>
            <Select value={form.format} onValueChange={(v) => set({ format: v as BlockListFormat })}>
              <SelectTrigger id="bl-format" className="w-full">
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                {formats.map((f) => (
                  <SelectItem key={f.value} value={f.value}>
                    {formatLabel[f.value]}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
          </Field>
          <FormError message={formError(save.error, ["name", "url", "format"])} />
          <DialogFooter>
            <Button type="button" variant="outline" onClick={() => onOpenChange(false)}>
              Annuler
            </Button>
            <Button type="submit" disabled={save.isPending}>
              {save.isPending && <Loader2 className="animate-spin" />}
              {list ? "Enregistrer" : "Ajouter"}
            </Button>
          </DialogFooter>
        </form>
      </DialogContent>
    </Dialog>
  )
}
