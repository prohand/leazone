import * as React from "react"
import { useMutation, useQueryClient } from "@tanstack/react-query"
import { Eraser, Loader2 } from "lucide-react"
import { toast } from "sonner"
import { api } from "@/api/client"
import { qk } from "@/api/queries"
import { Button } from "@/components/ui/button"
import { Input } from "@/components/ui/input"
import { Label } from "@/components/ui/label"
import { Popover, PopoverContent, PopoverTrigger } from "@/components/ui/popover"
import { cn } from "@/lib/utils"

export function useCacheFlush() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: (name: string) => api.post("/dns/cache/flush", { body: name ? { name } : {} }),
    onSuccess: (r, name) => {
      const n = r?.removed ?? 0
      const what = n === 1 ? "1 entrée supprimée" : `${n} entrées supprimées`
      toast.success(name ? `Cache vidé pour ${name} : ${what}.` : `Cache DNS vidé : ${what}.`)
      void qc.invalidateQueries({ queryKey: qk.dnsStatus })
    },
  })
}

/** Inline "empty the cache" form with an optional name. */
export function CacheFlushForm({ className, onDone }: { className?: string; onDone?: () => void }) {
  const [name, setName] = React.useState("")
  const flush = useCacheFlush()
  const submit = (e: React.FormEvent) => {
    e.preventDefault()
    flush.mutate(name.trim().replace(/\.$/, ""), {
      onSuccess: () => {
        setName("")
        onDone?.()
      },
    })
  }
  return (
    <form onSubmit={submit} className={cn("flex flex-col gap-2 sm:flex-row sm:items-end", className)}>
      <div className="flex-1 space-y-2">
        <Label htmlFor="flush-name">Seulement ce nom (facultatif)</Label>
        <Input
          id="flush-name"
          value={name}
          onChange={(e) => setName(e.target.value)}
          placeholder="ex. : exemple.com"
          autoCapitalize="none"
          spellCheck={false}
        />
      </div>
      <Button type="submit" variant="outline" disabled={flush.isPending}>
        {flush.isPending ? <Loader2 className="animate-spin" /> : <Eraser />}
        Vider le cache
      </Button>
    </form>
  )
}

/** Header button opening the flush form in a popover. */
export function CacheFlushPopover() {
  const [open, setOpen] = React.useState(false)
  return (
    <Popover open={open} onOpenChange={setOpen}>
      <PopoverTrigger asChild>
        <Button variant="outline">
          <Eraser /> Vider le cache
        </Button>
      </PopoverTrigger>
      <PopoverContent align="end" className="w-80">
        <p className="mb-3 text-sm text-muted-foreground">
          Les réponses des redirecteurs sont gardées en cache. Videz-le après un changement chez un fournisseur DNS.
        </p>
        <CacheFlushForm className="sm:flex-col sm:items-stretch" onDone={() => setOpen(false)} />
      </PopoverContent>
    </Popover>
  )
}
