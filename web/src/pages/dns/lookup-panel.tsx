import * as React from "react"
import { useMutation } from "@tanstack/react-query"
import { Loader2, Search } from "lucide-react"
import { api } from "@/api/client"
import type { LookupResult } from "@/api/types"
import { Badge } from "@/components/ui/badge"
import { Button } from "@/components/ui/button"
import { Input } from "@/components/ui/input"
import { Label } from "@/components/ui/label"
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select"
import { formatLatency, lookupTypes } from "@/lib/dns"
import { errorMessage } from "@/lib/errors"
import { isIP, reverseName } from "@/lib/net"
import { cn } from "@/lib/utils"

type LookupType = (typeof lookupTypes)[number]

const sourceLabel: Record<NonNullable<LookupResult["source"]>, string> = {
  local: "Zone locale",
  cache: "Cache",
  forwarder: "Redirecteur",
  refused: "Refusé",
  error: "Erreur",
}

function RcodeBadge({ rcode }: { rcode?: string }) {
  const r = (rcode ?? "").toUpperCase()
  const cls =
    r === "NOERROR"
      ? "border-success/40 text-success"
      : r === "NXDOMAIN"
        ? "border-warning/50 text-warning"
        : "border-destructive/40 text-destructive"
  return (
    <Badge variant="outline" className={cn("font-mono", cls)}>
      {r || "?"}
    </Badge>
  )
}

export function LookupResultView({ result }: { result: LookupResult }) {
  const answers = result.answers ?? []
  const authority = result.authority ?? []
  const src = result.source ?? "error"
  return (
    <div className="space-y-3 rounded-lg border p-3" aria-live="polite">
      <div className="flex flex-wrap items-center gap-2 text-sm">
        <RcodeBadge rcode={result.rcode} />
        <Badge variant={src === "refused" || src === "error" ? "destructive" : "secondary"}>
          {sourceLabel[src]}
          {src === "forwarder" && result.forwarder ? ` · ${result.forwarder}` : ""}
        </Badge>
        {result.latencyMs !== undefined && (
          <span className="text-muted-foreground tabular-nums">{formatLatency(result.latencyMs)}</span>
        )}
      </div>
      {src === "refused" && (
        <p className="text-xs text-muted-foreground">
          Nom externe refusé : ce réseau n'est pas autorisé à utiliser les redirecteurs (Paramètres › DNS).
        </p>
      )}
      {answers.length > 0 ? (
        <pre className="overflow-x-auto rounded-md bg-muted/60 p-3 font-mono text-xs leading-relaxed">
          {answers.join("\n")}
        </pre>
      ) : (
        <p className="text-sm text-muted-foreground">Aucune réponse.</p>
      )}
      {authority.length > 0 && (
        <div className="space-y-1">
          <p className="text-xs font-medium text-muted-foreground">Autorité</p>
          <pre className="overflow-x-auto rounded-md bg-muted/40 p-3 font-mono text-xs leading-relaxed text-muted-foreground">
            {authority.join("\n")}
          </pre>
        </div>
      )}
    </div>
  )
}

export default function LookupPanel({ initialName = "" }: { initialName?: string }) {
  const [name, setName] = React.useState(initialName)
  const [type, setType] = React.useState<LookupType>("A")

  const lookup = useMutation({
    mutationFn: (v: { name: string; type: string }) => api.post("/dns/lookup", { body: v }),
    meta: { silent: true },
  })

  const submit = (e: React.FormEvent) => {
    e.preventDefault()
    let n = name.trim()
    if (!n) return
    let t: string = type
    // Typing an IP means "who is this address": ask for the PTR record.
    if (isIP(n)) {
      const rev = reverseName(n)
      if (rev) {
        n = rev
        t = "PTR"
        setType("PTR")
      }
    }
    lookup.mutate({ name: n, type: t })
  }

  return (
    <div className="space-y-4">
      <form onSubmit={submit} className="flex flex-col gap-2 sm:flex-row sm:items-end">
        <div className="flex-1 space-y-2">
          <Label htmlFor="lookup-name">Nom</Label>
          <Input
            id="lookup-name"
            autoFocus
            autoCapitalize="none"
            spellCheck={false}
            value={name}
            onChange={(e) => setName(e.target.value)}
            placeholder="ex. : nas.maison.lan ou 192.168.1.10"
          />
        </div>
        <div className="space-y-2">
          <Label htmlFor="lookup-type">Type</Label>
          <Select value={type} onValueChange={(v) => setType(v as LookupType)}>
            <SelectTrigger id="lookup-type" className="w-full sm:w-28">
              <SelectValue />
            </SelectTrigger>
            <SelectContent>
              {lookupTypes.map((t) => (
                <SelectItem key={t} value={t}>
                  {t}
                </SelectItem>
              ))}
            </SelectContent>
          </Select>
        </div>
        <Button type="submit" disabled={lookup.isPending || !name.trim()}>
          {lookup.isPending ? <Loader2 className="animate-spin" /> : <Search />}
          Résoudre
        </Button>
      </form>
      {lookup.isError && <p className="text-sm text-destructive">{errorMessage(lookup.error)}</p>}
      {lookup.data && <LookupResultView result={lookup.data} />}
    </div>
  )
}
