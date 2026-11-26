import * as React from "react"
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query"
import { Loader2 } from "lucide-react"
import { toast } from "sonner"
import { api, isApiError } from "@/api/client"
import { dnsSettingsQuery, dnsStatusQuery, qk } from "@/api/queries"
import type { DnsSettings } from "@/api/types"
import { Field } from "@/components/form-field"
import { BlockSpinner } from "@/components/spinner"
import { StatusDot } from "@/components/status-dot"
import { Button } from "@/components/ui/button"
import { Card, CardContent, CardDescription, CardFooter, CardHeader, CardTitle } from "@/components/ui/card"
import { Input } from "@/components/ui/input"
import { Textarea } from "@/components/ui/textarea"
import { hitRate, humanDuration, percent } from "@/lib/dns"
import { errorMessage } from "@/lib/errors"
import { isCidr, isIP, lines } from "@/lib/net"
import { CacheFlushForm } from "@/pages/dns/cache-flush"

type NumKey = "cacheSize" | "cacheMinTtl" | "cacheMaxTtl" | "cacheNegativeMaxTtl"
type Form = Record<NumKey, string> & { recursionNetworks: string; extraListenAddresses: string }

const limits: Record<NumKey, [number, number]> = {
  cacheSize: [0, 1_000_000],
  cacheMinTtl: [0, 86_400],
  cacheMaxTtl: [1, 604_800],
  cacheNegativeMaxTtl: [0, 86_400],
}

function toForm(s: DnsSettings): Form {
  return {
    cacheSize: String(s.cacheSize ?? 10000),
    cacheMinTtl: String(s.cacheMinTtl ?? 0),
    cacheMaxTtl: String(s.cacheMaxTtl ?? 86400),
    cacheNegativeMaxTtl: String(s.cacheNegativeMaxTtl ?? 300),
    recursionNetworks: (s.recursionNetworks ?? []).join("\n"),
    extraListenAddresses: (s.extraListenAddresses ?? []).join("\n"),
  }
}

const fmt = new Intl.NumberFormat("fr-FR")

function secondsHint(v: string, extra?: string) {
  const n = Number(v)
  const h = v.trim() && Number.isFinite(n) ? `= ${humanDuration(n)}` : ""
  return [h, extra].filter(Boolean).join(". ")
}

export function DnsTab() {
  return (
    <div className="space-y-6">
      <DnsStatusCard />
      <DnsSettingsForm />
    </div>
  )
}

function DnsStatusCard() {
  const status = useQuery(dnsStatusQuery)
  const s = status.data
  const listeners = s?.listeners ?? []
  const rate = hitRate(s?.cache?.hits, s?.cache?.misses)
  return (
    <Card>
      <CardHeader>
        <CardTitle>État du serveur DNS</CardTitle>
        <CardDescription>
          {s?.port ? `Port ${s.port}. ` : ""}Les adresses d'écoute viennent des interfaces où le DNS est activé.
        </CardDescription>
      </CardHeader>
      <CardContent className="space-y-6">
        {status.isPending ? (
          <BlockSpinner />
        ) : status.isError ? (
          <p className="text-sm text-destructive">{errorMessage(status.error)}</p>
        ) : (
          <>
            <div className="grid gap-3 sm:grid-cols-4">
              <Stat label="Entrées en cache" value={fmt.format(s?.cache?.entries ?? 0)} />
              <Stat label="Trouvées en cache" value={fmt.format(s?.cache?.hits ?? 0)} />
              <Stat label="Absentes du cache" value={fmt.format(s?.cache?.misses ?? 0)} />
              <Stat label="Taux de cache" value={rate === null ? "—" : percent(rate)} />
            </div>
            <div className="space-y-2">
              <p className="text-sm font-medium">Écoute</p>
              {listeners.length === 0 ? (
                <p className="text-sm text-muted-foreground">
                  Rien n'écoute : activez le DNS sur une interface qui a une adresse IP.
                </p>
              ) : (
                <ul className="divide-y rounded-lg border">
                  {listeners.map((l) => (
                    <li key={`${l.address}-${l.protocol}`} className="flex flex-wrap items-center gap-x-3 gap-y-1 px-3 py-2 text-sm">
                      <StatusDot tone={l.state === "listening" ? "ok" : "error"} />
                      <span className="font-mono">{l.address}</span>
                      <span className="text-xs text-muted-foreground uppercase">{l.protocol}</span>
                      {l.interface && <span className="text-xs text-muted-foreground">{l.interface}</span>}
                      <span className={l.state === "listening" ? "ml-auto text-xs text-success" : "ml-auto text-xs text-destructive"}>
                        {l.state === "listening" ? "écoute" : l.error || "erreur"}
                      </span>
                    </li>
                  ))}
                </ul>
              )}
            </div>
          </>
        )}
        <div className="space-y-2 border-t pt-4">
          <p className="text-sm font-medium">Vider le cache</p>
          <CacheFlushForm className="sm:max-w-lg" />
        </div>
      </CardContent>
    </Card>
  )
}

function Stat({ label, value }: { label: string; value: string }) {
  return (
    <div className="rounded-lg border p-3">
      <div className="text-xl font-semibold tabular-nums">{value}</div>
      <div className="text-xs text-muted-foreground">{label}</div>
    </div>
  )
}

function DnsSettingsForm() {
  const qc = useQueryClient()
  const settings = useQuery(dnsSettingsQuery)
  const [form, setForm] = React.useState<Form | null>(null)
  const [errors, setErrors] = React.useState<Record<string, string>>({})

  React.useEffect(() => {
    if (settings.data) setForm(toForm(settings.data))
  }, [settings.data])

  const save = useMutation({
    mutationFn: (body: DnsSettings) => api.put("/dns/settings", { body }),
    meta: { silent: true },
    onSuccess: (s) => {
      qc.setQueryData(qk.dnsSettings, s)
      void qc.invalidateQueries({ queryKey: qk.dnsStatus })
      setErrors({})
      toast.success("Paramètres DNS enregistrés.")
    },
    onError: (e) => {
      // Keys may point inside a list ("recursionNetworks[2]"): show them on the list field.
      const errs: Record<string, string> = {}
      if (isApiError(e) && e.errors)
        for (const [k, m] of Object.entries(e.errors)) {
          const base = k.split(/[.[]/)[0]
          errs[base] = errs[base] ? `${errs[base]} ${m}` : m
        }
      setErrors(errs)
      toast.error(errorMessage(e))
    },
  })

  if (settings.isPending || !form)
    return settings.isError ? <p className="text-sm text-destructive">{errorMessage(settings.error)}</p> : <BlockSpinner />

  const set = <K extends keyof Form>(k: K, v: Form[K]) => setForm({ ...form, [k]: v })

  const submit = (e: React.FormEvent) => {
    e.preventDefault()
    const errs: Record<string, string> = {}
    const nums = {} as Record<NumKey, number>
    for (const k of Object.keys(limits) as NumKey[]) {
      const n = Number(form[k])
      const [min, max] = limits[k]
      if (!form[k].trim() || !Number.isInteger(n) || n < min || n > max) errs[k] = `Entre ${fmt.format(min)} et ${fmt.format(max)}.`
      else nums[k] = n
    }
    if (!errs.cacheMinTtl && !errs.cacheMaxTtl && nums.cacheMinTtl > nums.cacheMaxTtl)
      errs.cacheMaxTtl = "Doit être supérieur ou égal au TTL minimum."
    const networks = lines(form.recursionNetworks)
    const badNet = networks.filter((n) => !isCidr(n))
    if (badNet.length) errs.recursionNetworks = `Réseau non valide : ${badNet.join(", ")} (format attendu : 192.168.1.0/24).`
    const addrs = lines(form.extraListenAddresses)
    const badIp = addrs.filter((a) => !isIP(a))
    if (badIp.length) errs.extraListenAddresses = `Adresse non valide : ${badIp.join(", ")}.`
    setErrors(errs)
    if (Object.keys(errs).length) return
    save.mutate({ ...nums, recursionNetworks: networks, extraListenAddresses: addrs })
  }

  const cacheOff = form.cacheSize.trim() === "0"

  return (
    <form onSubmit={submit}>
      <Card>
        <CardHeader>
          <CardTitle>Réglages DNS</CardTitle>
          <CardDescription>Cache, accès à la résolution externe et adresses d'écoute.</CardDescription>
        </CardHeader>
        <CardContent className="space-y-8">
          <div className="grid gap-6 sm:grid-cols-2">
            <Field
              label="Taille du cache (entrées)"
              htmlFor="dns-cache-size"
              help={cacheOff ? "0 = cache désactivé." : "0 désactive le cache."}
              error={errors.cacheSize}
            >
              <Input id="dns-cache-size" inputMode="numeric" value={form.cacheSize} onChange={(e) => set("cacheSize", e.target.value)} />
            </Field>
            <div className="hidden sm:block" />
            <Field
              label="TTL minimum (secondes)"
              htmlFor="dns-min-ttl"
              help={secondsHint(form.cacheMinTtl, "Une réponse reste au moins ce temps en cache")}
              error={errors.cacheMinTtl}
            >
              <Input id="dns-min-ttl" inputMode="numeric" value={form.cacheMinTtl} onChange={(e) => set("cacheMinTtl", e.target.value)} />
            </Field>
            <Field
              label="TTL maximum (secondes)"
              htmlFor="dns-max-ttl"
              help={secondsHint(form.cacheMaxTtl, "Une réponse ne reste jamais plus longtemps")}
              error={errors.cacheMaxTtl}
            >
              <Input id="dns-max-ttl" inputMode="numeric" value={form.cacheMaxTtl} onChange={(e) => set("cacheMaxTtl", e.target.value)} />
            </Field>
            <Field
              label="TTL négatif maximum (secondes)"
              htmlFor="dns-neg-ttl"
              help={secondsHint(form.cacheNegativeMaxTtl, "Durée max. en cache d'un « nom inconnu »")}
              error={errors.cacheNegativeMaxTtl}
            >
              <Input
                id="dns-neg-ttl"
                inputMode="numeric"
                value={form.cacheNegativeMaxTtl}
                onChange={(e) => set("cacheNegativeMaxTtl", e.target.value)}
              />
            </Field>
          </div>

          <Field
            label="Réseaux autorisés pour la récursion"
            htmlFor="dns-recursion"
            help="Un réseau par ligne. Les zones locales répondent à tout le monde ; seuls ces réseaux peuvent résoudre des noms externes."
            error={errors.recursionNetworks}
          >
            <Textarea
              id="dns-recursion"
              rows={4}
              className="font-mono text-sm"
              spellCheck={false}
              placeholder={"192.168.0.0/16\n10.0.0.0/8"}
              value={form.recursionNetworks}
              onChange={(e) => set("recursionNetworks", e.target.value)}
            />
          </Field>

          <Field
            label="Adresses d'écoute supplémentaires"
            htmlFor="dns-extra"
            help="Une IP par ligne, en plus des interfaces activées. Ex. : 127.0.0.1 pour l'hôte lui-même."
            error={errors.extraListenAddresses}
          >
            <Textarea
              id="dns-extra"
              rows={3}
              className="font-mono text-sm"
              spellCheck={false}
              placeholder="127.0.0.1"
              value={form.extraListenAddresses}
              onChange={(e) => set("extraListenAddresses", e.target.value)}
            />
          </Field>
        </CardContent>
        <CardFooter className="justify-end gap-2 border-t pt-6">
          <Button
            type="button"
            variant="ghost"
            onClick={() => {
              if (settings.data) setForm(toForm(settings.data))
              setErrors({})
            }}
          >
            Annuler
          </Button>
          <Button type="submit" disabled={save.isPending}>
            {save.isPending && <Loader2 className="animate-spin" />}
            Enregistrer
          </Button>
        </CardFooter>
      </Card>
    </form>
  )
}
