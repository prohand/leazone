import * as React from "react"
import { Link } from "react-router"
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query"
import { Info, Loader2, Plus, Sparkles, TriangleAlert, X } from "lucide-react"
import { toast } from "sonner"
import { api } from "@/api/client"
import { dhcpStatusQuery, interfacesQuery, qk, vlansQuery } from "@/api/queries"
import type { DhcpOptionType, NetInterface, Scope, ScopeInput, ScopeMode } from "@/api/types"
import { ListInput, ModeBadge, SwitchRow } from "@/components/dhcp"
import { Field, FormError } from "@/components/form-field"
import { Button } from "@/components/ui/button"
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog"
import { Input } from "@/components/ui/input"
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select"
import { Switch } from "@/components/ui/switch"
import {
  checkOptionValue,
  ipToInt,
  modeHelp,
  net4String,
  netContains,
  optionTypes,
  parseNet4,
  reverseZoneOf,
  suggestRange,
  type Net4,
} from "@/lib/dhcp"
import { fieldError, formError } from "@/lib/errors"
import { isIPv4 } from "@/lib/net"
import { cn } from "@/lib/utils"

type Unit = "min" | "h" | "j"
const unitSeconds: Record<Unit, number> = { min: 60, h: 3600, j: 86400 }

type OptionRow = { code: string; type: DhcpOptionType; value: string }

type Form = {
  name: string
  vlanId: string
  enabled: boolean
  network: string
  rangeStart: string
  rangeEnd: string
  exclusions: { start: string; end: string }[]
  gateway: string
  dnsServers: string[]
  domain: string
  ntpServers: string[]
  leaseValue: string
  leaseUnit: Unit
  options: OptionRow[]
  direct: boolean
  interface: string
  relay: boolean
  relayAgents: string[]
  ddnsEnabled: boolean
  ddnsDomain: string
  pingCheck: boolean
  alertThreshold: string
}

const emptyForm = (): Form => ({
  name: "",
  vlanId: "",
  enabled: true,
  network: "",
  rangeStart: "",
  rangeEnd: "",
  exclusions: [],
  gateway: "",
  dnsServers: [],
  domain: "",
  ntpServers: [],
  leaseValue: "1",
  leaseUnit: "j",
  options: [],
  direct: true,
  interface: "",
  relay: false,
  relayAgents: [],
  ddnsEnabled: true,
  ddnsDomain: "",
  pingCheck: false,
  alertThreshold: "80",
})

function splitLease(seconds?: number): { leaseValue: string; leaseUnit: Unit } {
  const s = seconds && seconds > 0 ? seconds : 86400
  if (s % 86400 === 0) return { leaseValue: String(s / 86400), leaseUnit: "j" }
  if (s % 3600 === 0) return { leaseValue: String(s / 3600), leaseUnit: "h" }
  return { leaseValue: String(Math.max(1, Math.round(s / 60))), leaseUnit: "min" }
}

function toForm(s: Scope): Form {
  return {
    name: s.name ?? "",
    vlanId: s.vlanId != null ? String(s.vlanId) : "",
    enabled: s.enabled !== false,
    network: s.network ?? "",
    rangeStart: s.rangeStart ?? "",
    rangeEnd: s.rangeEnd ?? "",
    exclusions: (s.exclusions ?? []).map((r) => ({ start: r.start, end: r.end })),
    gateway: s.gateway ?? "",
    dnsServers: s.dnsServers ?? [],
    domain: s.domain ?? "",
    ntpServers: s.ntpServers ?? [],
    ...splitLease(s.leaseTime),
    options: (s.options ?? []).map((o) => ({ code: String(o.code), type: o.type, value: o.value })),
    direct: !!s.interface,
    interface: s.interface ?? "",
    relay: !!s.relay,
    relayAgents: s.relayAgents ?? [],
    ddnsEnabled: s.ddnsEnabled !== false,
    ddnsDomain: s.ddnsDomain ?? "",
    pingCheck: !!s.pingCheck,
    alertThreshold: String(s.alertThreshold ?? 80),
  }
}

/** Drop empty list rows before validation, so error indexes match what is sent. */
function clean(f: Form): Form {
  const t = (l: string[]) => l.map((x) => x.trim()).filter(Boolean)
  return {
    ...f,
    exclusions: f.exclusions
      .map((r) => ({ start: r.start.trim(), end: r.end.trim() }))
      .filter((r) => r.start || r.end)
      .map((r) => ({ start: r.start, end: r.end || r.start })),
    dnsServers: t(f.dnsServers),
    ntpServers: t(f.ntpServers),
    relayAgents: t(f.relayAgents),
    options: f.options.filter((o) => o.code.trim() || o.value.trim()),
  }
}

function toInput(f: Form): ScopeInput {
  return {
    name: f.name.trim(),
    vlanId: f.vlanId.trim() ? Number(f.vlanId) : null,
    enabled: f.enabled,
    network: f.network.trim(),
    rangeStart: f.rangeStart.trim(),
    rangeEnd: f.rangeEnd.trim(),
    exclusions: f.exclusions,
    leaseTime: Math.round(Number(f.leaseValue.replace(",", ".")) * unitSeconds[f.leaseUnit]),
    gateway: f.gateway.trim(),
    dnsServers: f.dnsServers,
    domain: f.domain.trim().replace(/\.$/, ""),
    ntpServers: f.ntpServers,
    options: f.options.map((o) => ({ code: Number(o.code), type: o.type, value: o.value.trim() })),
    interface: f.direct && f.interface ? f.interface : null,
    relay: f.relay,
    relayAgents: f.relay ? f.relayAgents : [],
    ddnsEnabled: f.ddnsEnabled,
    ddnsDomain: f.ddnsDomain.trim().replace(/\.$/, ""),
    pingCheck: f.pingCheck,
    alertThreshold: Number(f.alertThreshold),
  }
}

const domainRe = /^[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?)*\.?$/

function validate(f: Form): Record<string, string> {
  const e: Record<string, string> = {}
  const net = parseNet4(f.network)
  const inNet = (ip: string) => netContains(net, ip)
  if (!f.name.trim()) e.name = "Obligatoire."
  if (f.vlanId.trim()) {
    const v = Number(f.vlanId)
    if (!/^\d+$/.test(f.vlanId.trim()) || v < 1 || v > 4094) e.vlanId = "Numéro entre 1 et 4094."
  }
  if (!f.network.trim()) e.network = "Obligatoire."
  else if (!net) e.network = "Réseau IPv4 non valide (ex. : 192.168.20.0/24)."
  for (const k of ["rangeStart", "rangeEnd"] as const) {
    const v = f[k].trim()
    if (!v) e[k] = "Obligatoire."
    else if (!isIPv4(v)) e[k] = "Adresse IPv4 non valide."
    else if (net && !inNet(v)) e[k] = `Hors du réseau ${net4String(net)}.`
  }
  if (!e.rangeStart && !e.rangeEnd && (ipToInt(f.rangeStart) ?? 0) > (ipToInt(f.rangeEnd) ?? 0))
    e.rangeEnd = "La fin doit être après le début."
  f.exclusions.forEach((r, i) => {
    if (!isIPv4(r.start) || !isIPv4(r.end)) e[`exclusions[${i}]`] = "Adresses IPv4 attendues."
    else if ((ipToInt(r.start) ?? 0) > (ipToInt(r.end) ?? 0)) e[`exclusions[${i}]`] = "La fin doit être après le début."
    else if (net && (!inNet(r.start) || !inNet(r.end))) e[`exclusions[${i}]`] = "Hors du réseau de l'étendue."
  })
  const lease = Number(f.leaseValue.replace(",", "."))
  if (!(lease > 0)) e.leaseTime = "Durée positive."
  else if (lease * unitSeconds[f.leaseUnit] < 60) e.leaseTime = "Au moins 1 minute."
  if (f.gateway.trim()) {
    if (!isIPv4(f.gateway.trim())) e.gateway = "Adresse IPv4 non valide."
    else if (net && !inNet(f.gateway.trim())) e.gateway = "La passerelle doit être dans le réseau."
  }
  f.dnsServers.forEach((v, i) => !isIPv4(v) && (e[`dnsServers[${i}]`] = "Adresse IPv4 non valide."))
  f.ntpServers.forEach((v, i) => !isIPv4(v) && (e[`ntpServers[${i}]`] = "Adresse IPv4 non valide."))
  f.relayAgents.forEach((v, i) => !isIPv4(v) && (e[`relayAgents[${i}]`] = "Adresse IPv4 non valide."))
  if (f.domain.trim() && !domainRe.test(f.domain.trim())) e.domain = "Nom de domaine non valide."
  f.options.forEach((o, i) => {
    const c = Number(o.code)
    if (!/^\d+$/.test(o.code.trim()) || c < 1 || c > 254) e[`options[${i}].code`] = "Code entre 1 et 254."
    const m = checkOptionValue(o.type, o.value)
    if (m) e[`options[${i}].value`] = m
  })
  if (f.direct && !f.interface) e.interface = "Choisissez l'interface du VLAN, ou désactivez le mode direct."
  if (f.ddnsEnabled && f.ddnsDomain.trim() && !domainRe.test(f.ddnsDomain.trim()))
    e.ddnsDomain = "Nom de domaine non valide (ex. : invites.lan)."
  const t = Number(f.alertThreshold)
  if (!/^\d+$/.test(f.alertThreshold.trim()) || t < 1 || t > 100) e.alertThreshold = "Entre 1 et 100."
  return e
}

// Field keys the form shows next to a control (others go on the form-level line).
const shownKey = (k: string) =>
  /^(name|vlanId|enabled|network|rangeStart|rangeEnd|leaseTime|gateway|domain|interface|relay|ddnsEnabled|ddnsDomain|pingCheck|alertThreshold|options|exclusions|dnsServers|ntpServers|relayAgents)$/.test(
    k,
  ) || /^(exclusions|dnsServers|ntpServers|relayAgents|options)\[\d+\]/.test(k)

/** IPv4 addresses of an interface that fall inside `net`. */
function addressesIn(i: NetInterface, net: Net4 | null) {
  return (i.addresses ?? []).filter((a) => a.family !== "ipv6" && netContains(net, a.address ?? ""))
}

// Codes already set by the dedicated fields above.
const managedCodes: Record<number, string> = {
  1: "masque (déduit du réseau)",
  3: "Passerelle",
  6: "Serveurs DNS",
  15: "Domaine",
  42: "Serveurs NTP",
  51: "Durée du bail",
}

function Section({ title, description, children }: { title: string; description?: React.ReactNode; children: React.ReactNode }) {
  return (
    <section className="space-y-4 border-t pt-5 first:border-t-0 first:pt-0">
      <div className="space-y-0.5">
        <h3 className="text-sm font-semibold">{title}</h3>
        {description && <p className="text-xs text-muted-foreground">{description}</p>}
      </div>
      {children}
    </section>
  )
}

export function ScopeDialog({
  open,
  onOpenChange,
  scope,
  defaultVlanId,
}: {
  open: boolean
  onOpenChange: (o: boolean) => void
  /** null = new scope */
  scope: Scope | null
  defaultVlanId?: number
}) {
  const qc = useQueryClient()
  const ifaces = useQuery({ ...interfacesQuery, enabled: open, refetchInterval: open ? 10_000 : false })
  const vlans = useQuery({ ...vlansQuery, enabled: open, refetchInterval: false })
  const status = useQuery({ ...dhcpStatusQuery, enabled: open })
  const [form, setForm] = React.useState<Form>(emptyForm)
  const [local, setLocal] = React.useState<Record<string, string>>({})
  const [vlanChoice, setVlanChoice] = React.useState("none")
  // The range follows the network until the user types one.
  const [rangeTouched, setRangeTouched] = React.useState(false)
  const bodyRef = React.useRef<HTMLDivElement>(null)

  const save = useMutation({
    mutationFn: (body: ScopeInput) =>
      scope?.id ? api.put("/dhcp/scopes/{id}", { params: { id: scope.id }, body }) : api.post("/dhcp/scopes", { body }),
    meta: { silent: true },
    onSuccess: (s) => {
      void qc.invalidateQueries({ queryKey: qk.dhcp })
      void qc.invalidateQueries({ queryKey: qk.vlans })
      void qc.invalidateQueries({ queryKey: qk.zones })
      toast.success(scope ? "Étendue modifiée." : `Étendue « ${s.name} » créée.`, {
        description: !scope && (s.reverseZones ?? []).length > 0 ? `Zone inverse : ${(s.reverseZones ?? []).join(", ")}` : undefined,
      })
      onOpenChange(false)
    },
  })

  const knownVlans = React.useMemo(
    () =>
      (vlans.data?.items ?? [])
        .map((v) => ({ id: v.vlanId ?? 0, name: v.name ?? "" }))
        .filter((v) => v.id > 0)
        .sort((a, b) => a.id - b.id),
    [vlans.data],
  )

  React.useEffect(() => {
    if (!open) return
    const f = scope ? toForm(scope) : emptyForm()
    setForm(f)
    setLocal({})
    setRangeTouched(!!scope)
    setVlanChoice(f.vlanId ? f.vlanId : "none")
    save.reset()
    // Reset only when the dialog opens.
  }, [open])

  // Pre-select a VLAN given by the caller (e.g. "Créer une étendue" on a VLAN card), once data is there.
  const appliedDefault = React.useRef(false)
  React.useEffect(() => {
    if (!open) {
      appliedDefault.current = false
      return
    }
    if (scope || !defaultVlanId || appliedDefault.current || !ifaces.data || !vlans.data) return
    appliedDefault.current = true
    pickVlan(String(defaultVlanId))
  }, [open, scope, defaultVlanId, ifaces.data, vlans.data])

  // After a failed submit, bring the first field error into view.
  const scrollToError = () =>
    requestAnimationFrame(() => {
      const el = bodyRef.current?.querySelector('[data-slot="field-error"]')
      el?.scrollIntoView({ block: "center", behavior: "smooth" })
    })
  React.useEffect(() => {
    if (save.isError) scrollToError()
  }, [save.error])

  const set = (patch: Partial<Form>) => setForm((f) => ({ ...f, ...patch }))
  const err = (k: string) => local[k] ?? fieldError(save.error, k)
  const errItem = (prefix: string, i: number) =>
    err(`${prefix}[${i}]`) ?? err(`${prefix}[${i}].start`) ?? err(`${prefix}[${i}].end`)

  const net = parseNet4(form.network)
  const hostIfaces = React.useMemo(
    () => (ifaces.data?.items ?? []).filter((i) => i.type !== "loopback" && i.present !== false),
    [ifaces.data],
  )
  const sortedIfaces = React.useMemo(
    () =>
      [...hostIfaces].sort((a, b) => {
        const d = addressesIn(b, net).length - addressesIn(a, net).length
        return d !== 0 ? d : (a.name ?? "").localeCompare(b.name ?? "")
      }),
    [hostIfaces, form.network],
  )
  const chosenIface = hostIfaces.find((i) => i.name === form.interface)
  const chosenInNet = chosenIface ? addressesIn(chosenIface, net) : []

  /** Network (and range) from an interface address, when the form has none yet. */
  const fillFromIface = (f: Form, i: NetInterface | undefined): Form => {
    if (!i || f.network.trim()) return f
    const a = (i.addresses ?? []).find((x) => x.family !== "ipv6" && x.network)
    if (!a?.network) return f
    const r = !rangeTouched ? suggestRange(a.network) : null
    return { ...f, network: a.network, ...(r ? { rangeStart: r.start, rangeEnd: r.end } : {}) }
  }

  const pickVlan = (choice: string) => {
    setVlanChoice(choice)
    if (choice === "none" || choice === "other") {
      set({ vlanId: "" })
      return
    }
    const id = Number(choice)
    setForm((f) => {
      let next: Form = { ...f, vlanId: choice }
      const label = knownVlans.find((v) => v.id === id)?.name
      if (!f.name.trim() && label) next.name = `${id} - ${label}`
      // Suggest the host interface of this VLAN for direct mode.
      const iface = hostIfaces.find((i) => i.vlanId === id)
      if (iface && f.direct && !f.interface) next.interface = iface.name ?? ""
      next = fillFromIface(next, iface)
      return next
    })
  }

  const setNetwork = (v: string) => {
    setForm((f) => {
      const r = !rangeTouched ? suggestRange(v) : null
      return { ...f, network: v, ...(r ? { rangeStart: r.start, rangeEnd: r.end } : {}) }
    })
  }

  const pickIface = (name: string) => {
    const iface = hostIfaces.find((i) => i.name === name)
    let next: Form = { ...form, interface: name }
    if (!form.vlanId && iface?.vlanId) {
      next.vlanId = String(iface.vlanId)
      setVlanChoice(knownVlans.some((v) => v.id === iface.vlanId) ? String(iface.vlanId) : "other")
    }
    next = fillFromIface(next, iface)
    setForm(next)
  }

  const submit = (e: React.FormEvent) => {
    e.preventDefault()
    const f = clean(form)
    setForm(f)
    const errors = validate(f)
    setLocal(errors)
    save.reset()
    if (Object.keys(errors).length > 0) {
      scrollToError()
      return
    }
    save.mutate(toInput(f))
  }

  const mode: ScopeMode = form.direct && form.interface ? (form.relay ? "both" : "direct") : form.relay ? "relay" : "none"
  const suggestion = suggestRange(form.network)
  const reverse = reverseZoneOf(form.network)
  const pingUnavailable = status.data?.pingAvailable === false
  const hasLocalErrors = Object.keys(local).length > 0
  const placeholderIp = (last: number) => (net ? `${form.network.split(".").slice(0, 3).join(".")}.${last}` : `192.168.20.${last}`)

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="flex max-h-[92svh] flex-col gap-0 p-0 sm:max-w-3xl">
        <form onSubmit={submit} className="flex min-h-0 flex-1 flex-col" noValidate>
          <DialogHeader className="border-b px-6 pt-6 pb-4">
            <DialogTitle>{scope ? `Modifier « ${scope.name} »` : "Nouvelle étendue"}</DialogTitle>
            <DialogDescription>
              Plage d'adresses que Leazone distribue sur un réseau, avec les réglages envoyés aux clients.
            </DialogDescription>
          </DialogHeader>

          <div ref={bodyRef} className="min-h-0 flex-1 space-y-6 overflow-y-auto px-6 py-5">
            {/* ---- Général ---- */}
            <Section title="Général">
              <div className="grid gap-4 sm:grid-cols-2">
                <Field label="Nom" htmlFor="sc-name" error={err("name")}>
                  <Input id="sc-name" value={form.name} onChange={(e) => set({ name: e.target.value })} placeholder="20 - Invités" />
                </Field>
                <Field
                  label="VLAN"
                  htmlFor="sc-vlan"
                  error={err("vlanId")}
                  help={vlanChoice === "other" ? "Un nom de VLAN est créé s'il n'existe pas." : undefined}
                >
                  <div className="flex gap-2">
                    <Select value={vlanChoice} onValueChange={pickVlan}>
                      <SelectTrigger id="sc-vlan" className="w-full min-w-0 flex-1" aria-label="VLAN">
                        <SelectValue />
                      </SelectTrigger>
                      <SelectContent>
                        <SelectItem value="none">Aucun VLAN</SelectItem>
                        {knownVlans.map((v) => (
                          <SelectItem key={v.id} value={String(v.id)}>
                            {v.name ? `${v.id} - ${v.name}` : `VLAN ${v.id}`}
                          </SelectItem>
                        ))}
                        <SelectItem value="other">Autre numéro…</SelectItem>
                      </SelectContent>
                    </Select>
                    {vlanChoice === "other" && (
                      <Input
                        aria-label="Numéro de VLAN"
                        inputMode="numeric"
                        className="w-24"
                        autoFocus
                        value={form.vlanId}
                        onChange={(e) => set({ vlanId: e.target.value })}
                        placeholder="1-4094"
                      />
                    )}
                  </div>
                </Field>
              </div>
              <SwitchRow id="sc-enabled" title="Étendue activée" description="Désactivée : Leazone ne répond plus aux clients de ce réseau.">
                <Switch id="sc-enabled" checked={form.enabled} onCheckedChange={(v) => set({ enabled: v })} />
              </SwitchRow>
            </Section>

            {/* ---- Réseau ---- */}
            <Section title="Réseau" description="Adresses que les clients peuvent recevoir.">
              <Field label="Réseau" htmlFor="sc-network" error={err("network")} help={net ? `${net.size - 2} adresses utilisables.` : "Ex. : 192.168.20.0/24"}>
                <Input
                  id="sc-network"
                  className="font-mono sm:max-w-64"
                  autoCapitalize="none"
                  spellCheck={false}
                  value={form.network}
                  onChange={(e) => setNetwork(e.target.value)}
                  onBlur={() => net && form.network !== net4String(net) && set({ network: net4String(net) })}
                  placeholder="192.168.20.0/24"
                />
              </Field>
              <div className="space-y-2">
                <div className="grid gap-4 sm:grid-cols-2">
                  <Field label="Début de plage" htmlFor="sc-start" error={err("rangeStart")}>
                    <Input
                      id="sc-start"
                      className="font-mono"
                      value={form.rangeStart}
                      onChange={(e) => {
                        setRangeTouched(true)
                        set({ rangeStart: e.target.value })
                      }}
                      placeholder={placeholderIp(100)}
                    />
                  </Field>
                  <Field label="Fin de plage" htmlFor="sc-end" error={err("rangeEnd")}>
                    <Input
                      id="sc-end"
                      className="font-mono"
                      value={form.rangeEnd}
                      onChange={(e) => {
                        setRangeTouched(true)
                        set({ rangeEnd: e.target.value })
                      }}
                      placeholder={placeholderIp(199)}
                    />
                  </Field>
                </div>
                {suggestion && (form.rangeStart !== suggestion.start || form.rangeEnd !== suggestion.end) && (
                  <Button
                    type="button"
                    variant="link"
                    size="sm"
                    className="h-auto px-0 text-xs"
                    onClick={() => set({ rangeStart: suggestion.start, rangeEnd: suggestion.end })}
                  >
                    <Sparkles /> Proposer {suggestion.start} – {suggestion.end}
                  </Button>
                )}
              </div>
              <div className="space-y-2">
                <p className="text-sm font-medium">Exclusions</p>
                <p className="text-xs text-muted-foreground">Adresses de la plage à ne jamais donner (ex. : imprimantes en IP fixe).</p>
                {form.exclusions.map((r, i) => {
                  const e = errItem("exclusions", i)
                  return (
                    <div key={i} className="space-y-1">
                      <div className="flex items-center gap-2">
                        <Input
                          aria-label={`Exclusion ${i + 1} : début`}
                          className="font-mono"
                          value={r.start}
                          aria-invalid={!!e || undefined}
                          onChange={(ev) =>
                            set({ exclusions: form.exclusions.map((x, j) => (j === i ? { ...x, start: ev.target.value } : x)) })
                          }
                          placeholder={placeholderIp(150)}
                        />
                        <span className="text-muted-foreground">–</span>
                        <Input
                          aria-label={`Exclusion ${i + 1} : fin`}
                          className="font-mono"
                          value={r.end}
                          aria-invalid={!!e || undefined}
                          onChange={(ev) =>
                            set({ exclusions: form.exclusions.map((x, j) => (j === i ? { ...x, end: ev.target.value } : x)) })
                          }
                          placeholder={placeholderIp(159)}
                        />
                        <Button
                          type="button"
                          variant="ghost"
                          size="icon-sm"
                          aria-label="Retirer l'exclusion"
                          className="text-muted-foreground hover:text-destructive"
                          onClick={() => set({ exclusions: form.exclusions.filter((_, j) => j !== i) })}
                        >
                          <X />
                        </Button>
                      </div>
                      {e && (
                        <p data-slot="field-error" className="text-sm text-destructive">
                          {e}
                        </p>
                      )}
                    </div>
                  )
                })}
                {err("exclusions") && (
                  <p data-slot="field-error" className="text-sm text-destructive">
                    {err("exclusions")}
                  </p>
                )}
                <Button
                  type="button"
                  variant="outline"
                  size="sm"
                  onClick={() => set({ exclusions: [...form.exclusions, { start: "", end: "" }] })}
                >
                  <Plus /> Ajouter une exclusion
                </Button>
              </div>
            </Section>

            {/* ---- Options ---- */}
            <Section title="Options" description="Réglages envoyés aux clients avec leur adresse.">
              <div className="grid gap-4 sm:grid-cols-2">
                <Field label="Passerelle" htmlFor="sc-gateway" error={err("gateway")} help="Le routeur du réseau.">
                  <Input
                    id="sc-gateway"
                    className="font-mono"
                    value={form.gateway}
                    onChange={(e) => set({ gateway: e.target.value })}
                    placeholder={placeholderIp(1)}
                  />
                </Field>
                <Field label="Durée du bail" htmlFor="sc-lease" error={err("leaseTime")} help="Les clients renouvellent à mi-parcours.">
                  <div className="flex gap-2">
                    <Input
                      id="sc-lease"
                      inputMode="decimal"
                      className="w-24"
                      value={form.leaseValue}
                      onChange={(e) => set({ leaseValue: e.target.value })}
                    />
                    <Select value={form.leaseUnit} onValueChange={(v) => set({ leaseUnit: v as Unit })}>
                      <SelectTrigger className="w-32" aria-label="Unité de la durée">
                        <SelectValue />
                      </SelectTrigger>
                      <SelectContent>
                        <SelectItem value="min">minutes</SelectItem>
                        <SelectItem value="h">heures</SelectItem>
                        <SelectItem value="j">jours</SelectItem>
                      </SelectContent>
                    </Select>
                  </div>
                </Field>
              </div>
              <div className="grid gap-4 sm:grid-cols-2">
                <Field label="Serveurs DNS" htmlFor="sc-dns" error={err("dnsServers")} help="En général l'adresse de Leazone sur ce réseau.">
                  <ListInput
                    id="sc-dns"
                    values={form.dnsServers}
                    onChange={(v) => set({ dnsServers: v })}
                    placeholder={chosenInNet[0]?.address ?? placeholderIp(1)}
                    addLabel="Ajouter un serveur DNS"
                    errorAt={(i) => err(`dnsServers[${i}]`)}
                  />
                </Field>
                <Field label="Serveurs NTP" htmlFor="sc-ntp" error={err("ntpServers")} help="Facultatif : serveurs d'heure.">
                  <ListInput
                    id="sc-ntp"
                    values={form.ntpServers}
                    onChange={(v) => set({ ntpServers: v })}
                    placeholder={placeholderIp(1)}
                    addLabel="Ajouter un serveur NTP"
                    errorAt={(i) => err(`ntpServers[${i}]`)}
                  />
                </Field>
              </div>
              <Field label="Domaine" htmlFor="sc-domain" error={err("domain")} help="Suffixe donné aux clients (option 15).">
                <Input
                  id="sc-domain"
                  className="sm:max-w-64"
                  autoCapitalize="none"
                  spellCheck={false}
                  value={form.domain}
                  onChange={(e) => set({ domain: e.target.value })}
                  placeholder="invites.lan"
                />
              </Field>
              <CustomOptions form={form} set={set} err={err} />
            </Section>

            {/* ---- Mode de service ---- */}
            <Section
              title="Mode de service"
              description={
                <span className="inline-flex flex-wrap items-center gap-2">
                  Mode obtenu : <ModeBadge mode={mode} /> <span>{modeHelp[mode]}</span>
                </span>
              }
            >
              <div className="space-y-3 rounded-lg border p-3">
                <div className="flex items-center justify-between gap-3">
                  <label htmlFor="sc-direct" className="flex flex-col gap-0.5 text-sm">
                    <span className="font-medium">Direct</span>
                    <span className="text-xs text-muted-foreground">Leazone a une patte dans le VLAN et répond lui-même sur cette interface.</span>
                  </label>
                  <Switch id="sc-direct" checked={form.direct} onCheckedChange={(v) => set({ direct: v })} />
                </div>
                {form.direct && (
                  <Field label="Interface" htmlFor="sc-iface" error={err("interface")}>
                    <Select value={form.interface || "__none"} onValueChange={(v) => pickIface(v === "__none" ? "" : v)}>
                      <SelectTrigger id="sc-iface" className="w-full">
                        <SelectValue />
                      </SelectTrigger>
                      <SelectContent>
                        <SelectItem value="__none">Choisir une interface…</SelectItem>
                        {form.interface && !chosenIface && (
                          <SelectItem value={form.interface}>{form.interface} (absente de l'hôte)</SelectItem>
                        )}
                        {sortedIfaces.map((i) => {
                          const inNet = addressesIn(i, net)
                          const v4 = (i.addresses ?? []).filter((a) => a.family !== "ipv6")
                          return (
                            <SelectItem key={i.name} value={i.name ?? ""}>
                              <span className="font-medium">{i.name}</span>
                              <span className="font-mono text-xs text-muted-foreground">
                                {v4.length ? v4.map((a) => `${a.address}/${a.prefixLength}`).join(", ") : "aucune IPv4"}
                              </span>
                              {inNet.length > 0 && <span className="text-xs text-success">dans le réseau</span>}
                            </SelectItem>
                          )
                        })}
                      </SelectContent>
                    </Select>
                    {chosenIface && net && chosenInNet.length === 0 && (
                      <p className="flex items-start gap-1.5 text-xs text-warning">
                        <TriangleAlert className="mt-px size-3.5 shrink-0" />
                        <span>
                          {chosenIface.name} n'a pas d'adresse dans {net4String(net)} : donnez-lui une IP de ce réseau sur l'hôte, sinon les
                          clients ne recevront rien.
                        </span>
                      </p>
                    )}
                    {chosenIface && chosenIface.dhcpEnabled === false && (
                      <p className="flex items-start gap-1.5 text-xs text-muted-foreground">
                        <Info className="mt-px size-3.5 shrink-0" />
                        <span>
                          Le DHCP est désactivé sur {chosenIface.name}. Activez-le dans{" "}
                          <Link to="/interfaces" className="underline underline-offset-2" onClick={() => onOpenChange(false)}>
                            Interfaces
                          </Link>
                          .
                        </span>
                      </p>
                    )}
                  </Field>
                )}
              </div>
              <div className="space-y-3 rounded-lg border p-3">
                <div className="flex items-center justify-between gap-3">
                  <label htmlFor="sc-relay" className="flex flex-col gap-0.5 text-sm">
                    <span className="font-medium">Relais</span>
                    <span className="text-xs text-muted-foreground">
                      Le routeur du VLAN relaie les demandes vers Leazone (ip helper-address).
                    </span>
                  </label>
                  <Switch id="sc-relay" checked={form.relay} onCheckedChange={(v) => set({ relay: v })} />
                </div>
                {form.relay && (
                  <Field
                    label="Agents relais supplémentaires"
                    htmlFor="sc-relays"
                    error={err("relayAgents")}
                    help="Facultatif : adresses de relais (giaddr) hors du réseau de l'étendue. Celles du réseau sont acceptées d'office."
                  >
                    <ListInput
                      id="sc-relays"
                      values={form.relayAgents}
                      onChange={(v) => set({ relayAgents: v })}
                      placeholder="10.255.0.2"
                      addLabel="Ajouter un agent relais"
                      errorAt={(i) => err(`relayAgents[${i}]`)}
                    />
                  </Field>
                )}
              </div>
              {mode === "none" && (
                <p className="flex items-center gap-1.5 text-xs text-warning">
                  <TriangleAlert className="size-3.5" /> Sans mode direct ni relais, l'étendue ne sert aucun client.
                </p>
              )}
            </Section>

            {/* ---- DNS automatique ---- */}
            <Section title="DNS automatique" description="Les clients reçoivent un nom dans le DNS, ex. : pc-marie.invites.lan.">
              <SwitchRow id="sc-ddns" title="Enregistrer les clients dans le DNS">
                <Switch id="sc-ddns" checked={form.ddnsEnabled} onCheckedChange={(v) => set({ ddnsEnabled: v })} />
              </SwitchRow>
              {form.ddnsEnabled && (
                <Field label="Domaine DNS" htmlFor="sc-ddns-domain" error={err("ddnsDomain")} help="La zone est créée si besoin.">
                  <Input
                    id="sc-ddns-domain"
                    className="sm:max-w-64"
                    autoCapitalize="none"
                    spellCheck={false}
                    value={form.ddnsDomain}
                    onChange={(e) => set({ ddnsDomain: e.target.value })}
                    placeholder={form.domain || "invites.lan"}
                  />
                </Field>
              )}
              <p className="flex items-start gap-1.5 text-xs text-muted-foreground">
                <Info className="mt-px size-3.5 shrink-0" />
                <span>
                  La zone inverse
                  {(scope?.reverseZones ?? []).length > 0 ? (
                    <span className="font-mono"> {(scope?.reverseZones ?? []).join(", ")}</span>
                  ) : reverse ? (
                    <span className="font-mono"> {reverse}</span>
                  ) : null}{" "}
                  est créée automatiquement avec l'étendue.
                </span>
              </p>
            </Section>

            {/* ---- Avancé ---- */}
            <Section title="Avancé">
              <SwitchRow
                id="sc-ping"
                title="Ping avant attribution"
                description="Vérifie qu'aucun appareil n'utilise déjà l'adresse avant de la donner (300 ms de plus)."
              >
                <Switch id="sc-ping" checked={form.pingCheck} onCheckedChange={(v) => set({ pingCheck: v })} />
              </SwitchRow>
              {pingUnavailable && (
                <p className="flex items-start gap-1.5 text-xs text-warning">
                  <TriangleAlert className="mt-px size-3.5 shrink-0" />
                  <span>Le ping ne fonctionne pas sur ce serveur : il manque la capacité NET_RAW. Le réglage est gardé mais sans effet.</span>
                </p>
              )}
              <Field label="Seuil d'alerte" htmlFor="sc-alert" error={err("alertThreshold")} help="La carte du VLAN passe en rouge au-delà de ce remplissage.">
                <div className="flex items-center gap-2">
                  <Input
                    id="sc-alert"
                    inputMode="numeric"
                    className="w-20"
                    value={form.alertThreshold}
                    onChange={(e) => set({ alertThreshold: e.target.value })}
                  />
                  <span className="text-sm text-muted-foreground">%</span>
                </div>
              </Field>
            </Section>
          </div>

          <div className="space-y-3 border-t px-6 py-4">
            {hasLocalErrors && <FormError message="Corrigez les champs en rouge." />}
            <FormError message={formError(save.error, shownKey) ?? (save.error && !hasLocalErrors ? "Corrigez les champs en rouge." : undefined)} />
            <DialogFooter>
              <Button type="button" variant="ghost" onClick={() => onOpenChange(false)}>
                Annuler
              </Button>
              <Button type="submit" disabled={save.isPending}>
                {save.isPending && <Loader2 className="animate-spin" />}
                {scope ? "Enregistrer" : "Créer l'étendue"}
              </Button>
            </DialogFooter>
          </div>
        </form>
      </DialogContent>
    </Dialog>
  )
}

function CustomOptions({
  form,
  set,
  err,
}: {
  form: Form
  set: (p: Partial<Form>) => void
  err: (k: string) => string | undefined
}) {
  const update = (i: number, patch: Partial<OptionRow>) =>
    set({ options: form.options.map((o, j) => (j === i ? { ...o, ...patch } : o)) })
  return (
    <div className="space-y-2">
      <p className="text-sm font-medium">Options personnalisées</p>
      <p className="text-xs text-muted-foreground">
        Pour les options non prévues ci-dessus. Ex. : 66 = serveur TFTP (texte), 67 = fichier de démarrage (texte), 150 = TFTP
        Cisco (IP). Valeurs : listes séparées par des virgules, hexadécimal en octets (01:02:0a).
      </p>
      {form.options.length > 0 && (
        <div className="space-y-2">
          <div className="hidden grid-cols-[5rem_10rem_1fr_2rem] gap-2 text-xs text-muted-foreground sm:grid">
            <span>Code</span>
            <span>Type</span>
            <span>Valeur</span>
          </div>
          {form.options.map((o, i) => {
            const codeErr = err(`options[${i}].code`)
            const valueErr = err(`options[${i}].value`) ?? err(`options[${i}].type`) ?? err(`options[${i}]`)
            const managed = managedCodes[Number(o.code)]
            const ph = optionTypes.find((t) => t.value === o.type)?.placeholder
            return (
              <div key={i} className="space-y-1 rounded-lg border p-2 sm:rounded-none sm:border-0 sm:p-0">
                <div className="grid grid-cols-[5rem_1fr_2rem] gap-2 sm:grid-cols-[5rem_10rem_1fr_2rem]">
                  <Input
                    aria-label={`Option ${i + 1} : code`}
                    inputMode="numeric"
                    value={o.code}
                    aria-invalid={!!codeErr || undefined}
                    onChange={(e) => update(i, { code: e.target.value })}
                    placeholder="66"
                  />
                  <Select value={o.type} onValueChange={(v) => update(i, { type: v as DhcpOptionType })}>
                    <SelectTrigger aria-label={`Option ${i + 1} : type`} className="w-full">
                      <SelectValue />
                    </SelectTrigger>
                    <SelectContent>
                      {optionTypes.map((t) => (
                        <SelectItem key={t.value} value={t.value}>
                          {t.label}
                        </SelectItem>
                      ))}
                    </SelectContent>
                  </Select>
                  <Input
                    aria-label={`Option ${i + 1} : valeur`}
                    className="col-span-2 font-mono sm:col-span-1 max-sm:order-last"
                    value={o.value}
                    aria-invalid={!!valueErr || undefined}
                    onChange={(e) => update(i, { value: e.target.value })}
                    placeholder={ph}
                  />
                  <Button
                    type="button"
                    variant="ghost"
                    size="icon-sm"
                    aria-label="Retirer l'option"
                    className="self-center text-muted-foreground hover:text-destructive"
                    onClick={() => set({ options: form.options.filter((_, j) => j !== i) })}
                  >
                    <X />
                  </Button>
                </div>
                {codeErr && (
                  <p data-slot="field-error" className="text-sm text-destructive">
                    {codeErr}
                  </p>
                )}
                {valueErr && (
                  <p data-slot="field-error" className="text-sm text-destructive">
                    {valueErr}
                  </p>
                )}
                {managed && !codeErr && (
                  <p className={cn("text-xs text-warning")}>Option {o.code} déjà réglée par « {managed} » : celle-ci la remplace.</p>
                )}
              </div>
            )
          })}
        </div>
      )}
      {err("options") && (
        <p data-slot="field-error" className="text-sm text-destructive">
          {err("options")}
        </p>
      )}
      <Button
        type="button"
        variant="outline"
        size="sm"
        onClick={() => set({ options: [...form.options, { code: "", type: "string", value: "" }] })}
      >
        <Plus /> Ajouter une option
      </Button>
    </div>
  )
}
