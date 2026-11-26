import * as React from "react"
import { useMutation, useQueryClient } from "@tanstack/react-query"
import { FlaskConical, Loader2, TriangleAlert } from "lucide-react"
import { toast } from "sonner"
import { api } from "@/api/client"
import { qk } from "@/api/queries"
import type { Forwarder, ForwarderInput, ForwarderProtocol, ForwarderTest } from "@/api/types"
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
import { Label } from "@/components/ui/label"
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select"
import { Switch } from "@/components/ui/switch"
import { defaultPort, formatLatency, protocolLongLabel } from "@/lib/dns"
import { fieldError, formError } from "@/lib/errors"
import { isIP, urlHost } from "@/lib/net"
import { cn } from "@/lib/utils"

type Form = {
  domain: string
  protocol: ForwarderProtocol
  address: string
  port: string
  tlsServerName: string
  tlsVerify: boolean
  dohUrl: string
}

const protocols: ForwarderProtocol[] = ["udp", "tcp", "dot", "doh"]

const presets: { label: string; form: Partial<Form> }[] = [
  { label: "Quad9 DoT", form: { protocol: "dot", address: "9.9.9.9", port: "853", tlsServerName: "dns.quad9.net", tlsVerify: true, dohUrl: "" } },
  { label: "Cloudflare DoH", form: { protocol: "doh", dohUrl: "https://cloudflare-dns.com/dns-query", address: "1.1.1.1", port: "", tlsServerName: "", tlsVerify: true } },
  { label: "Google DoT", form: { protocol: "dot", address: "8.8.8.8", port: "853", tlsServerName: "dns.google", tlsVerify: true, dohUrl: "" } },
]

const emptyForm = (domain = ""): Form => ({
  domain,
  protocol: "udp",
  address: "",
  port: "53",
  tlsServerName: "",
  tlsVerify: true,
  dohUrl: "",
})

function toForm(f: Forwarder): Form {
  const protocol = f.protocol ?? "udp"
  return {
    domain: f.domain ?? "",
    protocol,
    address: f.address ?? "",
    port: f.port ? String(f.port) : protocol === "doh" ? "" : String(defaultPort[protocol]),
    tlsServerName: f.tlsServerName ?? "",
    tlsVerify: f.tlsVerify !== false,
    dohUrl: f.dohUrl ?? "",
  }
}

/** Body sent to the API: only the fields that make sense for the protocol. */
function toInput(f: Form, base?: Forwarder): ForwarderInput {
  const p = f.protocol
  const input: ForwarderInput = { domain: f.domain.trim().replace(/\.$/, ""), protocol: p }
  if (f.address.trim()) input.address = f.address.trim()
  if (p !== "doh" && f.port.trim()) input.port = Number(f.port)
  if (p === "dot") input.tlsServerName = f.tlsServerName.trim()
  if (p === "doh") input.dohUrl = f.dohUrl.trim()
  if (p === "dot" || p === "doh") input.tlsVerify = f.tlsVerify
  if (base) {
    input.enabled = base.enabled !== false
    if (base.position !== undefined) input.position = base.position
  }
  return input
}

function validate(f: Form): Record<string, string> {
  const e: Record<string, string> = {}
  const address = f.address.trim()
  if (f.domain.trim() && !/^[a-zA-Z0-9_]([a-zA-Z0-9_-]*[a-zA-Z0-9_])?(\.[a-zA-Z0-9_]([a-zA-Z0-9_-]*[a-zA-Z0-9_])?)*\.?$/.test(f.domain.trim()))
    e.domain = "Nom de domaine non valide (ex. : corp.local)."
  if (f.protocol === "doh") {
    const url = f.dohUrl.trim()
    const host = urlHost(url)
    if (!/^https:\/\//i.test(url) || !host) e.dohUrl = "Adresse https:// complète (ex. : https://dns.quad9.net/dns-query)."
    else if (!address && !isIP(host)) e.address = "Indiquez l'IP du serveur : le nom dans l'URL ne peut pas être résolu sans elle."
    if (address && !isIP(address)) e.address = "Adresse IP non valide."
  } else {
    if (!address) e.address = "Obligatoire."
    else if (!isIP(address)) e.address = "Adresse IP non valide (ex. : 9.9.9.9)."
    const port = Number(f.port)
    if (f.port.trim() && (!Number.isInteger(port) || port < 1 || port > 65535)) e.port = "Port entre 1 et 65535."
  }
  return e
}

export function TestResult({ result }: { result: ForwarderTest }) {
  const answers = result.answers ?? []
  return (
    <div
      aria-live="polite"
      className={cn(
        "space-y-2 rounded-lg border p-3 text-sm",
        result.ok ? "border-success/40 bg-success/5" : "border-destructive/40 bg-destructive/5",
      )}
    >
      <p className={cn("font-medium", result.ok ? "text-success" : "text-destructive")}>
        {result.ok
          ? `Réponse en ${formatLatency(result.latencyMs)}${result.rcode ? ` · ${result.rcode}` : ""}`
          : `Échec : ${result.error || "pas de réponse"}`}
      </p>
      {answers.length > 0 && (
        <pre className="overflow-x-auto font-mono text-xs leading-relaxed text-muted-foreground">{answers.join("\n")}</pre>
      )}
    </div>
  )
}

export function ForwarderDialog({
  open,
  onOpenChange,
  forwarder,
  defaultDomain = "",
}: {
  open: boolean
  onOpenChange: (o: boolean) => void
  /** null = new forwarder */
  forwarder: Forwarder | null
  defaultDomain?: string
}) {
  const qc = useQueryClient()
  const [form, setForm] = React.useState<Form>(() => emptyForm(defaultDomain))
  const [local, setLocal] = React.useState<Record<string, string>>({})

  const save = useMutation({
    mutationFn: (body: ForwarderInput) =>
      forwarder?.id
        ? api.put("/dns/forwarders/{id}", { params: { id: forwarder.id }, body })
        : api.post("/dns/forwarders", { body }),
    meta: { silent: true },
    onSuccess: () => {
      void qc.invalidateQueries({ queryKey: qk.forwarders })
      void qc.invalidateQueries({ queryKey: qk.dnsStatus })
      toast.success(forwarder ? "Redirecteur modifié." : "Redirecteur ajouté.")
      onOpenChange(false)
    },
  })

  const test = useMutation({
    mutationFn: (body: ForwarderInput) => api.post("/dns/forwarders/test", { body }),
    meta: { silent: true },
  })

  React.useEffect(() => {
    if (open) {
      setForm(forwarder ? toForm(forwarder) : emptyForm(defaultDomain))
      setLocal({})
      save.reset()
      test.reset()
    }
    // Reset only when the dialog opens.
  }, [open])

  const set = (patch: Partial<Form>) => {
    setForm((f) => ({ ...f, ...patch }))
    test.reset()
  }

  const setProtocol = (p: ForwarderProtocol) =>
    setForm((f) => {
      // Follow the protocol's default port unless the user typed another one.
      const wasDefault = !f.port || Number(f.port) === defaultPort[f.protocol]
      return { ...f, protocol: p, port: wasDefault ? (p === "doh" ? "" : String(defaultPort[p])) : f.port }
    })

  const err = (k: string) => local[k] ?? fieldError(save.error, k) ?? fieldError(test.error, k)
  const known = ["domain", "protocol", "address", "port", "tlsServerName", "tlsVerify", "dohUrl"]

  const check = () => {
    const e = validate(form)
    setLocal(e)
    return Object.keys(e).length === 0
  }

  const submit = (e: React.FormEvent) => {
    e.preventDefault()
    if (check()) save.mutate(toInput(form, forwarder ?? undefined))
  }

  const runTest = () => {
    if (check()) test.mutate(toInput(form))
  }

  const p = form.protocol
  const tls = p === "dot" || p === "doh"

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="max-h-[90svh] overflow-y-auto sm:max-w-lg">
        <form onSubmit={submit} className="space-y-4">
          <DialogHeader>
            <DialogTitle>{forwarder ? "Modifier le redirecteur" : "Ajouter un redirecteur"}</DialogTitle>
            <DialogDescription>Serveur DNS à qui Leazone demande les noms qu'il ne connaît pas.</DialogDescription>
          </DialogHeader>

          {!forwarder && (
            <div className="space-y-2">
              <p className="text-xs font-medium text-muted-foreground">Préréglages</p>
              <div className="flex flex-wrap gap-2">
                {presets.map((pr) => (
                  <Button
                    key={pr.label}
                    type="button"
                    variant="outline"
                    size="sm"
                    onClick={() => {
                      set(pr.form)
                      setLocal({})
                    }}
                  >
                    {pr.label}
                  </Button>
                ))}
              </div>
            </div>
          )}

          <Field
            label="Domaine (facultatif)"
            htmlFor="fw-domain"
            help="Vide = redirecteur global. Ex. : corp.local pour envoyer ce domaine à un autre serveur."
            error={err("domain")}
          >
            <Input
              id="fw-domain"
              autoCapitalize="none"
              spellCheck={false}
              value={form.domain}
              onChange={(e) => set({ domain: e.target.value })}
              placeholder="tous les noms"
            />
          </Field>

          <Field label="Protocole" htmlFor="fw-protocol" error={err("protocol")}>
            <Select value={p} onValueChange={(v) => setProtocol(v as ForwarderProtocol)}>
              <SelectTrigger id="fw-protocol" className="w-full">
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                {protocols.map((x) => (
                  <SelectItem key={x} value={x}>
                    {protocolLongLabel[x]}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
          </Field>

          {p === "doh" && (
            <Field label="URL DoH" htmlFor="fw-url" error={err("dohUrl")}>
              <Input
                id="fw-url"
                autoCapitalize="none"
                spellCheck={false}
                className="font-mono"
                value={form.dohUrl}
                onChange={(e) => set({ dohUrl: e.target.value })}
                placeholder="https://dns.quad9.net/dns-query"
              />
            </Field>
          )}

          <div className={p === "doh" ? undefined : "grid gap-4 sm:grid-cols-[1fr_7rem]"}>
            <Field
              label={p === "doh" ? "IP de démarrage" : "Adresse IP"}
              htmlFor="fw-address"
              help={p === "doh" ? "IP du serveur de l'URL. Facultatif si l'URL contient déjà une IP." : undefined}
              error={err("address")}
            >
              <Input
                id="fw-address"
                autoCapitalize="none"
                spellCheck={false}
                className="font-mono"
                value={form.address}
                onChange={(e) => set({ address: e.target.value })}
                placeholder="9.9.9.9"
              />
            </Field>
            {p !== "doh" && (
              <Field label="Port" htmlFor="fw-port" error={err("port")}>
                <Input
                  id="fw-port"
                  inputMode="numeric"
                  value={form.port}
                  onChange={(e) => set({ port: e.target.value })}
                  placeholder={String(defaultPort[p])}
                />
              </Field>
            )}
          </div>

          {p === "dot" && (
            <Field
              label="Nom TLS du serveur"
              htmlFor="fw-tlsname"
              help="Nom attendu dans le certificat, ex. : dns.quad9.net."
              error={err("tlsServerName")}
            >
              <Input
                id="fw-tlsname"
                autoCapitalize="none"
                spellCheck={false}
                className="font-mono"
                value={form.tlsServerName}
                onChange={(e) => set({ tlsServerName: e.target.value })}
                placeholder="dns.quad9.net"
              />
            </Field>
          )}

          {tls && (
            <div className="space-y-2">
              <div className="flex items-center justify-between gap-3 rounded-lg border p-3">
                <Label htmlFor="fw-verify" className="flex flex-col items-start gap-0.5 font-normal">
                  <span className="font-medium">Vérifier le certificat TLS</span>
                  <span className="text-xs text-muted-foreground">Protège contre un faux serveur. Laissez activé.</span>
                </Label>
                <Switch id="fw-verify" checked={form.tlsVerify} onCheckedChange={(v) => set({ tlsVerify: v })} />
              </div>
              {!form.tlsVerify && (
                <p className="flex items-center gap-1.5 text-xs text-warning">
                  <TriangleAlert className="size-3.5" /> Sans vérification, n'importe qui sur le chemin peut se faire passer pour ce serveur.
                </p>
              )}
            </div>
          )}

          {test.data && <TestResult result={test.data} />}
          {test.isError && <FormError message={formError(test.error, known)} />}
          <FormError message={formError(save.error, known)} />

          <DialogFooter className="gap-2 sm:justify-between">
            <Button type="button" variant="outline" onClick={runTest} disabled={test.isPending}>
              {test.isPending ? <Loader2 className="animate-spin" /> : <FlaskConical />}
              Tester
            </Button>
            <div className="flex flex-col-reverse gap-2 sm:flex-row">
              <Button type="button" variant="ghost" onClick={() => onOpenChange(false)}>
                Annuler
              </Button>
              <Button type="submit" disabled={save.isPending}>
                {save.isPending && <Loader2 className="animate-spin" />}
                {forwarder ? "Enregistrer" : "Ajouter"}
              </Button>
            </div>
          </DialogFooter>
        </form>
      </DialogContent>
    </Dialog>
  )
}
