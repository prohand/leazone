import * as React from "react"
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query"
import { FileKey, Loader2, ShieldAlert, Upload } from "lucide-react"
import { toast } from "sonner"
import { api } from "@/api/client"
import { qk } from "@/api/queries"
import type { TlsInfo } from "@/api/types"
import { CopyButton } from "@/components/copy-button"
import { BlockSpinner } from "@/components/spinner"
import { Alert, AlertDescription } from "@/components/ui/alert"
import { Badge } from "@/components/ui/badge"
import { Button } from "@/components/ui/button"
import { Card, CardContent, CardDescription, CardFooter, CardHeader, CardTitle } from "@/components/ui/card"
import { Label } from "@/components/ui/label"
import { Textarea } from "@/components/ui/textarea"
import { errorMessage, fieldError } from "@/lib/errors"
import { formatDateTime } from "@/lib/format"

const sourceLabel: Record<NonNullable<TlsInfo["source"]>, string> = {
  selfsigned: "Auto-signé",
  import: "Importé depuis l'interface",
  file: "Fichier (/data/tls)",
}

function daysLeft(notAfter?: string) {
  if (!notAfter) return null
  return Math.floor((new Date(notAfter).getTime() - Date.now()) / 86400_000)
}

export function HttpsTab() {
  const tls = useQuery({ queryKey: qk.tls, queryFn: () => api.get("/settings/tls") })
  return (
    <div className="space-y-6">
      <Card>
        <CardHeader>
          <CardTitle>Certificat actuel</CardTitle>
          <CardDescription>Certificat présenté par Leazone sur le port HTTPS.</CardDescription>
        </CardHeader>
        <CardContent>
          {tls.isPending ? (
            <BlockSpinner />
          ) : tls.isError ? (
            <p className="text-sm text-destructive">{errorMessage(tls.error)}</p>
          ) : (
            <TlsDetails info={tls.data} />
          )}
        </CardContent>
      </Card>
      <ImportCard />
    </div>
  )
}

function TlsDetails({ info }: { info: TlsInfo }) {
  const left = daysLeft(info.notAfter)
  return (
    <div className="space-y-4">
      {info.source === "selfsigned" && (
        <Alert variant="destructive">
          <ShieldAlert />
          <AlertDescription>
            Certificat auto-signé : à remplacer avant la mise en production. Les passkeys ne fonctionneront pas.
          </AlertDescription>
        </Alert>
      )}
      <dl className="grid gap-x-6 gap-y-3 text-sm sm:grid-cols-[max-content_1fr]">
        <dt className="text-muted-foreground">Source</dt>
        <dd>
          <Badge variant={info.source === "selfsigned" ? "destructive" : "secondary"}>
            {info.source ? sourceLabel[info.source] : "—"}
          </Badge>
        </dd>
        <dt className="text-muted-foreground">Sujet</dt>
        <dd className="break-all">{info.subject || "—"}</dd>
        <dt className="text-muted-foreground">Noms</dt>
        <dd className="flex flex-wrap gap-1.5">
          {info.dnsNames?.length
            ? info.dnsNames.map((n) => (
                <Badge key={n} variant="outline" className="font-mono">
                  {n}
                </Badge>
              ))
            : "—"}
        </dd>
        <dt className="text-muted-foreground">Valide du</dt>
        <dd>{formatDateTime(info.notBefore)}</dd>
        <dt className="text-muted-foreground">Expire le</dt>
        <dd className="flex flex-wrap items-center gap-2">
          {formatDateTime(info.notAfter)}
          {left !== null &&
            (left < 0 ? (
              <Badge variant="destructive">Expiré</Badge>
            ) : left < 30 ? (
              <Badge variant="outline" className="text-warning">
                Dans {left} jour{left > 1 ? "s" : ""}
              </Badge>
            ) : (
              <span className="text-muted-foreground">(dans {left} jours)</span>
            ))}
        </dd>
        <dt className="text-muted-foreground">Empreinte SHA-256</dt>
        <dd className="flex items-start gap-2">
          <code className="font-mono text-xs break-all">{info.fingerprintSha256 || "—"}</code>
          {info.fingerprintSha256 && <CopyButton value={info.fingerprintSha256} iconOnly size="icon-sm" variant="ghost" />}
        </dd>
      </dl>
    </div>
  )
}

function PemField({
  id,
  label,
  help,
  value,
  onChange,
  error,
}: {
  id: string
  label: string
  help: string
  value: string
  onChange: (v: string) => void
  error?: string
}) {
  const fileRef = React.useRef<HTMLInputElement>(null)
  return (
    <div className="space-y-2">
      <div className="flex items-center justify-between gap-2">
        <Label htmlFor={id}>{label}</Label>
        <Button type="button" variant="outline" size="sm" onClick={() => fileRef.current?.click()}>
          <FileKey /> Choisir un fichier
        </Button>
        <input
          ref={fileRef}
          type="file"
          accept=".pem,.crt,.cer,.key,text/plain,application/x-pem-file"
          className="hidden"
          onChange={async (e) => {
            const f = e.target.files?.[0]
            if (f) onChange(await f.text())
            e.target.value = ""
          }}
        />
      </div>
      <Textarea
        id={id}
        rows={7}
        spellCheck={false}
        className="font-mono text-xs"
        placeholder="-----BEGIN …-----"
        value={value}
        onChange={(e) => onChange(e.target.value)}
      />
      <p className="text-xs text-muted-foreground">{help}</p>
      {error && <p className="text-sm text-destructive">{error}</p>}
    </div>
  )
}

function ImportCard() {
  const qc = useQueryClient()
  const [cert, setCert] = React.useState("")
  const [key, setKey] = React.useState("")

  const upload = useMutation({
    mutationFn: () => api.post("/settings/tls", { body: { certPem: cert.trim() + "\n", keyPem: key.trim() + "\n" } }),
    onSuccess: (info) => {
      qc.setQueryData(qk.tls, info)
      void qc.invalidateQueries({ queryKey: qk.systemInfo })
      setCert("")
      setKey("")
      toast.success("Certificat importé.", { description: "Rechargez la page pour utiliser le nouveau certificat." })
    },
  })

  const valid = cert.includes("-----BEGIN CERTIFICATE-----") && /-----BEGIN [A-Z ]*PRIVATE KEY-----/.test(key)

  return (
    <Card>
      <CardHeader>
        <CardTitle>Importer un certificat</CardTitle>
        <CardDescription>
          Format PEM. Le certificat est copié sur l'autre nœud en cas de haute disponibilité.
        </CardDescription>
      </CardHeader>
      <CardContent className="grid gap-6 lg:grid-cols-2">
        <PemField
          id="cert-pem"
          label="Certificat"
          help="Le certificat du serveur d'abord, puis les certificats intermédiaires."
          value={cert}
          onChange={setCert}
          error={fieldError(upload.error, "certPem")}
        />
        <PemField
          id="key-pem"
          label="Clé privée"
          help="Clé non chiffrée (sans mot de passe). Elle est stockée chiffrée par Leazone."
          value={key}
          onChange={setKey}
          error={fieldError(upload.error, "keyPem")}
        />
      </CardContent>
      <CardFooter className="justify-end border-t pt-6">
        <Button onClick={() => upload.mutate()} disabled={!valid || upload.isPending}>
          {upload.isPending ? <Loader2 className="animate-spin" /> : <Upload />}
          Importer
        </Button>
      </CardFooter>
    </Card>
  )
}
