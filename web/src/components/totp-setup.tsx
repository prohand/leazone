import * as React from "react"
import { useMutation } from "@tanstack/react-query"
import { Loader2 } from "lucide-react"
import { api, isApiError } from "@/api/client"
import type { MfaEnrollResult } from "@/api/types"
import { Button } from "@/components/ui/button"
import { Label } from "@/components/ui/label"
import { Skeleton } from "@/components/ui/skeleton"
import { errorMessage } from "@/lib/errors"
import { CodeInput } from "./code-input"
import { CopyButton } from "./copy-button"

/**
 * TOTP enrollment: generates a secret (POST /me/totp/setup), shows the QR code
 * and the secret, then confirms with a code (POST /me/totp/confirm).
 */
export function TotpSetup({ onEnrolled, onCancel }: { onEnrolled: (r: MfaEnrollResult) => void; onCancel?: () => void }) {
  const [code, setCode] = React.useState("")
  const [error, setError] = React.useState<string | null>(null)
  const started = React.useRef(false)

  const setup = useMutation({
    mutationFn: () => api.post("/me/totp/setup"),
    meta: { silent: true },
  })
  const confirm = useMutation({
    mutationFn: (c: string) => api.post("/me/totp/confirm", { body: { code: c } }),
    meta: { silent: true },
    onSuccess: (r) => onEnrolled(r),
    onError: (e) => {
      setCode("")
      setError(isApiError(e) && (e.status === 401 || e.status === 422) ? "Code incorrect. Réessayez." : errorMessage(e))
    },
  })

  React.useEffect(() => {
    // Guard against React StrictMode double effects: one secret per mount.
    if (started.current) return
    started.current = true
    setup.mutate()
  }, [setup.mutate])

  const submit = (c = code) => {
    if (c.length !== 6 || confirm.isPending) return
    setError(null)
    confirm.mutate(c)
  }

  if (setup.isError) {
    return (
      <div className="space-y-3">
        <p className="text-sm text-destructive">{errorMessage(setup.error)}</p>
        <Button variant="outline" onClick={() => setup.mutate()}>
          Réessayer
        </Button>
      </div>
    )
  }

  const data = setup.data
  const grouped = data?.secret?.replace(/(.{4})/g, "$1 ").trim()

  return (
    <div className="space-y-5">
      <ol className="list-decimal space-y-1 pl-5 text-sm text-muted-foreground">
        <li>Ouvrez une application d'authentification (Aegis, Google Authenticator, 1Password…).</li>
        <li>Scannez le QR code, ou saisissez la clé à la main.</li>
        <li>Tapez le code à 6 chiffres affiché par l'application.</li>
      </ol>
      <div className="flex flex-col items-center gap-4 sm:flex-row sm:items-start">
        {data?.qrPng ? (
          <img
            src={data.qrPng}
            alt="QR code TOTP"
            width={176}
            height={176}
            className="size-44 shrink-0 rounded-lg border bg-white p-2"
          />
        ) : (
          <Skeleton className="size-44 shrink-0 rounded-lg" />
        )}
        <div className="w-full min-w-0 space-y-2">
          <Label>Clé secrète</Label>
          <div className="flex items-center gap-2">
            <code className="flex-1 rounded-md border bg-muted/40 px-3 py-2 font-mono text-sm break-all select-all">
              {grouped ?? "…"}
            </code>
            {data?.secret && <CopyButton value={data.secret} iconOnly />}
          </div>
        </div>
      </div>
      <form
        className="space-y-2"
        onSubmit={(e) => {
          e.preventDefault()
          submit()
        }}
      >
        <Label htmlFor="totp-confirm">Code de vérification</Label>
        <div className="flex gap-2">
          <CodeInput
            id="totp-confirm"
            value={code}
            onChange={setCode}
            onComplete={submit}
            disabled={!data || confirm.isPending}
            className="max-w-48"
          />
          <Button type="submit" className="h-11" disabled={!data || code.length !== 6 || confirm.isPending}>
            {confirm.isPending && <Loader2 className="animate-spin" />}
            Activer
          </Button>
          {onCancel && (
            <Button type="button" variant="ghost" className="h-11" onClick={onCancel}>
              Annuler
            </Button>
          )}
        </div>
        {error && <p className="text-sm text-destructive">{error}</p>}
      </form>
    </div>
  )
}
