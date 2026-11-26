import * as React from "react"
import { useQuery } from "@tanstack/react-query"
import { Fingerprint, Loader2 } from "lucide-react"
import { api } from "@/api/client"
import { systemInfoQuery } from "@/api/queries"
import type { MfaEnrollResult } from "@/api/types"
import { Button } from "@/components/ui/button"
import { Input } from "@/components/ui/input"
import { Label } from "@/components/ui/label"
import { errorMessage } from "@/lib/errors"
import { defaultPasskeyName, register, webauthnSupported } from "@/lib/webauthn"

/** Explains why passkeys cannot be used here, or returns null when they can. */
export function usePasskeyBlocker(): string | null {
  const { data } = useQuery(systemInfoQuery)
  if (!webauthnSupported()) return "Ce navigateur ne gère pas les passkeys."
  if (data && !data.passkeysAvailable)
    return data.passkeysUnavailableReason || "Les passkeys ne sont pas disponibles avec cette adresse."
  return null
}

/** Name field + button to register a new passkey (POST /me/passkeys/begin + finish). */
export function PasskeyRegister({
  onEnrolled,
  submitLabel = "Créer la passkey",
}: {
  onEnrolled: (r: MfaEnrollResult) => void
  submitLabel?: string
}) {
  const [name, setName] = React.useState(defaultPasskeyName)
  const [busy, setBusy] = React.useState(false)
  const [error, setError] = React.useState<string | null>(null)
  const blocker = usePasskeyBlocker()

  const submit = async (e: React.FormEvent) => {
    e.preventDefault()
    if (!name.trim()) return
    setBusy(true)
    setError(null)
    try {
      const begin = await api.post("/me/passkeys/begin")
      const fin = await register(begin)
      const res = await api.post("/me/passkeys/finish", { body: { ...fin, name: name.trim() } })
      onEnrolled(res)
    } catch (err) {
      setError(errorMessage(err))
    } finally {
      setBusy(false)
    }
  }

  return (
    <form onSubmit={submit} className="space-y-2">
      <Label htmlFor="passkey-name">Nom de la passkey</Label>
      <div className="flex flex-col gap-2 sm:flex-row">
        <Input
          id="passkey-name"
          value={name}
          maxLength={64}
          onChange={(e) => setName(e.target.value)}
          placeholder="Ex. : MacBook pro, YubiKey…"
          disabled={!!blocker || busy}
        />
        <Button type="submit" disabled={!!blocker || busy || !name.trim()}>
          {busy ? <Loader2 className="animate-spin" /> : <Fingerprint />}
          {submitLabel}
        </Button>
      </div>
      {blocker && <p className="text-sm text-muted-foreground">{blocker}</p>}
      {error && <p className="text-sm text-destructive">{error}</p>}
    </form>
  )
}
