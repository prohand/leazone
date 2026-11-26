import * as React from "react"
import { useQuery } from "@tanstack/react-query"
import { Fingerprint, Loader2 } from "lucide-react"
import { api, isApiError, ProblemType } from "@/api/client"
import { systemInfoQuery } from "@/api/queries"
import { AuthShell } from "@/components/auth-shell"
import { CodeInput } from "@/components/code-input"
import { Alert, AlertDescription } from "@/components/ui/alert"
import { Button } from "@/components/ui/button"
import { Card, CardContent, CardDescription, CardFooter, CardHeader, CardTitle } from "@/components/ui/card"
import { Input } from "@/components/ui/input"
import { Label } from "@/components/ui/label"
import { Separator } from "@/components/ui/separator"
import { useCooldown } from "@/hooks/use-cooldown"
import { useApplySession, useLogout, useSession } from "@/hooks/use-session"
import { errorMessage } from "@/lib/errors"
import { authenticate, webauthnSupported } from "@/lib/webauthn"

export default function LoginMfaPage() {
  const { data: session } = useSession()
  const info = useQuery(systemInfoQuery)
  const applySession = useApplySession()
  const logout = useLogout()
  const cooldown = useCooldown()
  const methods = session?.mfaMethods ?? []
  const passkeysOk = webauthnSupported() && info.data?.passkeysAvailable !== false
  const hasPasskey = methods.includes("passkey") && passkeysOk
  const hasTotp = methods.includes("totp")
  const hasRecovery = methods.includes("recovery")

  const [mode, setMode] = React.useState<"main" | "recovery">("main")
  const [code, setCode] = React.useState("")
  const [recovery, setRecovery] = React.useState("")
  const [busy, setBusy] = React.useState<"passkey" | "totp" | "recovery" | null>(null)
  const [error, setError] = React.useState<string | null>(null)

  const run = async (kind: "passkey" | "totp" | "recovery", fn: () => Promise<unknown>) => {
    setBusy(kind)
    setError(null)
    try {
      applySession((await fn()) as Parameters<typeof applySession>[0])
    } catch (e) {
      if (isApiError(e, ProblemType.rateLimited)) cooldown.start(e.retryAfter ?? 60)
      else if (isApiError(e) && (e.status === 401 || e.status === 422))
        setError(kind === "passkey" ? "Passkey non reconnue." : "Code incorrect.")
      else setError(errorMessage(e))
      setCode("")
    } finally {
      setBusy(null)
    }
  }

  const viaPasskey = () =>
    run("passkey", async () => {
      const begin = await api.post("/auth/mfa/passkey/begin")
      return api.post("/auth/mfa/passkey/finish", { body: await authenticate(begin) })
    })
  const viaTotp = (value = code) => {
    if (value.length !== 6 || busy) return
    void run("totp", () => api.post("/auth/mfa/totp", { body: { code: value } }))
  }
  const viaRecovery = (e: React.FormEvent) => {
    e.preventDefault()
    if (!recovery.trim()) return
    void run("recovery", () => api.post("/auth/mfa/recovery", { body: { code: recovery.trim() } }))
  }

  const locked = cooldown.remaining > 0
  const disabled = busy !== null || locked

  return (
    <AuthShell>
      <Card>
        <CardHeader>
          <CardTitle className="text-xl">Double vérification</CardTitle>
          <CardDescription>
            {mode === "recovery"
              ? "Saisissez un de vos codes de secours. Chaque code ne marche qu'une fois."
              : `Confirmez votre identité${session?.user?.username ? ` (${session.user.username})` : ""}.`}
          </CardDescription>
        </CardHeader>
        <CardContent className="space-y-5">
          {locked && (
            <Alert variant="destructive">
              <AlertDescription>Trop de tentatives, réessayez dans {cooldown.remaining} s.</AlertDescription>
            </Alert>
          )}

          {mode === "main" ? (
            <>
              {hasPasskey && (
                <Button className="w-full" onClick={viaPasskey} disabled={disabled}>
                  {busy === "passkey" ? <Loader2 className="animate-spin" /> : <Fingerprint />}
                  Utiliser ma passkey
                </Button>
              )}
              {hasPasskey && hasTotp && (
                <div className="flex items-center gap-3 text-xs text-muted-foreground">
                  <Separator className="flex-1" /> ou <Separator className="flex-1" />
                </div>
              )}
              {hasTotp && (
                <form
                  className="space-y-2"
                  onSubmit={(e) => {
                    e.preventDefault()
                    viaTotp()
                  }}
                >
                  <Label htmlFor="mfa-code">Code de l'application (6 chiffres)</Label>
                  <CodeInput
                    id="mfa-code"
                    autoFocus={!hasPasskey}
                    value={code}
                    onChange={setCode}
                    onComplete={viaTotp}
                    disabled={disabled}
                  />
                  <Button
                    type="submit"
                    variant={hasPasskey ? "outline" : "default"}
                    className="w-full"
                    disabled={disabled || code.length !== 6}
                  >
                    {busy === "totp" && <Loader2 className="animate-spin" />}
                    Vérifier
                  </Button>
                </form>
              )}
              {!hasPasskey && !hasTotp && methods.includes("passkey") && (
                <p className="text-sm text-muted-foreground">
                  Les passkeys ne sont pas disponibles ici. Utilisez un code de secours.
                </p>
              )}
            </>
          ) : (
            <form onSubmit={viaRecovery} className="space-y-2">
              <Label htmlFor="recovery-code">Code de secours</Label>
              <Input
                id="recovery-code"
                autoFocus
                autoComplete="off"
                autoCapitalize="none"
                spellCheck={false}
                className="font-mono"
                value={recovery}
                onChange={(e) => setRecovery(e.target.value)}
              />
              <Button type="submit" className="w-full" disabled={disabled || !recovery.trim()}>
                {busy === "recovery" && <Loader2 className="animate-spin" />}
                Vérifier
              </Button>
            </form>
          )}

          {error && <p className="text-sm text-destructive">{error}</p>}
        </CardContent>
        <CardFooter className="flex flex-col gap-2 text-sm">
          {hasRecovery && mode === "main" && (
            <Button variant="link" className="h-auto p-0" onClick={() => setMode("recovery")}>
              Utiliser un code de secours
            </Button>
          )}
          {mode === "recovery" && (
            <Button variant="link" className="h-auto p-0" onClick={() => setMode("main")}>
              Retour
            </Button>
          )}
          <Button variant="link" className="h-auto p-0 text-muted-foreground" onClick={() => void logout()}>
            Changer de compte
          </Button>
        </CardFooter>
      </Card>
    </AuthShell>
  )
}
