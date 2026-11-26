import * as React from "react"
import { useQuery } from "@tanstack/react-query"
import { Fingerprint, Loader2 } from "lucide-react"
import { api, isApiError, ProblemType } from "@/api/client"
import { systemInfoQuery } from "@/api/queries"
import { AuthShell } from "@/components/auth-shell"
import { Alert, AlertDescription } from "@/components/ui/alert"
import { Button } from "@/components/ui/button"
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"
import { Input } from "@/components/ui/input"
import { Label } from "@/components/ui/label"
import { Separator } from "@/components/ui/separator"
import { useCooldown } from "@/hooks/use-cooldown"
import { useApplySession } from "@/hooks/use-session"
import { errorMessage } from "@/lib/errors"
import { authenticate, webauthnSupported } from "@/lib/webauthn"

export default function LoginPage() {
  const info = useQuery(systemInfoQuery)
  const applySession = useApplySession()
  const cooldown = useCooldown()
  const [username, setUsername] = React.useState("")
  const [password, setPassword] = React.useState("")
  const [busy, setBusy] = React.useState<"password" | "passkey" | null>(null)
  const [error, setError] = React.useState<string | null>(null)

  const handleError = (e: unknown, badCredentials: string) => {
    if (isApiError(e, ProblemType.rateLimited)) {
      cooldown.start(e.retryAfter ?? 60)
      setError(null)
    } else if (isApiError(e) && e.status === 401) {
      setError(badCredentials)
    } else {
      setError(errorMessage(e))
    }
  }

  const loginPassword = async (e: React.FormEvent) => {
    e.preventDefault()
    setBusy("password")
    setError(null)
    try {
      applySession(await api.post("/auth/login", { body: { username: username.trim(), password } }))
    } catch (err) {
      setPassword("")
      handleError(err, "Identifiant ou mot de passe incorrect.")
    } finally {
      setBusy(null)
    }
  }

  const loginPasskey = async () => {
    setBusy("passkey")
    setError(null)
    try {
      const begin = await api.post("/auth/passkey/begin")
      const body = await authenticate(begin)
      applySession(await api.post("/auth/passkey/finish", { body }))
    } catch (err) {
      handleError(err, "Passkey non reconnue.")
    } finally {
      setBusy(null)
    }
  }

  const passkeyBlocker = !webauthnSupported()
    ? "Ce navigateur ne gère pas les passkeys."
    : info.data && !info.data.passkeysAvailable
      ? info.data.passkeysUnavailableReason || "Les passkeys ne sont pas disponibles avec cette adresse."
      : null

  const locked = cooldown.remaining > 0

  return (
    <AuthShell>
      <Card>
        <CardHeader>
          <CardTitle className="text-xl">Connexion</CardTitle>
          <CardDescription>Connectez-vous pour gérer votre serveur.</CardDescription>
        </CardHeader>
        <CardContent className="space-y-5">
          {locked && (
            <Alert variant="destructive">
              <AlertDescription>Trop de tentatives, réessayez dans {cooldown.remaining} s.</AlertDescription>
            </Alert>
          )}
          <form onSubmit={loginPassword} className="space-y-4">
            <div className="space-y-2">
              <Label htmlFor="username">Identifiant</Label>
              <Input
                id="username"
                autoComplete="username webauthn"
                autoCapitalize="none"
                spellCheck={false}
                autoFocus
                required
                value={username}
                onChange={(e) => setUsername(e.target.value)}
              />
            </div>
            <div className="space-y-2">
              <Label htmlFor="password">Mot de passe</Label>
              <Input
                id="password"
                type="password"
                autoComplete="current-password"
                required
                value={password}
                onChange={(e) => setPassword(e.target.value)}
              />
            </div>
            {error && <p className="text-sm text-destructive">{error}</p>}
            <Button type="submit" className="w-full" disabled={busy !== null || locked}>
              {busy === "password" && <Loader2 className="animate-spin" />}
              Se connecter
            </Button>
          </form>

          <div className="flex items-center gap-3 text-xs text-muted-foreground">
            <Separator className="flex-1" /> ou <Separator className="flex-1" />
          </div>

          <div className="space-y-2">
            <Button
              type="button"
              variant="outline"
              className="w-full"
              onClick={loginPasskey}
              disabled={busy !== null || locked || !!passkeyBlocker}
            >
              {busy === "passkey" ? <Loader2 className="animate-spin" /> : <Fingerprint />}
              Se connecter avec une passkey
            </Button>
            {passkeyBlocker && <p className="text-center text-xs text-muted-foreground">{passkeyBlocker}</p>}
          </div>
        </CardContent>
      </Card>
    </AuthShell>
  )
}
