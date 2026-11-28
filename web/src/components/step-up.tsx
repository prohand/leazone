import * as React from "react"
import { useQuery, useQueryClient } from "@tanstack/react-query"
import { Fingerprint, KeyRound, Loader2, RefreshCw, ShieldCheck } from "lucide-react"
import { api, isApiError, ProblemType, setStepUpHandler } from "@/api/client"
import { meQuery, qk, sessionQuery, systemInfoQuery } from "@/api/queries"
import { Alert, AlertDescription } from "@/components/ui/alert"
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
import { Separator } from "@/components/ui/separator"
import { errorMessage } from "@/lib/errors"
import { authenticate, webauthnSupported } from "@/lib/webauthn"
import { CodeInput } from "./code-input"

/*
 * Global step-up ("Confirmez votre identité") dialog.
 * The fetch wrapper calls the registered handler when an API call fails with
 * urn:leazone:step-up-required; the handler resolves true once the user has
 * re-verified, and the wrapper retries the original request once.
 */
export function StepUpProvider({ children }: { children: React.ReactNode }) {
  const [open, setOpen] = React.useState(false)
  const waiters = React.useRef<Array<(ok: boolean) => void>>([])

  React.useEffect(() => {
    setStepUpHandler(
      () =>
        new Promise<boolean>((resolve) => {
          waiters.current.push(resolve)
          setOpen(true)
        }),
    )
    return () => setStepUpHandler(null)
  }, [])

  const finish = React.useCallback((ok: boolean) => {
    const list = waiters.current
    waiters.current = []
    setOpen(false)
    list.forEach((r) => r(ok))
  }, [])

  return (
    <>
      {children}
      <Dialog open={open} onOpenChange={(o) => !o && finish(false)}>
        <DialogContent className="sm:max-w-sm" onInteractOutside={(e) => e.preventDefault()}>
          {open && <StepUpBody onDone={finish} />}
        </DialogContent>
      </Dialog>
    </>
  )
}

function StepUpBody({ onDone }: { onDone: (ok: boolean) => void }) {
  const qc = useQueryClient()
  const me = useQuery(meQuery)
  const info = useQuery(systemInfoQuery)
  const session = useQuery(sessionQuery)
  const [code, setCode] = React.useState("")
  const [password, setPassword] = React.useState("")
  const [busy, setBusy] = React.useState<"passkey" | "totp" | "password" | null>(null)
  const [error, setError] = React.useState<string | null>(null)

  // Forced MFA setup: the only check asked is a code of a TOTP that the
  // policy no longer accepts, before a passkey replaces it.
  const setup = session.data?.state === "mfa_setup_required"
  const totpUsable = !!me.data?.totpEnabled && me.data?.totpAllowed !== false
  const hasPasskey = (me.data?.passkeyCount ?? 0) > 0 && info.data?.passkeysAvailable !== false && webauthnSupported()
  // A TOTP enabled before the policy switched to "passkey only" is refused by the server (except as a proof in the setup).
  const hasTotp = !!me.data?.totpEnabled && (me.data?.totpAllowed !== false || setup)
  // No usable second factor at all: the server asks for the password.
  const usePassword = !setup && (me.data?.passkeyCount ?? 0) === 0 && !totpUsable

  const succeed = (s: unknown) => {
    if (s && typeof s === "object" && "state" in s) qc.setQueryData(qk.session, s)
    onDone(true)
  }

  const viaPasskey = async () => {
    setBusy("passkey")
    setError(null)
    try {
      const begin = await api.post("/auth/step-up/passkey/begin")
      const body = await authenticate(begin)
      succeed(await api.post("/auth/step-up/passkey/finish", { body }))
    } catch (e) {
      setError(errorMessage(e))
    } finally {
      setBusy(null)
    }
  }

  const viaTotp = async (value = code) => {
    if (value.length !== 6) return
    setBusy("totp")
    setError(null)
    try {
      succeed(await api.post("/auth/step-up/totp", { body: { code: value } }))
    } catch (e) {
      setCode("")
      setError(
        isApiError(e) && (e.status === 401 || e.is(ProblemType.validation)) ? "Code incorrect." : errorMessage(e),
      )
    } finally {
      setBusy(null)
    }
  }

  const viaPassword = async () => {
    if (!password) return
    setBusy("password")
    setError(null)
    try {
      succeed(await api.post("/auth/step-up/password", { body: { password } }))
    } catch (e) {
      setPassword("")
      setError(isApiError(e) && e.is(ProblemType.validation) ? "Mot de passe incorrect." : errorMessage(e))
    } finally {
      setBusy(null)
    }
  }

  return (
    <>
      <DialogHeader>
        <DialogTitle className="flex items-center gap-2">
          <ShieldCheck className="size-5" /> Confirmez votre identité
        </DialogTitle>
        <DialogDescription>
          {setup
            ? "Avant d'ajouter une passkey, entrez un code de l'application TOTP configurée sur votre compte."
            : usePassword
              ? "Cette action est sensible. Entrez votre mot de passe pour continuer."
              : "Cette action est sensible. Vérifiez votre identité pour continuer."}
        </DialogDescription>
      </DialogHeader>

      {me.isPending ? (
        <div className="flex justify-center py-6">
          <Loader2 className="size-5 animate-spin text-muted-foreground" />
        </div>
      ) : me.isError ? (
        <div className="space-y-3">
          <Alert variant="destructive">
            <AlertDescription>
              Impossible de charger vos méthodes de vérification : {errorMessage(me.error)}
            </AlertDescription>
          </Alert>
          <Button variant="outline" className="w-full" onClick={() => void me.refetch()} disabled={me.isFetching}>
            {me.isFetching ? <Loader2 className="animate-spin" /> : <RefreshCw />}
            Réessayer
          </Button>
        </div>
      ) : (
        <div className="space-y-4">
          {hasPasskey && (
            <Button className="w-full" onClick={viaPasskey} disabled={busy !== null}>
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
                void viaTotp()
              }}
            >
              <Label htmlFor="stepup-code">Code de l'application (6 chiffres)</Label>
              <CodeInput
                id="stepup-code"
                autoFocus={!hasPasskey}
                value={code}
                onChange={setCode}
                onComplete={(v) => void viaTotp(v)}
                disabled={busy !== null}
              />
              <Button type="submit" variant="outline" className="w-full" disabled={busy !== null || code.length !== 6}>
                {busy === "totp" && <Loader2 className="animate-spin" />}
                Vérifier
              </Button>
            </form>
          )}
          {usePassword && (
            <form
              className="space-y-2"
              onSubmit={(e) => {
                e.preventDefault()
                void viaPassword()
              }}
            >
              <Label htmlFor="stepup-password">Mot de passe</Label>
              <Input
                id="stepup-password"
                type="password"
                autoComplete="current-password"
                autoFocus
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                disabled={busy !== null}
              />
              <Button type="submit" className="w-full" disabled={busy !== null || !password}>
                {busy === "password" ? <Loader2 className="animate-spin" /> : <KeyRound />}
                Vérifier
              </Button>
            </form>
          )}
          {!hasPasskey && !hasTotp && !usePassword && (
            <Alert>
              <AlertDescription>
                Aucune méthode de vérification n'est disponible. Ajoutez une passkey ou une application TOTP dans
                « Mon compte ».
              </AlertDescription>
            </Alert>
          )}
          {error && <p className="text-sm text-destructive">{error}</p>}
        </div>
      )}

      <DialogFooter>
        <Button variant="ghost" onClick={() => onDone(false)} disabled={busy !== null}>
          Annuler
        </Button>
      </DialogFooter>
    </>
  )
}
