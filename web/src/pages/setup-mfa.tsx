import * as React from "react"
import { Fingerprint, ShieldCheck, Smartphone } from "lucide-react"
import type { EnrollMethod, MfaEnrollResult } from "@/api/types"
import { useHoldAuthRedirect } from "@/components/auth-gate"
import { AuthShell } from "@/components/auth-shell"
import { PasskeyRegister, usePasskeyBlocker } from "@/components/passkey-register"
import { RecoveryCodesDialog } from "@/components/recovery-codes-dialog"
import { TotpSetup } from "@/components/totp-setup"
import { Badge } from "@/components/ui/badge"
import { Button } from "@/components/ui/button"
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"
import { useApplySession, useLogout, useSession } from "@/hooks/use-session"
import { cn } from "@/lib/utils"

/** Forced MFA enrollment (session state mfa_setup_required). */
export default function SetupMfaPage() {
  const { data: session } = useSession()
  const applySession = useApplySession()
  const logout = useLogout()
  const allowed: EnrollMethod[] = session?.allowedMfaMethods?.length ? session.allowedMfaMethods : ["passkey"]
  // Passkeys unusable here (browser, IP address, RP ID...): suggest TOTP first.
  const passkeyBlocker = usePasskeyBlocker()
  const preferred: EnrollMethod = passkeyBlocker && allowed.includes("totp") ? "totp" : allowed[0]
  const [chosen, setChosen] = React.useState<EnrollMethod | null>(null)
  const method = chosen ?? preferred
  const setMethod = setChosen
  const [totpStarted, setTotpStarted] = React.useState(false)
  const [pending, setPending] = React.useState<MfaEnrollResult | null>(null)
  // The session is already "authenticated" on the server: a session refresh
  // (window focus...) must not leave this page before the codes are saved.
  useHoldAuthRedirect(pending !== null)

  const onEnrolled = (r: MfaEnrollResult) => {
    if (r.recoveryCodes && r.recoveryCodes.length > 0) setPending(r)
    else applySession(r.session)
  }

  return (
    <AuthShell wide>
      <Card>
        <CardHeader>
          <div className="mb-2 flex size-10 items-center justify-center rounded-full border bg-muted/50">
            <ShieldCheck className="size-5" />
          </div>
          <CardTitle className="text-xl">Protégez votre compte</CardTitle>
          <CardDescription>
            La double vérification (MFA) est obligatoire sur ce serveur. Même si quelqu'un trouve votre mot de passe,
            il ne pourra pas se connecter sans votre passkey ou votre téléphone. Choisissez une méthode pour continuer.
          </CardDescription>
        </CardHeader>
        <CardContent className="space-y-6">
          {allowed.length > 1 && (
            <div className="grid gap-3 sm:grid-cols-2" role="radiogroup">
              <MethodCard
                active={method === "passkey"}
                onClick={() => setMethod("passkey")}
                icon={Fingerprint}
                title="Passkey"
                text="Empreinte, visage, code de l'appareil ou clé de sécurité."
                badge={passkeyBlocker ? "Indisponible ici" : "Conseillé"}
              />
              <MethodCard
                active={method === "totp"}
                onClick={() => setMethod("totp")}
                icon={Smartphone}
                title="Application TOTP"
                text="Un code à 6 chiffres qui change toutes les 30 secondes."
              />
            </div>
          )}

          {method === "passkey" ? (
            <div className="space-y-3">
              <p className="text-sm text-muted-foreground">
                Donnez un nom à cette passkey pour la reconnaître plus tard, puis suivez les instructions de votre
                navigateur.
              </p>
              <PasskeyRegister onEnrolled={onEnrolled} />
            </div>
          ) : totpStarted ? (
            <TotpSetup onEnrolled={onEnrolled} onCancel={() => setTotpStarted(false)} />
          ) : (
            <Button onClick={() => setTotpStarted(true)}>
              <Smartphone /> Configurer une application TOTP
            </Button>
          )}

          <div className="border-t pt-4 text-center">
            <Button variant="link" className="h-auto p-0 text-muted-foreground" onClick={() => void logout()}>
              Se déconnecter
            </Button>
          </div>
        </CardContent>
      </Card>
      <RecoveryCodesDialog
        codes={pending?.recoveryCodes ?? null}
        onDone={() => {
          const s = pending?.session
          setPending(null)
          applySession(s)
        }}
      />
    </AuthShell>
  )
}

function MethodCard({
  active,
  onClick,
  icon: Icon,
  title,
  text,
  badge,
}: {
  active: boolean
  onClick: () => void
  icon: typeof Fingerprint
  title: string
  text: string
  badge?: string
}) {
  return (
    <button
      type="button"
      role="radio"
      aria-checked={active}
      onClick={onClick}
      className={cn(
        "flex flex-col items-start gap-1 rounded-lg border p-4 text-left transition-colors hover:bg-muted/50 focus-visible:ring-[3px] focus-visible:ring-ring/50 focus-visible:outline-none",
        active && "border-foreground/40 bg-muted/50 ring-1 ring-foreground/20",
      )}
    >
      <div className="flex w-full items-center gap-2">
        <Icon className="size-4" />
        <span className="font-medium">{title}</span>
        {badge && (
          <Badge variant="secondary" className="ml-auto">
            {badge}
          </Badge>
        )}
      </div>
      <span className="text-sm text-muted-foreground">{text}</span>
    </button>
  )
}
