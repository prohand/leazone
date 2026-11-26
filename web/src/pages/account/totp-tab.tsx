import * as React from "react"
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query"
import { Smartphone } from "lucide-react"
import { toast } from "sonner"
import { api } from "@/api/client"
import { qk } from "@/api/queries"
import type { MfaEnrollResult } from "@/api/types"
import { ConfirmDialog } from "@/components/confirm-dialog"
import { RecoveryCodesDialog } from "@/components/recovery-codes-dialog"
import { BlockSpinner } from "@/components/spinner"
import { TotpSetup } from "@/components/totp-setup"
import { Badge } from "@/components/ui/badge"
import { Button } from "@/components/ui/button"
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"

export function TotpTab() {
  const qc = useQueryClient()
  const status = useQuery({ queryKey: qk.totp, queryFn: () => api.get("/me/totp") })
  const [setup, setSetup] = React.useState(false)
  const [confirmOff, setConfirmOff] = React.useState(false)
  const [codes, setCodes] = React.useState<string[] | null>(null)

  const refresh = () => {
    void qc.invalidateQueries({ queryKey: qk.totp })
    void qc.invalidateQueries({ queryKey: qk.me })
  }

  const disable = useMutation({
    mutationFn: () => api.delete("/me/totp"),
    onSuccess: () => {
      toast.success("TOTP désactivé.")
      refresh()
    },
  })

  const onEnrolled = (r: MfaEnrollResult) => {
    toast.success("TOTP activé.")
    setSetup(false)
    refresh()
    if (r.recoveryCodes?.length) setCodes(r.recoveryCodes)
  }

  const enabled = !!status.data?.enabled

  return (
    <Card>
      <CardHeader>
        <CardTitle className="flex items-center gap-2">
          Application TOTP
          {!status.isPending &&
            (enabled ? <Badge className="bg-success text-white">Activé</Badge> : <Badge variant="outline">Désactivé</Badge>)}
        </CardTitle>
        <CardDescription>
          Un code à 6 chiffres donné par une application (Aegis, Google Authenticator, 1Password…).
        </CardDescription>
      </CardHeader>
      <CardContent>
        {status.isPending ? (
          <BlockSpinner />
        ) : enabled ? (
          <Button variant="outline" onClick={() => setConfirmOff(true)}>
            Désactiver le TOTP
          </Button>
        ) : setup ? (
          <TotpSetup onEnrolled={onEnrolled} onCancel={() => setSetup(false)} />
        ) : (
          <Button onClick={() => setSetup(true)}>
            <Smartphone /> Configurer
          </Button>
        )}
      </CardContent>
      <ConfirmDialog
        open={confirmOff}
        onOpenChange={setConfirmOff}
        title="Désactiver le TOTP ?"
        description="Vous ne pourrez plus utiliser l'application pour vous connecter. Gardez au moins une autre méthode (passkey)."
        confirmLabel="Désactiver"
        destructive
        onConfirm={() => disable.mutateAsync()}
      />
      <RecoveryCodesDialog codes={codes} onDone={() => setCodes(null)} />
    </Card>
  )
}
