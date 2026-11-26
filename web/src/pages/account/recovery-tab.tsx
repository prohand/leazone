import * as React from "react"
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query"
import { RefreshCw, TriangleAlert } from "lucide-react"
import { api } from "@/api/client"
import { qk } from "@/api/queries"
import { ConfirmDialog } from "@/components/confirm-dialog"
import { RecoveryCodesDialog } from "@/components/recovery-codes-dialog"
import { Alert, AlertDescription } from "@/components/ui/alert"
import { Button } from "@/components/ui/button"
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"
import { Skeleton } from "@/components/ui/skeleton"

export function RecoveryTab() {
  const qc = useQueryClient()
  const status = useQuery({ queryKey: qk.recovery, queryFn: () => api.get("/me/recovery-codes") })
  const [confirm, setConfirm] = React.useState(false)
  const [codes, setCodes] = React.useState<string[] | null>(null)

  const regenerate = useMutation({
    mutationFn: () => api.post("/me/recovery-codes"),
    onSuccess: (r) => {
      setCodes(r.codes ?? [])
      void qc.invalidateQueries({ queryKey: qk.recovery })
      void qc.invalidateQueries({ queryKey: qk.me })
    },
  })

  const remaining = status.data?.remaining ?? 0

  return (
    <Card>
      <CardHeader>
        <CardTitle>Codes de secours</CardTitle>
        <CardDescription>
          À utiliser si vous perdez votre passkey ou votre téléphone. Chaque code ne marche qu'une fois.
        </CardDescription>
      </CardHeader>
      <CardContent className="space-y-4">
        {status.isPending ? (
          <Skeleton className="h-10 w-40" />
        ) : (
          <div>
            <div className="text-3xl font-semibold tabular-nums">{remaining}</div>
            <p className="text-sm text-muted-foreground">code{remaining > 1 ? "s" : ""} restant{remaining > 1 ? "s" : ""} sur 10</p>
          </div>
        )}
        {!status.isPending && remaining < 3 && (
          <Alert>
            <TriangleAlert />
            <AlertDescription>Il vous reste peu de codes. Générez-en de nouveaux.</AlertDescription>
          </Alert>
        )}
        <Button variant="outline" onClick={() => setConfirm(true)}>
          <RefreshCw /> Générer de nouveaux codes
        </Button>
      </CardContent>
      <ConfirmDialog
        open={confirm}
        onOpenChange={setConfirm}
        title="Générer de nouveaux codes ?"
        description="Les anciens codes ne marcheront plus."
        confirmLabel="Générer"
        onConfirm={() => regenerate.mutateAsync()}
      />
      <RecoveryCodesDialog codes={codes} onDone={() => setCodes(null)} />
    </Card>
  )
}
