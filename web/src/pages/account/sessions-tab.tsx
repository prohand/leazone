import * as React from "react"
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query"
import { MonitorSmartphone } from "lucide-react"
import { toast } from "sonner"
import { api } from "@/api/client"
import { qk } from "@/api/queries"
import type { Session } from "@/api/types"
import { ConfirmDialog } from "@/components/confirm-dialog"
import { BlockSpinner } from "@/components/spinner"
import { Badge } from "@/components/ui/badge"
import { Button } from "@/components/ui/button"
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table"
import { describeUserAgent, formatDateTime, formatRelative } from "@/lib/format"

export function SessionsTab() {
  const qc = useQueryClient()
  const list = useQuery({ queryKey: qk.sessions, queryFn: () => api.get("/me/sessions") })
  const [revoking, setRevoking] = React.useState<Session | null>(null)

  const revoke = useMutation({
    mutationFn: (id: string) => api.delete("/me/sessions/{id}", { params: { id } }),
    onSuccess: () => {
      toast.success("Session fermée.")
      void qc.invalidateQueries({ queryKey: qk.sessions })
    },
  })

  const items = [...(list.data?.items ?? [])].sort((a, b) => Number(!!b.current) - Number(!!a.current))

  return (
    <Card>
      <CardHeader>
        <CardTitle>Sessions ouvertes</CardTitle>
        <CardDescription>Fermez les sessions que vous ne reconnaissez pas.</CardDescription>
      </CardHeader>
      <CardContent>
        {list.isPending ? (
          <BlockSpinner />
        ) : (
          <div className="rounded-lg border">
            <Table>
              <TableHeader>
                <TableRow className="hover:bg-transparent">
                  <TableHead>Appareil</TableHead>
                  <TableHead>Adresse IP</TableHead>
                  <TableHead>Ouverte le</TableHead>
                  <TableHead>Dernière activité</TableHead>
                  <TableHead>Expire le</TableHead>
                  <TableHead />
                </TableRow>
              </TableHeader>
              <TableBody>
                {items.map((s) => (
                  <TableRow key={s.id}>
                    <TableCell>
                      <div className="flex items-center gap-2">
                        <MonitorSmartphone className="size-4 text-muted-foreground" />
                        <span title={s.userAgent}>{describeUserAgent(s.userAgent)}</span>
                        {s.current && <Badge variant="secondary">Cette session</Badge>}
                      </div>
                    </TableCell>
                    <TableCell className="font-mono text-xs">{s.ip}</TableCell>
                    <TableCell>{formatDateTime(s.createdAt)}</TableCell>
                    <TableCell>{formatRelative(s.lastSeenAt)}</TableCell>
                    <TableCell>{formatDateTime(s.expiresAt)}</TableCell>
                    <TableCell className="text-right">
                      {!s.current && (
                        <Button variant="outline" size="sm" onClick={() => setRevoking(s)}>
                          Fermer
                        </Button>
                      )}
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </div>
        )}
      </CardContent>
      <ConfirmDialog
        open={!!revoking}
        onOpenChange={(o) => !o && setRevoking(null)}
        title="Fermer cette session ?"
        description={`L'appareil « ${describeUserAgent(revoking?.userAgent)} » (${revoking?.ip ?? ""}) sera déconnecté.`}
        confirmLabel="Fermer la session"
        destructive
        onConfirm={() => revoking?.id && revoke.mutateAsync(revoking.id)}
      />
    </Card>
  )
}
