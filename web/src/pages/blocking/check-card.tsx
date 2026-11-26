import * as React from "react"
import { useMutation } from "@tanstack/react-query"
import { Ban, CircleCheck, FlaskConical, Info, Loader2 } from "lucide-react"
import { api } from "@/api/client"
import { Field, FormError } from "@/components/form-field"
import { Button } from "@/components/ui/button"
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"
import { Input } from "@/components/ui/input"
import { cleanDomain } from "@/lib/blocking"
import { errorMessage } from "@/lib/errors"
import { isIP } from "@/lib/net"
import { cn } from "@/lib/utils"

/** "Is this name blocked, and why?" (POST /blocking/check, any role). */
export function CheckCard({ focus }: { focus?: boolean }) {
  const [name, setName] = React.useState("")
  const [client, setClient] = React.useState("")
  const [errors, setErrors] = React.useState<{ name?: string; client?: string }>({})
  const nameRef = React.useRef<HTMLInputElement>(null)
  const cardRef = React.useRef<HTMLDivElement>(null)

  const check = useMutation({
    mutationFn: (body: { name: string; client?: string }) => api.post("/blocking/check", { body }),
    meta: { silent: true },
  })

  // ⌘K "Tester un domaine" lands here with ?test=1.
  React.useEffect(() => {
    if (focus) {
      cardRef.current?.scrollIntoView({ block: "center" })
      nameRef.current?.focus()
    }
  }, [focus])

  const submit = (e: React.FormEvent) => {
    e.preventDefault()
    const n = cleanDomain(name)
    const c = client.trim()
    const errs: typeof errors = {}
    if (!n) errs.name = "Nom de domaine non valide (ex. : ads.example.com)."
    if (c && !isIP(c)) errs.client = "Adresse IP non valide."
    setErrors(errs)
    if (Object.keys(errs).length || !n) return
    check.mutate({ name: n, client: c || undefined })
  }

  const r = check.data
  return (
    <Card ref={cardRef} className="gap-4" data-testid="check-card">
      <CardHeader>
        <CardTitle>Tester un domaine</CardTitle>
        <CardDescription>Savoir si un nom est bloqué, et pourquoi.</CardDescription>
      </CardHeader>
      <CardContent className="space-y-4">
        <form onSubmit={submit} className="space-y-3">
          <div className="grid gap-3 sm:grid-cols-[1fr_11rem]">
            <Field label="Domaine" htmlFor="check-name" error={errors.name}>
              <Input
                id="check-name"
                ref={nameRef}
                autoCapitalize="none"
                spellCheck={false}
                className="font-mono"
                placeholder="ads.example.com"
                value={name}
                onChange={(e) => {
                  setName(e.target.value)
                  check.reset()
                }}
              />
            </Field>
            <Field label="IP du client (facultatif)" htmlFor="check-client" error={errors.client}>
              <Input
                id="check-client"
                autoCapitalize="none"
                spellCheck={false}
                className="font-mono"
                placeholder="192.168.1.57"
                value={client}
                onChange={(e) => {
                  setClient(e.target.value)
                  check.reset()
                }}
              />
            </Field>
          </div>
          <Button type="submit" variant="outline" disabled={check.isPending}>
            {check.isPending ? <Loader2 className="animate-spin" /> : <FlaskConical />} Tester
          </Button>
        </form>
        <FormError message={check.isError ? errorMessage(check.error) : undefined} />
        {r && (
          <div
            aria-live="polite"
            data-testid="check-result"
            className={cn(
              "space-y-1.5 rounded-lg border p-3 text-sm",
              r.blocked ? "border-destructive/40 bg-destructive/5" : "border-success/40 bg-success/5",
            )}
          >
            <p className={cn("flex items-center gap-2 font-semibold", r.blocked ? "text-destructive" : "text-success")}>
              {r.blocked ? <Ban className="size-4" /> : <CircleCheck className="size-4" />}
              {r.blocked ? "Bloqué" : "Autorisé"}
              {r.reason && <span className="font-normal text-foreground">· {r.reason}</span>}
            </p>
            {r.matched && (
              <p className="text-muted-foreground">
                Entrée trouvée : <span className="font-mono text-foreground">{r.matched}</span>
              </p>
            )}
            {r.policyActive === false && (
              <p className="flex items-center gap-1.5 text-muted-foreground">
                <Info className="size-3.5 shrink-0" /> Le blocage ne s'applique pas à ce client.
              </p>
            )}
          </div>
        )}
      </CardContent>
    </Card>
  )
}
