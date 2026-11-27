import * as React from "react"
import { RefreshCw } from "lucide-react"
import { Alert, AlertDescription } from "@/components/ui/alert"
import { Button } from "@/components/ui/button"
import { Label } from "@/components/ui/label"
import { errorMessage } from "@/lib/errors"
import { cn } from "@/lib/utils"

type ControlProps = { "aria-describedby"?: string; "aria-invalid"?: React.AriaAttributes["aria-invalid"] }

/**
 * Label + control + help text + error message. When `children` is a single
 * element (the control), it gets aria-describedby (help and error) and
 * aria-invalid while there is an error.
 */
export function Field({
  label,
  htmlFor,
  help,
  error,
  className,
  children,
}: {
  label: React.ReactNode
  htmlFor?: string
  help?: React.ReactNode
  error?: string
  className?: string
  children: React.ReactNode
}) {
  const auto = React.useId()
  const base = htmlFor || auto
  const helpId = `${base}-help`
  const errorId = `${base}-error`
  let control = children
  // Layout wrappers (<div>…) are left alone: only a control gets the attributes.
  const wrapper =
    React.isValidElement(children) &&
    typeof children.type === "string" &&
    !["input", "textarea", "select", "button"].includes(children.type)
  if (React.isValidElement<ControlProps>(children) && !wrapper) {
    const own = children.props["aria-describedby"]
    const describedBy = [own, help ? helpId : "", error ? errorId : ""].filter(Boolean).join(" ")
    control = React.cloneElement(children, {
      "aria-describedby": describedBy || undefined,
      "aria-invalid": error ? true : children.props["aria-invalid"],
    })
  }
  return (
    <div className={cn("space-y-2", className)}>
      <Label htmlFor={htmlFor}>{label}</Label>
      {control}
      {help && (
        <p id={helpId} className="text-xs text-muted-foreground">
          {help}
        </p>
      )}
      {error && (
        <p id={errorId} data-slot="field-error" className="text-sm text-destructive">
          {error}
        </p>
      )}
    </div>
  )
}

/** Form-level error line. */
export function FormError({ message }: { message?: string }) {
  if (!message) return null
  return (
    <p role="alert" className="text-sm text-destructive">
      {message}
    </p>
  )
}

/** Loading failure of a list or a card (instead of a misleading empty state), with a retry button. */
export function LoadError({
  error,
  onRetry,
  retrying,
  className,
}: {
  error: unknown
  onRetry?: () => void
  retrying?: boolean
  className?: string
}) {
  return (
    <Alert variant="destructive" className={className}>
      <AlertDescription className="flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between">
        <span>Chargement impossible : {errorMessage(error)}</span>
        {onRetry && (
          <Button type="button" variant="outline" size="sm" className="shrink-0" onClick={onRetry} disabled={retrying}>
            <RefreshCw className={cn(retrying && "animate-spin")} /> Réessayer
          </Button>
        )}
      </AlertDescription>
    </Alert>
  )
}
