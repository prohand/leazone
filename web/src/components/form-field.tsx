import type * as React from "react"
import { Label } from "@/components/ui/label"
import { cn } from "@/lib/utils"

/** Label + control + help text + error message. */
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
  return (
    <div className={cn("space-y-2", className)}>
      <Label htmlFor={htmlFor}>{label}</Label>
      {children}
      {help && <p className="text-xs text-muted-foreground">{help}</p>}
      {error && (
        <p data-slot="field-error" className="text-sm text-destructive">
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
