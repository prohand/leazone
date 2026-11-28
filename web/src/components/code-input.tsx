import * as React from "react"
import { Input } from "@/components/ui/input"
import { cn } from "@/lib/utils"

/** 6-digit TOTP input. Calls onComplete when 6 digits are typed. */
export function CodeInput({
  value,
  onChange,
  onComplete,
  className,
  ...props
}: Omit<React.ComponentProps<"input">, "value" | "onChange"> & {
  value: string
  onChange: (v: string) => void
  onComplete?: (v: string) => void
}) {
  return (
    <Input
      inputMode="numeric"
      autoComplete="one-time-code"
      pattern="[0-9]{6}"
      // No maxLength: a pasted "123 456" must not be cut before the spaces are removed.
      placeholder="000000"
      className={cn("h-11 text-center font-mono text-xl tracking-[0.5em]", className)}
      value={value}
      onChange={(e) => {
        const v = e.target.value.replace(/\D/g, "").slice(0, 6)
        if (v === value) return
        onChange(v)
        if (v.length === 6) onComplete?.(v)
      }}
      {...props}
    />
  )
}
