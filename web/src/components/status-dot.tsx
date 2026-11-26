import type * as React from "react"
import { cn } from "@/lib/utils"

export type DotTone = "ok" | "error" | "warning" | "off"

const tones: Record<DotTone, string> = {
  ok: "bg-success",
  error: "bg-destructive",
  warning: "bg-warning",
  off: "bg-muted-foreground/40",
}

/** Small colored status dot, with an optional label next to it. */
export function StatusDot({ tone, label, className }: { tone: DotTone; label?: React.ReactNode; className?: string }) {
  return (
    <span className={cn("inline-flex items-center gap-1.5", className)}>
      <span className={cn("size-2 shrink-0 rounded-full", tones[tone])} aria-hidden />
      {label}
    </span>
  )
}
