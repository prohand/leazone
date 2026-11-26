import { cn } from "@/lib/utils"

/** Leazone mark: a rounded "zone" with connected network nodes. Same drawing as public/logo.svg. */
export function LogoMark({ className }: { className?: string }) {
  return (
    <svg viewBox="0 0 32 32" fill="none" aria-hidden="true" className={cn("size-6", className)}>
      <rect x="2.5" y="2.5" width="27" height="27" rx="8" stroke="currentColor" strokeWidth="2.25" />
      <path
        d="M10.5 11.5h11M10.5 11.5 16 21M21.5 11.5 16 21"
        stroke="currentColor"
        strokeWidth="1.75"
        strokeLinecap="round"
        strokeOpacity=".55"
      />
      <circle cx="10.5" cy="11.5" r="2.75" fill="currentColor" />
      <circle cx="21.5" cy="11.5" r="2.75" fill="currentColor" />
      <circle cx="16" cy="21" r="2.75" className="fill-blue-500" />
    </svg>
  )
}

export function Logo({ className }: { className?: string }) {
  return (
    <span className={cn("inline-flex items-center gap-2 font-semibold tracking-tight", className)}>
      <LogoMark />
      <span>Leazone</span>
    </span>
  )
}
