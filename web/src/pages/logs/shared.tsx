import * as React from "react"
import { useSearchParams } from "react-router"
import { Loader2, Search, X } from "lucide-react"
import { Button } from "@/components/ui/button"
import { Input } from "@/components/ui/input"
import { Label } from "@/components/ui/label"
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select"
import { useDebounced } from "@/hooks/use-debounced"
import { isPeriod, isoToLocal, logTime, periods, type Period } from "@/lib/logs"
import { cn } from "@/lib/utils"

/* Building blocks shared by the DNS and DHCP log tabs. Filters live in the URL. */

export type Params = URLSearchParams
export type SetParams = (patch: Record<string, string | undefined>) => void

/** URL params and a patch setter (empty values remove the key; history is replaced). */
export function useLogParams(): [Params, SetParams] {
  const [params, setParams] = useSearchParams()
  const set = React.useCallback<SetParams>(
    (patch) =>
      setParams(
        (p) => {
          const n = new URLSearchParams(p)
          for (const [k, v] of Object.entries(patch)) {
            if (v) n.set(k, v)
            else n.delete(k)
          }
          return n
        },
        { replace: true },
      ),
    [setParams],
  )
  return [params, set]
}

/** Period from the URL (default: last hour). */
export function usePeriod(params: Params): { period: Period; from: string; to: string } {
  const p = params.get("period")
  return { period: isPeriod(p) ? p : "1h", from: params.get("from") ?? "", to: params.get("to") ?? "" }
}

/**
 * Text filter kept in the URL: typing stays smooth (local state), the URL is
 * updated 300 ms after the last key, and a change of the URL from elsewhere
 * (a "filter on this client" action, a dashboard link) refills the box.
 */
export function UrlTextFilter({
  name,
  params,
  setParam,
  placeholder,
  label,
  className,
  mono,
}: {
  name: string
  params: Params
  setParam: SetParams
  placeholder: string
  label: string
  className?: string
  mono?: boolean
}) {
  const urlValue = params.get(name) ?? ""
  const [value, setValue] = React.useState(urlValue)
  const pushed = React.useRef(urlValue)
  // Only text typed here goes to the URL (never an echo of a URL value, which
  // could be a stale one while the router switches tabs).
  const typed = React.useRef(false)
  React.useEffect(() => {
    if (urlValue !== pushed.current) {
      pushed.current = urlValue
      typed.current = false
      setValue(urlValue)
    }
  }, [urlValue])
  const debounced = useDebounced(value.trim(), 300)
  React.useEffect(() => {
    if (typed.current && debounced !== pushed.current) {
      pushed.current = debounced
      setParam({ [name]: debounced || undefined })
    }
  }, [debounced, name, setParam])
  const change = (v: string) => {
    typed.current = true
    setValue(v)
  }
  return (
    <div className={cn("relative", className)}>
      <Search className="pointer-events-none absolute top-1/2 left-2.5 size-4 -translate-y-1/2 text-muted-foreground" />
      <Input
        value={value}
        onChange={(e) => change(e.target.value)}
        placeholder={placeholder}
        aria-label={label}
        className={cn("pr-8 pl-8", mono && value && "font-mono text-xs")}
        spellCheck={false}
        autoCapitalize="off"
      />
      {value && (
        <button
          type="button"
          onClick={() => change("")}
          className="absolute top-1/2 right-2 -translate-y-1/2 rounded-sm p-0.5 text-muted-foreground hover:text-foreground"
          aria-label={`Effacer : ${label}`}
        >
          <X className="size-3.5" />
        </button>
      )}
    </div>
  )
}

/** Select kept in the URL ("all" = no filter). */
export function UrlSelect({
  name,
  params,
  setParam,
  label,
  allLabel,
  options,
  className,
}: {
  name: string
  params: Params
  setParam: SetParams
  label: string
  allLabel: string
  options: { value: string; label: string }[]
  className?: string
}) {
  const v = params.get(name) ?? ""
  const value = options.some((o) => o.value === v) ? v : "all"
  return (
    <Select value={value} onValueChange={(nv) => setParam({ [name]: nv === "all" ? undefined : nv })}>
      <SelectTrigger className={cn("w-full sm:w-auto sm:min-w-36", className)} aria-label={label}>
        <SelectValue />
      </SelectTrigger>
      <SelectContent>
        <SelectItem value="all">{allLabel}</SelectItem>
        {options.map((o) => (
          <SelectItem key={o.value} value={o.value}>
            {o.label}
          </SelectItem>
        ))}
      </SelectContent>
    </Select>
  )
}

/** Period presets + custom from/to (datetime-local inputs). */
export function PeriodFilter({ params, setParam, className }: { params: Params; setParam: SetParams; className?: string }) {
  const { period, from, to } = usePeriod(params)
  const onPeriod = (v: string) => {
    if (v === "custom") {
      // Start from the last hour, easy to adjust.
      const now = new Date()
      setParam({ period: "custom", from: from || isoToLocal(new Date(now.getTime() - 3600_000)), to: to || isoToLocal(now) })
    } else setParam({ period: v === "1h" ? undefined : v, from: undefined, to: undefined })
  }
  return (
    <>
      <Select value={period} onValueChange={onPeriod}>
        <SelectTrigger className={cn("w-full sm:w-auto sm:min-w-40", className)} aria-label="Période">
          <SelectValue />
        </SelectTrigger>
        <SelectContent>
          {periods.map((p) => (
            <SelectItem key={p.value} value={p.value}>
              {p.label}
            </SelectItem>
          ))}
        </SelectContent>
      </Select>
      {period === "custom" && (
        <div className="col-span-2 flex w-full flex-col gap-2 sm:w-auto sm:flex-row sm:items-center">
          <Label className="flex items-center gap-2 text-xs font-normal text-muted-foreground">
            Du
            <Input
              type="datetime-local"
              value={from}
              max={to || undefined}
              onChange={(e) => setParam({ from: e.target.value || undefined })}
              className="w-full sm:w-auto"
            />
          </Label>
          <Label className="flex items-center gap-2 text-xs font-normal text-muted-foreground">
            au
            <Input
              type="datetime-local"
              value={to}
              min={from || undefined}
              onChange={(e) => setParam({ to: e.target.value || undefined })}
              className="w-full sm:w-auto"
            />
          </Label>
        </div>
      )}
    </>
  )
}

/** Time cell: "14:05:09" (date when not today), full date on hover. */
export function TimeCell({ value }: { value?: string }) {
  const t = logTime(value)
  return (
    <time dateTime={value} title={t.title} className="whitespace-nowrap tabular-nums">
      {t.short}
    </time>
  )
}

/**
 * "Charger plus" button, also triggered when it scrolls into view
 * (infinite scroll), except while following live.
 */
export function LoadMore({
  hasMore,
  loading,
  onLoad,
  auto,
  count,
}: {
  hasMore: boolean
  loading: boolean
  onLoad: () => void
  auto: boolean
  count: number
}) {
  const ref = React.useRef<HTMLDivElement>(null)
  const cb = React.useRef(onLoad)
  cb.current = onLoad
  React.useEffect(() => {
    const el = ref.current
    if (!el || !hasMore || !auto || typeof IntersectionObserver === "undefined") return
    const io = new IntersectionObserver((entries) => {
      if (entries[0]?.isIntersecting) cb.current()
    }, { rootMargin: "200px" })
    io.observe(el)
    return () => io.disconnect()
  }, [hasMore, auto])
  return (
    <div ref={ref} className="flex items-center justify-between gap-2">
      <p className="text-xs text-muted-foreground">
        {count} entrée{count > 1 ? "s" : ""}
        {hasMore ? " affichée" + (count > 1 ? "s" : "") : ""}
      </p>
      {hasMore && (
        <Button variant="outline" onClick={onLoad} disabled={loading}>
          {loading && <Loader2 className="animate-spin" />}
          Charger plus
        </Button>
      )}
    </div>
  )
}
