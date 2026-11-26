import * as React from "react"
import type { SeriesPoint } from "@/api/types"
import { compact, fmtInt, hhmm } from "@/lib/logs"
import { cn } from "@/lib/utils"

/*
 * DNS queries of the last hour, one point per minute: overlaid areas
 * (10 % wash + 2 px line) for all queries, answers from the cache and blocked
 * queries. Hand-written SVG (no chart library), sized in real pixels from a
 * ResizeObserver so the text never scales. Crosshair + tooltip on hover and
 * with the arrow keys; the values are also in a table under the chart.
 */

type Key = "queries" | "cached" | "blocked"
type Series = { key: Key; label: string; stroke: string; fill: string; swatch: string }

const ALL: Series[] = [
  { key: "queries", label: "Requêtes", stroke: "stroke-series-1", fill: "fill-series-1", swatch: "bg-series-1" },
  { key: "blocked", label: "Bloquées", stroke: "stroke-series-2", fill: "fill-series-2", swatch: "bg-series-2" },
  { key: "cached", label: "Depuis le cache", stroke: "stroke-series-3", fill: "fill-series-3", swatch: "bg-series-3" },
]

const HEIGHT = 220
const M = { top: 12, right: 12, bottom: 24, left: 40 }

/** Rounded max and tick step for a 0-based axis (about 4 ticks). */
function niceScale(max: number): { max: number; step: number } {
  if (max <= 0) return { max: 4, step: 1 }
  const raw = max / 4
  const pow = 10 ** Math.floor(Math.log10(raw))
  const step = [1, 2, 2.5, 5, 10].map((m) => m * pow).find((s) => s >= raw) ?? 10 * pow
  const s = step < 1 ? 1 : step
  return { max: Math.ceil(max / s) * s, step: s }
}

function useWidth(ref: React.RefObject<HTMLDivElement | null>) {
  const [w, setW] = React.useState(0)
  React.useLayoutEffect(() => {
    const el = ref.current
    if (!el) return
    setW(el.clientWidth)
    const ro = new ResizeObserver((entries) => setW(Math.round(entries[0].contentRect.width)))
    ro.observe(el)
    return () => ro.disconnect()
  }, [ref])
  return w
}

export function QueryChart({ points, showBlocked }: { points: SeriesPoint[]; showBlocked: boolean }) {
  const series = showBlocked ? ALL : ALL.filter((s) => s.key !== "blocked")
  const boxRef = React.useRef<HTMLDivElement>(null)
  const width = useWidth(boxRef)
  const [hover, setHover] = React.useState<number | null>(null)

  const n = points.length
  const innerW = Math.max(0, width - M.left - M.right)
  const innerH = HEIGHT - M.top - M.bottom
  const val = (p: SeriesPoint, k: Key) => Math.max(0, p[k] ?? 0)
  const { max, step } = niceScale(Math.max(0, ...points.flatMap((p) => series.map((s) => val(p, s.key)))))
  const x = (i: number) => M.left + (n <= 1 ? innerW : (i / (n - 1)) * innerW)
  const y = (v: number) => M.top + innerH - (v / max) * innerH
  const base = M.top + innerH

  const ticks: number[] = []
  for (let t = 0; t <= max + step / 2; t += step) ticks.push(t)

  // X labels: one every 15 minutes (on round quarters when possible), never crowded.
  const xLabels: number[] = []
  if (n > 1) {
    const every = innerW < 360 ? 30 : 15
    points.forEach((p, i) => {
      const d = new Date(p.t ?? "")
      if (!Number.isNaN(d.getTime()) && d.getMinutes() % every === 0) xLabels.push(i)
    })
    if (xLabels.length === 0) xLabels.push(0, n - 1)
  }

  const line = (k: Key) => points.map((p, i) => `${i === 0 ? "M" : "L"}${x(i).toFixed(1)},${y(val(p, k)).toFixed(1)}`).join("")
  const area = (k: Key) => `${line(k)}L${x(n - 1).toFixed(1)},${base}L${x(0).toFixed(1)},${base}Z`

  const indexAt = (clientX: number, rect: DOMRect) => {
    if (n === 0) return null
    const px = clientX - rect.left - M.left
    return Math.max(0, Math.min(n - 1, Math.round((px / Math.max(1, innerW)) * (n - 1))))
  }

  const onKey = (e: React.KeyboardEvent) => {
    if (n === 0) return
    const cur = hover ?? n - 1
    if (e.key === "ArrowLeft") setHover(Math.max(0, cur - 1))
    else if (e.key === "ArrowRight") setHover(Math.min(n - 1, cur + 1))
    else if (e.key === "Home") setHover(0)
    else if (e.key === "End") setHover(n - 1)
    else if (e.key === "Escape") setHover(null)
    else return
    e.preventDefault()
  }

  const h = hover !== null && hover < n ? points[hover] : null
  const hx = hover !== null ? x(hover) : 0
  const tipLeft = hx > width / 2

  return (
    <div className="space-y-3">
      <ul className="flex flex-wrap gap-x-4 gap-y-1 text-xs text-muted-foreground" aria-hidden>
        {series.map((s) => (
          <li key={s.key} className="inline-flex items-center gap-1.5">
            <span className={cn("size-2.5 rounded-[3px]", s.swatch)} />
            {s.label}
          </li>
        ))}
      </ul>
      <div ref={boxRef} className="relative w-full" style={{ height: HEIGHT }}>
        {width > 0 && (
          <svg
            width={width}
            height={HEIGHT}
            role="img"
            tabIndex={0}
            aria-label="Requêtes DNS par minute sur la dernière heure. Flèches gauche et droite pour lire les valeurs."
            className="block touch-pan-y rounded-md outline-none focus-visible:ring-[3px] focus-visible:ring-ring/50"
            onPointerMove={(e) => setHover(indexAt(e.clientX, e.currentTarget.getBoundingClientRect()))}
            onPointerDown={(e) => setHover(indexAt(e.clientX, e.currentTarget.getBoundingClientRect()))}
            onPointerLeave={(e) => e.pointerType === "mouse" && setHover(null)}
            onKeyDown={onKey}
            onFocus={() => setHover((v) => v ?? (n > 0 ? n - 1 : null))}
            onBlur={() => setHover(null)}
          >
            {/* Grid and Y axis */}
            {ticks.map((t) => (
              <g key={t}>
                <line x1={M.left} x2={width - M.right} y1={y(t)} y2={y(t)} className="stroke-border" strokeWidth={1} shapeRendering="crispEdges" />
                <text x={M.left - 8} y={y(t)} dy="0.32em" textAnchor="end" className="fill-muted-foreground text-[11px] tabular-nums">
                  {compact(t)}
                </text>
              </g>
            ))}
            {xLabels.map((i) => (
              <text
                key={i}
                x={x(i)}
                y={HEIGHT - 6}
                textAnchor={i === 0 ? "start" : i === n - 1 ? "end" : "middle"}
                className="fill-muted-foreground text-[11px] tabular-nums"
              >
                {hhmm.format(new Date(points[i].t ?? ""))}
              </text>
            ))}
            {n > 1 &&
              series.map((s) => (
                <g key={s.key} data-series={s.key}>
                  <path d={area(s.key)} className={s.fill} fillOpacity={0.1} />
                  <path d={line(s.key)} className={s.stroke} fill="none" strokeWidth={2} strokeLinejoin="round" strokeLinecap="round" />
                </g>
              ))}
            {h && (
              <g pointerEvents="none">
                <line x1={hx} x2={hx} y1={M.top} y2={base} className="stroke-muted-foreground/60" strokeWidth={1} />
                {series.map((s) => (
                  <circle key={s.key} cx={hx} cy={y(val(h, s.key))} r={4} className={cn(s.fill, "stroke-card")} strokeWidth={2} />
                ))}
              </g>
            )}
          </svg>
        )}
        {n <= 1 && (
          <div className="absolute inset-0 flex items-center justify-center text-sm text-muted-foreground">
            Pas encore de données pour la dernière heure.
          </div>
        )}
        {h && (
          <div
            role="status"
            data-testid="chart-tooltip"
            className="pointer-events-none absolute top-2 z-10 min-w-36 rounded-md border bg-popover px-3 py-2 text-xs text-popover-foreground shadow-md"
            style={tipLeft ? { right: width - hx + 10 } : { left: hx + 10 }}
          >
            <div className="mb-1 font-medium text-muted-foreground tabular-nums">{hhmm.format(new Date(h.t ?? ""))}</div>
            <ul className="space-y-0.5">
              {series.map((s) => (
                <li key={s.key} className="flex items-center gap-2">
                  <span className={cn("h-0.5 w-3 rounded-full", s.swatch)} aria-hidden />
                  <span className="font-semibold tabular-nums">{fmtInt.format(val(h, s.key))}</span>
                  <span className="text-muted-foreground">{s.label.toLowerCase()}</span>
                </li>
              ))}
            </ul>
          </div>
        )}
      </div>
      {n > 0 && (
        <details className="group text-xs">
          <summary className="w-fit cursor-pointer text-muted-foreground select-none hover:text-foreground">Voir les valeurs</summary>
          <div className="mt-2 max-h-56 overflow-auto rounded-md border">
            <table className="w-full text-left tabular-nums">
              <caption className="sr-only">Requêtes DNS par minute</caption>
              <thead className="sticky top-0 bg-muted text-muted-foreground">
                <tr>
                  <th className="px-3 py-1.5 font-medium">Minute</th>
                  {series.map((s) => (
                    <th key={s.key} className="px-3 py-1.5 text-right font-medium">
                      {s.label}
                    </th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {[...points].reverse().map((p) => (
                  <tr key={p.t} className="border-t">
                    <td className="px-3 py-1">{hhmm.format(new Date(p.t ?? ""))}</td>
                    {series.map((s) => (
                      <td key={s.key} className="px-3 py-1 text-right">
                        {fmtInt.format(val(p, s.key))}
                      </td>
                    ))}
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </details>
      )}
    </div>
  )
}
