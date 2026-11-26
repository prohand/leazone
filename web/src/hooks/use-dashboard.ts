import * as React from "react"
import { useQuery, useQueryClient, type QueryClient } from "@tanstack/react-query"
import { API_BASE } from "@/api/client"
import { dashboardQuery, qk } from "@/api/queries"
import type { Dashboard } from "@/api/types"

/*
 * Live dashboard data.
 *
 * One shared EventSource on /api/v1/events (opened while at least one
 * component uses the hook): each "dashboard" event replaces the cached
 * GET /dashboard answer, "leases" refreshes the DHCP queries. While the stream
 * is down, the query polls GET /dashboard every 5 s, and the stream is
 * reopened with an exponential backoff (1 s, 2 s, 4 s... up to 30 s).
 */

const POLL_MS = 5_000
const BACKOFF_MIN_MS = 1_000
const BACKOFF_MAX_MS = 30_000

type StreamState = { connected: boolean }

let users = 0
let source: EventSource | null = null
let retryTimer: number | undefined
let backoff = BACKOFF_MIN_MS
let client: QueryClient | null = null
let state: StreamState = { connected: false }
const listeners = new Set<() => void>()

function setConnected(connected: boolean) {
  if (state.connected === connected) return
  state = { connected }
  listeners.forEach((l) => l())
}

function open() {
  if (source || typeof EventSource === "undefined") return
  const es = new EventSource(`${API_BASE}/events`, { withCredentials: true })
  source = es
  es.onopen = () => {
    backoff = BACKOFF_MIN_MS
    setConnected(true)
  }
  es.addEventListener("dashboard", (e) => {
    try {
      const data = JSON.parse((e as MessageEvent<string>).data) as Dashboard
      client?.setQueryData(qk.dashboard, data)
      setConnected(true)
    } catch {
      // malformed event: keep the previous data
    }
  })
  es.addEventListener("leases", () => {
    void client?.invalidateQueries({ queryKey: qk.dhcp })
    void client?.invalidateQueries({ queryKey: qk.vlans })
  })
  es.onerror = () => {
    // The browser would retry on its own with a fixed delay; we take over
    // (polling meanwhile) so a closed or refused stream backs off.
    es.close()
    if (source === es) source = null
    setConnected(false)
    scheduleReconnect()
  }
}

function scheduleReconnect() {
  window.clearTimeout(retryTimer)
  if (users === 0) return
  const delay = backoff
  backoff = Math.min(backoff * 2, BACKOFF_MAX_MS)
  retryTimer = window.setTimeout(() => {
    if (users > 0) open()
  }, delay)
}

function close() {
  window.clearTimeout(retryTimer)
  source?.close()
  source = null
  backoff = BACKOFF_MIN_MS
  setConnected(false)
}

function subscribe(listener: () => void) {
  listeners.add(listener)
  return () => listeners.delete(listener)
}

/** Dashboard data (live) and whether the event stream is connected. */
export function useDashboard() {
  const qc = useQueryClient()
  React.useEffect(() => {
    client = qc
    users++
    open()
    return () => {
      users--
      if (users === 0) close()
    }
  }, [qc])
  const live = React.useSyncExternalStore(subscribe, () => state.connected)
  const query = useQuery({ ...dashboardQuery, refetchInterval: live ? false : POLL_MS })
  return { ...query, live }
}
