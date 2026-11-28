import { StrictMode } from "react"
import { createRoot } from "react-dom/client"
import { RouterProvider } from "react-router"
import { MutationCache, QueryClient, QueryClientProvider } from "@tanstack/react-query"
import { toast } from "sonner"
import { ApiError, ProblemType, setAuthLostHandler, setCsrfToken, setReadOnlyHandler } from "@/api/client"
import { qk } from "@/api/queries"
import type { SessionState } from "@/api/types"
import { StepUpProvider } from "@/components/step-up"
import { Toaster } from "@/components/ui/sonner"
import { TooltipProvider } from "@/components/ui/tooltip"
import { safeUrl } from "@/hooks/use-cluster"
import { errorMessage, toastError } from "@/lib/errors"
import { ThemeProvider } from "@/lib/theme"
import { router } from "./router"
import "./index.css"

const queryClient = new QueryClient({
  defaultOptions: {
    queries: {
      refetchOnWindowFocus: false,
      retry: (count, err) => {
        // Do not retry client errors (4xx): they will not fix themselves.
        if (err instanceof ApiError && err.status >= 400 && err.status < 500) return false
        return count < 2
      },
    },
  },
  mutationCache: new MutationCache({
    // Mutations report their errors as a toast unless they handle them inline (meta.silent).
    onError: (err, _vars, _ctx, mutation) => {
      if (!mutation.meta?.silent) toastError(err)
    },
  }),
})

// Data that does not depend on who is logged in.
const SHARED_KEYS: readonly unknown[] = [qk.session[0], qk.systemInfo[0]]

// Keep the CSRF token in sync with the cached session state, and forget the
// previous user's data when the session ends or another user logs in (in the
// same tab, after an expiry): /me, users, settings... must not be reused.
let sessionUserId: string | undefined
queryClient.getQueryCache().subscribe((event) => {
  if (event.query.queryKey[0] !== qk.session[0]) return
  const s = event.query.state.data as SessionState | undefined
  setCsrfToken(s?.csrfToken)
  if (!s) return
  const id = s.state === "anonymous" ? undefined : s.user?.id
  if (id === sessionUserId) return
  const previous = sessionUserId
  sessionUserId = id
  if (previous === undefined) return
  // Deferred: the cache is being updated right now.
  queueMicrotask(() => queryClient.removeQueries({ predicate: (q) => !SHARED_KEYS.includes(q.queryKey[0]) }))
})

// Session expired / revoked while using the app: refresh the session state;
// the route guard then sends the user to the login page. (A refused request
// origin is not reported here: see api/client.ts.)
let lostNotified = 0
setAuthLostHandler(() => {
  if (Date.now() - lostNotified > 5000) {
    lostNotified = Date.now()
    toast.info("Session expirée. Reconnectez-vous.")
  }
  void queryClient.invalidateQueries({ queryKey: qk.session })
})

// Config change refused by a cluster secondary (or while the config is frozen):
// explain it once, offer to open the primary, and refresh the cluster state so
// the read-only banner and disabled buttons show up at once.
setReadOnlyHandler((err) => {
  const primary = err.is(ProblemType.notPrimary) ? safeUrl(err.primaryUrl) : ""
  toast.error(err.is(ProblemType.notPrimary) ? "Nœud secondaire" : "Configuration en lecture seule", {
    id: "read-only",
    description: errorMessage(err),
    action: primary ? { label: "Ouvrir le primaire", onClick: () => window.open(primary, "_blank", "noopener,noreferrer") } : undefined,
  })
  void queryClient.invalidateQueries({ queryKey: qk.cluster })
})

createRoot(document.getElementById("root")!).render(
  <StrictMode>
    <ThemeProvider>
      <QueryClientProvider client={queryClient}>
        <TooltipProvider delayDuration={300}>
          <StepUpProvider>
            <RouterProvider router={router} />
          </StepUpProvider>
        </TooltipProvider>
        <Toaster position="bottom-right" richColors closeButton />
      </QueryClientProvider>
    </ThemeProvider>
  </StrictMode>,
)
