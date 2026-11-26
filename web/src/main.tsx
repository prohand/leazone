import { StrictMode } from "react"
import { createRoot } from "react-dom/client"
import { RouterProvider } from "react-router"
import { MutationCache, QueryClient, QueryClientProvider } from "@tanstack/react-query"
import { toast } from "sonner"
import { ApiError, setAuthLostHandler, setCsrfToken } from "@/api/client"
import { qk } from "@/api/queries"
import type { SessionState } from "@/api/types"
import { StepUpProvider } from "@/components/step-up"
import { Toaster } from "@/components/ui/sonner"
import { TooltipProvider } from "@/components/ui/tooltip"
import { toastError } from "@/lib/errors"
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

// Keep the CSRF token in sync with the cached session state.
queryClient.getQueryCache().subscribe((event) => {
  if (event.query.queryKey[0] !== qk.session[0]) return
  const s = event.query.state.data as SessionState | undefined
  setCsrfToken(s?.csrfToken)
})

// Session expired / revoked while using the app: refresh the session state;
// the route guard then sends the user to the login page.
let lostNotified = 0
setAuthLostHandler(() => {
  if (Date.now() - lostNotified > 5000) {
    lostNotified = Date.now()
    toast.info("Session expirée. Reconnectez-vous.")
  }
  void queryClient.invalidateQueries({ queryKey: qk.session })
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
