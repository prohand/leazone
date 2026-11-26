import * as React from "react"
import { Dialog, DialogContent, DialogDescription, DialogHeader, DialogTitle } from "@/components/ui/dialog"
import { BlockSpinner } from "./spinner"

// The panel (form + result) is loaded on first use.
const LookupPanel = React.lazy(() => import("@/pages/dns/lookup-panel"))

type Ctx = { openLookup: (name?: string) => void }
const DnsLookupContext = React.createContext<Ctx>({ openLookup: () => {} })
export const useDnsLookup = () => React.useContext(DnsLookupContext)

/** Global "Tester une résolution DNS" dialog, opened from pages and the ⌘K palette. */
export function DnsLookupProvider({ children }: { children: React.ReactNode }) {
  const [open, setOpen] = React.useState(false)
  const [initialName, setInitialName] = React.useState("")
  const openLookup = React.useCallback((name?: string) => {
    setInitialName(name ?? "")
    setOpen(true)
  }, [])
  const value = React.useMemo(() => ({ openLookup }), [openLookup])
  return (
    <DnsLookupContext.Provider value={value}>
      {children}
      <Dialog open={open} onOpenChange={setOpen}>
        <DialogContent className="sm:max-w-xl">
          <DialogHeader>
            <DialogTitle>Tester une résolution DNS</DialogTitle>
            <DialogDescription>Leazone répond comme il le ferait pour un appareil du réseau.</DialogDescription>
          </DialogHeader>
          {open && (
            <React.Suspense fallback={<BlockSpinner />}>
              <LookupPanel initialName={initialName} />
            </React.Suspense>
          )}
        </DialogContent>
      </Dialog>
    </DnsLookupContext.Provider>
  )
}
