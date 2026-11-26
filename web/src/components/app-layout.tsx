import * as React from "react"
import { Outlet, useLocation } from "react-router"
import { Search } from "lucide-react"
import { Button } from "@/components/ui/button"
import { Separator } from "@/components/ui/separator"
import { SidebarInset, SidebarProvider, SidebarTrigger } from "@/components/ui/sidebar"
import { findNavItem } from "@/lib/nav"
import { AppSidebar } from "./app-sidebar"
import { SelfSignedBanner } from "./auth-shell"
import { CommandPaletteProvider, useCommandPalette } from "./command-palette"
import { BlockSpinner } from "./spinner"
import { ThemeToggle } from "./theme-toggle"

const isMac = typeof navigator !== "undefined" && /Mac|iPhone|iPad/.test(navigator.platform)

function TopBar() {
  const { setOpen } = useCommandPalette()
  const location = useLocation()
  const title = location.pathname === "/account" ? "Mon compte" : findNavItem(location.pathname)?.title
  return (
    <header className="sticky top-0 z-10 flex h-14 shrink-0 items-center gap-2 border-b bg-background/80 px-4 backdrop-blur supports-[backdrop-filter]:bg-background/60">
      <SidebarTrigger className="-ml-1" />
      <Separator orientation="vertical" className="mr-1 data-[orientation=vertical]:h-4" />
      <span className="truncate text-sm font-medium">{title}</span>
      <div className="ml-auto flex items-center gap-1">
        <Button
          variant="outline"
          className="h-8 w-9 justify-start gap-2 px-2 text-muted-foreground sm:w-56 sm:px-3"
          onClick={() => setOpen(true)}
          aria-label="Rechercher"
        >
          <Search className="size-4" />
          <span className="hidden flex-1 text-left text-sm font-normal sm:inline">Rechercher…</span>
          <kbd className="pointer-events-none hidden h-5 items-center gap-0.5 rounded border bg-muted px-1.5 font-mono text-[10px] font-medium sm:inline-flex">
            {isMac ? "⌘" : "Ctrl"} K
          </kbd>
        </Button>
        <ThemeToggle />
      </div>
    </header>
  )
}

export function AppLayout() {
  return (
    <CommandPaletteProvider>
      <SidebarProvider>
        <AppSidebar />
        <SidebarInset>
          <SelfSignedBanner />
          <TopBar />
          <main className="mx-auto w-full max-w-6xl flex-1 px-4 py-6 sm:px-6 lg:py-8">
            <React.Suspense fallback={<BlockSpinner />}>
              <Outlet />
            </React.Suspense>
          </main>
        </SidebarInset>
      </SidebarProvider>
    </CommandPaletteProvider>
  )
}
