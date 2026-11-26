import type * as React from "react"
import { useQuery } from "@tanstack/react-query"
import { ShieldAlert } from "lucide-react"
import { systemInfoQuery } from "@/api/queries"
import { Logo } from "./logo"
import { ThemeToggle } from "./theme-toggle"

export function SelfSignedBanner() {
  const { data } = useQuery(systemInfoQuery)
  if (!data?.selfSignedCertificate) return null
  return (
    <div role="alert" className="flex items-center justify-center gap-2 bg-red-600 px-4 py-2 text-center text-sm font-medium text-white dark:bg-red-700">
      <ShieldAlert className="size-4 shrink-0" />
      Certificat auto-signé : à remplacer avant la mise en production. Les passkeys ne fonctionneront pas.
    </div>
  )
}

/** Centered layout for login / MFA / enrollment pages (outside the app layout). */
export function AuthShell({ children, wide = false }: { children: React.ReactNode; wide?: boolean }) {
  const { data } = useQuery(systemInfoQuery)
  return (
    <div className="flex min-h-svh flex-col bg-muted/30">
      <SelfSignedBanner />
      <div className="flex justify-end p-3">
        <ThemeToggle />
      </div>
      <main className="flex flex-1 flex-col items-center px-4 pt-4 pb-12 sm:pt-12">
        <Logo className="mb-8 text-xl [&_svg]:size-8" />
        <div className={wide ? "w-full max-w-2xl" : "w-full max-w-sm"}>{children}</div>
      </main>
      <footer className="pb-6 text-center text-xs text-muted-foreground">
        {data?.product || "Leazone"} {data?.version && `· v${data.version}`}
      </footer>
    </div>
  )
}
