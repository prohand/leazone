import { useSearchParams } from "react-router"
import { PageHeader } from "@/components/page-header"
import { WriteGuard } from "@/components/read-only"
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs"
import { PasskeysTab } from "./passkeys-tab"
import { ProfileTab } from "./profile-tab"
import { RecoveryTab } from "./recovery-tab"
import { SessionsTab } from "./sessions-tab"
import { TokensTab } from "./tokens-tab"
import { TotpTab } from "./totp-tab"

// `local`: changes stay on this node (allowed on a read-only cluster secondary).
const tabs = [
  { value: "profile", label: "Profil", Component: ProfileTab, local: false },
  { value: "passkeys", label: "Passkeys", Component: PasskeysTab, local: false },
  { value: "totp", label: "TOTP", Component: TotpTab, local: false },
  { value: "recovery", label: "Codes de secours", Component: RecoveryTab, local: false },
  { value: "sessions", label: "Sessions", Component: SessionsTab, local: true },
  { value: "tokens", label: "Jetons d'API", Component: TokensTab, local: false },
] as const

export default function AccountPage() {
  const [params, setParams] = useSearchParams()
  const current = tabs.some((t) => t.value === params.get("tab")) ? params.get("tab")! : "profile"
  return (
    <>
      <PageHeader title="Mon compte" description="Profil, méthodes de connexion, sessions et jetons d'API." />
      <Tabs value={current} onValueChange={(v) => setParams({ tab: v }, { replace: true })}>
        <div className="-mx-4 overflow-x-auto px-4 sm:mx-0 sm:px-0">
          <TabsList>
            {tabs.map((t) => (
              <TabsTrigger key={t.value} value={t.value}>
                {t.label}
              </TabsTrigger>
            ))}
          </TabsList>
        </div>
        {tabs.map((t) => (
          <TabsContent key={t.value} value={t.value} className="mt-4">
            {t.local ? (
              <t.Component />
            ) : (
              <WriteGuard block>
                <t.Component />
              </WriteGuard>
            )}
          </TabsContent>
        ))}
      </Tabs>
    </>
  )
}
