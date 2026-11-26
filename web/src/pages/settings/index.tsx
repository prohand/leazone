import { useSearchParams } from "react-router"
import { PageHeader } from "@/components/page-header"
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs"
import { HttpsTab } from "./https-tab"
import { SecurityTab } from "./security-tab"

export default function SettingsPage() {
  const [params, setParams] = useSearchParams()
  const tab = params.get("tab") === "https" ? "https" : "security"
  return (
    <>
      <PageHeader title="Paramètres" description="Réglages du serveur. Réservé aux administrateurs." />
      <Tabs value={tab} onValueChange={(v) => setParams({ tab: v }, { replace: true })}>
        <TabsList>
          <TabsTrigger value="security">Sécurité</TabsTrigger>
          <TabsTrigger value="https">HTTPS</TabsTrigger>
        </TabsList>
        <TabsContent value="security" className="mt-4">
          <SecurityTab />
        </TabsContent>
        <TabsContent value="https" className="mt-4">
          <HttpsTab />
        </TabsContent>
      </Tabs>
    </>
  )
}
