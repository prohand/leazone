import { useSearchParams } from "react-router"
import { PageHeader } from "@/components/page-header"
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs"
import { DnsTab } from "./dns-tab"
import { HttpsTab } from "./https-tab"
import { ImportTab } from "./import-tab"
import { SecurityTab } from "./security-tab"

export default function SettingsPage() {
  const [params, setParams] = useSearchParams()
  const t = params.get("tab")
  const tab = t === "https" || t === "dns" || t === "import" ? t : "security"
  return (
    <>
      <PageHeader title="Paramètres" description="Réglages du serveur. Réservé aux administrateurs." />
      <Tabs value={tab} onValueChange={(v) => setParams({ tab: v }, { replace: true })}>
        <TabsList>
          <TabsTrigger value="security">Sécurité</TabsTrigger>
          <TabsTrigger value="https">HTTPS</TabsTrigger>
          <TabsTrigger value="dns">DNS</TabsTrigger>
          <TabsTrigger value="import">Import</TabsTrigger>
        </TabsList>
        <TabsContent value="security" className="mt-4">
          <SecurityTab />
        </TabsContent>
        <TabsContent value="https" className="mt-4">
          <HttpsTab />
        </TabsContent>
        <TabsContent value="dns" className="mt-4">
          <DnsTab />
        </TabsContent>
        <TabsContent value="import" className="mt-4">
          <ImportTab />
        </TabsContent>
      </Tabs>
    </>
  )
}
