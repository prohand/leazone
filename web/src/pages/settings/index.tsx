import { useSearchParams } from "react-router"
import { PageHeader } from "@/components/page-header"
import { WriteGuard } from "@/components/read-only"
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs"
import { BackupTab } from "./backup-tab"
import { DnsTab } from "./dns-tab"
import { HttpsTab } from "./https-tab"
import { ImportTab } from "./import-tab"
import { ModulesTab } from "./modules-tab"
import { SecurityTab } from "./security-tab"

export default function SettingsPage() {
  const [params, setParams] = useSearchParams()
  const t = params.get("tab")
  const tab = t === "https" || t === "dns" || t === "modules" || t === "import" || t === "backup" ? t : "security"
  return (
    <>
      <PageHeader title="Paramètres" description="Réglages du serveur. Réservé aux administrateurs." />
      <Tabs value={tab} onValueChange={(v) => setParams({ tab: v }, { replace: true })}>
        <div className="-mx-4 overflow-x-auto px-4 sm:mx-0 sm:px-0">
          <TabsList>
            <TabsTrigger value="security">Sécurité</TabsTrigger>
            <TabsTrigger value="https">HTTPS</TabsTrigger>
            <TabsTrigger value="dns">DNS</TabsTrigger>
            <TabsTrigger value="modules">Modules</TabsTrigger>
            <TabsTrigger value="import">Import</TabsTrigger>
            <TabsTrigger value="backup">Sauvegarde</TabsTrigger>
          </TabsList>
        </div>
        <TabsContent value="security" className="mt-4">
          <WriteGuard block>
            <SecurityTab />
          </WriteGuard>
        </TabsContent>
        <TabsContent value="https" className="mt-4">
          <WriteGuard block>
            <HttpsTab />
          </WriteGuard>
        </TabsContent>
        <TabsContent value="dns" className="mt-4">
          <DnsTab />
        </TabsContent>
        <TabsContent value="modules" className="mt-4">
          <WriteGuard block>
            <ModulesTab />
          </WriteGuard>
        </TabsContent>
        <TabsContent value="import" className="mt-4">
          <WriteGuard block>
            <ImportTab />
          </WriteGuard>
        </TabsContent>
        <TabsContent value="backup" className="mt-4">
          {/* Not guarded as a whole: a backup works on every node, only the restore needs the primary. */}
          <BackupTab />
        </TabsContent>
      </Tabs>
    </>
  )
}
