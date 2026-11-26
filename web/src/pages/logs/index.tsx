import { useSearchParams } from "react-router"
import { PageHeader } from "@/components/page-header"
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs"
import { AuditTab } from "./audit-tab"
import { DhcpTab } from "./dhcp-tab"
import { DnsTab } from "./dns-tab"
import { RetentionCard } from "./retention-card"

export default function LogsPage() {
  const [params, setParams] = useSearchParams()
  const t = params.get("tab")
  const tab = t === "dhcp" || t === "audit" ? t : "dns"
  return (
    <>
      <PageHeader title="Journaux" description="Requêtes DNS, événements DHCP et actions des utilisateurs." />
      {tab !== "audit" && <RetentionCard />}
      {/* Changing tab clears the filters (they do not mean the same thing). */}
      <Tabs value={tab} onValueChange={(v) => setParams({ tab: v }, { replace: true })}>
        <div className="-mx-4 overflow-x-auto px-4 sm:mx-0 sm:px-0">
          <TabsList>
            <TabsTrigger value="dns">Requêtes DNS</TabsTrigger>
            <TabsTrigger value="dhcp">DHCP</TabsTrigger>
            <TabsTrigger value="audit">Audit</TabsTrigger>
          </TabsList>
        </div>
        <TabsContent value="dns" className="mt-4">
          <DnsTab />
        </TabsContent>
        <TabsContent value="dhcp" className="mt-4">
          <DhcpTab />
        </TabsContent>
        <TabsContent value="audit" className="mt-4">
          <AuditTab />
        </TabsContent>
      </Tabs>
    </>
  )
}
