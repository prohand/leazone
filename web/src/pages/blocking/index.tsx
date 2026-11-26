import * as React from "react"
import { useSearchParams } from "react-router"
import { PageHeader } from "@/components/page-header"
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs"
import { CheckCard } from "./check-card"
import { ListsTab } from "./lists-tab"
import { PoliciesTab } from "./policies-tab"
import { RulesTab } from "./rules-tab"
import { SettingsTab } from "./settings-tab"
import { StatusCard, TopBlockedCard } from "./status"

const tabs = [
  { value: "lists", label: "Listes" },
  { value: "deny", label: "Liste noire" },
  { value: "allow", label: "Liste blanche" },
  { value: "policies", label: "Où bloquer" },
  { value: "settings", label: "Réglages" },
] as const
type Tab = (typeof tabs)[number]["value"]

export default function BlockingPage() {
  const [params, setParams] = useSearchParams()
  const t = params.get("tab")
  const tab: Tab = tabs.some((x) => x.value === t) ? (t as Tab) : "lists"
  const focusTest = params.get("test") === "1"

  // ⌘K "Tester un domaine" lands here with ?test=1: the test box takes the
  // focus (child effect first), then the flag is dropped so it works again.
  React.useEffect(() => {
    if (!focusTest) return
    const next = new URLSearchParams(params)
    next.delete("test")
    setParams(next, { replace: true })
  }, [focusTest, params, setParams])

  return (
    <>
      <PageHeader
        title="Blocage"
        description="Bloque les publicités et les traqueurs pour tout le réseau, à partir de listes publiques."
      />
      <div className="space-y-6">
        <StatusCard />
        <div className="grid gap-6 lg:grid-cols-2 lg:items-start [&>*]:min-w-0">
          <TopBlockedCard />
          <CheckCard focus={focusTest} />
        </div>
        <Tabs
          value={tab}
          onValueChange={(v) => {
            const next = new URLSearchParams(params)
            next.set("tab", v)
            setParams(next, { replace: true })
          }}
        >
          <div className="-mx-4 overflow-x-auto px-4 sm:mx-0 sm:px-0">
            <TabsList>
              {tabs.map((x) => (
                <TabsTrigger key={x.value} value={x.value}>
                  {x.label}
                </TabsTrigger>
              ))}
            </TabsList>
          </div>
          <TabsContent value="lists" className="mt-4">
            <ListsTab />
          </TabsContent>
          <TabsContent value="deny" className="mt-4">
            <RulesTab kind="deny" />
          </TabsContent>
          <TabsContent value="allow" className="mt-4">
            <RulesTab kind="allow" />
          </TabsContent>
          <TabsContent value="policies" className="mt-4">
            <PoliciesTab />
          </TabsContent>
          <TabsContent value="settings" className="mt-4">
            <SettingsTab />
          </TabsContent>
        </Tabs>
      </div>
    </>
  )
}
