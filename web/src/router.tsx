import * as React from "react"
import { createBrowserRouter, Outlet } from "react-router"
import { AppLayout } from "@/components/app-layout"
import { AuthGate } from "@/components/auth-gate"
import { FullScreenSpinner } from "@/components/spinner"
import { RequireAdmin } from "@/pages/forbidden"

// Route-level code splitting.
const LoginPage = React.lazy(() => import("@/pages/login"))
const LoginMfaPage = React.lazy(() => import("@/pages/login-mfa"))
const SetupMfaPage = React.lazy(() => import("@/pages/setup-mfa"))
const DashboardPage = React.lazy(() => import("@/pages/dashboard"))
const AccountPage = React.lazy(() => import("@/pages/account"))
const UsersPage = React.lazy(() => import("@/pages/users"))
const SettingsPage = React.lazy(() => import("@/pages/settings"))
const LogsPage = React.lazy(() => import("@/pages/logs"))
const InterfacesPage = React.lazy(() => import("@/pages/interfaces"))
const ZonesPage = React.lazy(() => import("@/pages/dns/zones"))
const ZoneDetailPage = React.lazy(() => import("@/pages/dns/zone-detail"))
const ForwardersPage = React.lazy(() => import("@/pages/dns/forwarders"))
const ComingSoonPage = React.lazy(() => import("@/pages/coming-soon"))
const NotFoundPage = React.lazy(() => import("@/pages/not-found"))

function Root() {
  return (
    <React.Suspense fallback={<FullScreenSpinner />}>
      <Outlet />
    </React.Suspense>
  )
}

const soon = (path: string) => ({ path, element: <ComingSoonPage /> })

export const router = createBrowserRouter([
  {
    element: <Root />,
    children: [
      { path: "/login", element: <AuthGate allow="anonymous"><LoginPage /></AuthGate> },
      { path: "/login/mfa", element: <AuthGate allow="mfa_required"><LoginMfaPage /></AuthGate> },
      { path: "/setup-mfa", element: <AuthGate allow="mfa_setup_required"><SetupMfaPage /></AuthGate> },
      {
        element: (
          <AuthGate allow="authenticated">
            <AppLayout />
          </AuthGate>
        ),
        children: [
          { index: true, element: <DashboardPage /> },
          { path: "/interfaces", element: <InterfacesPage /> },
          soon("/vlans"),
          { path: "/dns/zones", element: <ZonesPage /> },
          { path: "/dns/zones/:id", element: <ZoneDetailPage /> },
          { path: "/dns/forwarders", element: <ForwardersPage /> },
          soon("/blocking"),
          soon("/dnssec"),
          soon("/dhcp/scopes"),
          soon("/dhcp/leases"),
          soon("/dhcp/reservations"),
          soon("/cluster"),
          { path: "/logs", element: <LogsPage /> },
          { path: "/account", element: <AccountPage /> },
          { path: "/users", element: <RequireAdmin><UsersPage /></RequireAdmin> },
          { path: "/settings", element: <RequireAdmin><SettingsPage /></RequireAdmin> },
          { path: "*", element: <NotFoundPage /> },
        ],
      },
    ],
  },
])
