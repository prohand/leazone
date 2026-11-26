import * as React from "react"
import { createBrowserRouter, Outlet } from "react-router"
import { AppLayout } from "@/components/app-layout"
import { AuthGate } from "@/components/auth-gate"
import { RequireModule } from "@/components/module-gate"
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
const VlansPage = React.lazy(() => import("@/pages/vlans"))
const ScopesPage = React.lazy(() => import("@/pages/dhcp/scopes"))
const LeasesPage = React.lazy(() => import("@/pages/dhcp/leases"))
const ReservationsPage = React.lazy(() => import("@/pages/dhcp/reservations"))
const ClusterPage = React.lazy(() => import("@/pages/cluster"))
const BlockingPage = React.lazy(() => import("@/pages/blocking"))
const DnssecPage = React.lazy(() => import("@/pages/dnssec"))
const DnssecZonePage = React.lazy(() => import("@/pages/dnssec/zone"))
const NotFoundPage = React.lazy(() => import("@/pages/not-found"))

function Root() {
  return (
    <React.Suspense fallback={<FullScreenSpinner />}>
      <Outlet />
    </React.Suspense>
  )
}

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
          { path: "/vlans", element: <VlansPage /> },
          { path: "/dns/zones", element: <ZonesPage /> },
          { path: "/dns/zones/:id", element: <ZoneDetailPage /> },
          { path: "/dns/forwarders", element: <ForwardersPage /> },
          { path: "/blocking", element: <RequireModule module="blocking"><BlockingPage /></RequireModule> },
          { path: "/dnssec", element: <RequireModule module="dnssec"><DnssecPage /></RequireModule> },
          { path: "/dnssec/:id", element: <RequireModule module="dnssec"><DnssecZonePage /></RequireModule> },
          { path: "/dhcp/scopes", element: <ScopesPage /> },
          { path: "/dhcp/leases", element: <LeasesPage /> },
          { path: "/dhcp/reservations", element: <ReservationsPage /> },
          { path: "/cluster", element: <ClusterPage /> },
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
