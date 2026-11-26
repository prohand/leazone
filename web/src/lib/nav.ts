import type { LucideIcon } from "lucide-react"
import {
  BookmarkCheck,
  EthernetPort,
  Forward,
  Globe,
  Layers,
  LayoutDashboard,
  Network,
  ScrollText,
  Server,
  Settings,
  ShieldBan,
  ShieldCheck,
  Timer,
  Users,
} from "lucide-react"
import type { Role } from "@/api/types"
import { modules, type ModuleName } from "./modules"
import { can } from "./permissions"

export type NavItem = {
  title: string
  path: string
  icon: LucideIcon
  adminOnly?: boolean
  module?: ModuleName
  /** Extra words for the ⌘K search. */
  keywords?: string[]
}

export type NavGroup = { label: string; items: NavItem[] }

export const navGroups: NavGroup[] = [
  {
    label: "Vue d'ensemble",
    items: [
      { title: "Tableau de bord", path: "/", icon: LayoutDashboard, keywords: ["accueil", "dashboard"] },
      { title: "Interfaces", path: "/interfaces", icon: EthernetPort, keywords: ["réseau", "carte"] },
      { title: "VLAN", path: "/vlans", icon: Layers },
    ],
  },
  {
    label: "DNS",
    items: [
      { title: "Zones DNS", path: "/dns/zones", icon: Globe, keywords: ["enregistrements", "domaine"] },
      { title: "Redirecteurs", path: "/dns/forwarders", icon: Forward, keywords: ["forwarders", "DoH", "DoT"] },
      { title: "Blocage", path: "/blocking", icon: ShieldBan, module: "blocking", keywords: ["publicité", "pub"] },
      { title: "DNSSEC", path: "/dnssec", icon: ShieldCheck, module: "dnssec" },
    ],
  },
  {
    label: "DHCP",
    items: [
      { title: "Étendues", path: "/dhcp/scopes", icon: Network, keywords: ["scopes", "plages"] },
      { title: "Baux", path: "/dhcp/leases", icon: Timer, keywords: ["leases", "clients"] },
      { title: "Réservations", path: "/dhcp/reservations", icon: BookmarkCheck, keywords: ["IP fixe", "MAC"] },
    ],
  },
  {
    label: "Système",
    items: [
      { title: "Cluster", path: "/cluster", icon: Server, keywords: ["HA", "haute disponibilité", "témoin"] },
      { title: "Journaux", path: "/logs", icon: ScrollText, keywords: ["audit", "logs"] },
      { title: "Utilisateurs", path: "/users", icon: Users, adminOnly: true, keywords: ["comptes"] },
      { title: "Paramètres", path: "/settings", icon: Settings, adminOnly: true, keywords: ["sécurité", "HTTPS", "certificat"] },
    ],
  },
]

export function isVisible(item: NavItem, role: Role | undefined) {
  if (item.module && !modules[item.module]) return false
  if (item.adminOnly && !can(role, "admin")) return false
  return true
}

export function visibleGroups(role: Role | undefined): NavGroup[] {
  return navGroups
    .map((g) => ({ ...g, items: g.items.filter((i) => isVisible(i, role)) }))
    .filter((g) => g.items.length > 0)
}

/** Nav item of a path: exact match, else the deepest parent (e.g. /dns/zones/42 -> Zones DNS). */
export function findNavItem(path: string): NavItem | undefined {
  let best: NavItem | undefined
  for (const g of navGroups)
    for (const i of g.items) {
      if (i.path === path) return i
      if (i.path !== "/" && path.startsWith(i.path + "/") && (!best || i.path.length > best.path.length)) best = i
    }
  return best
}
