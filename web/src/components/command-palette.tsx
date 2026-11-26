import * as React from "react"
import { useNavigate } from "react-router"
import { useMutation, useQuery } from "@tanstack/react-query"
import {
  ArrowLeftRight,
  BookmarkPlus,
  Download,
  Eraser,
  Forward,
  Globe,
  LogOut,
  Monitor,
  Moon,
  Network,
  Plus,
  RefreshCw,
  SearchCheck,
  SlidersHorizontal,
  Sun,
  Tag,
  TextSearch,
  UserRound,
} from "lucide-react"
import { toast } from "sonner"
import { api } from "@/api/client"
import { scopesQuery, zonesQuery } from "@/api/queries"
import {
  CommandDialog,
  CommandEmpty,
  CommandGroup,
  CommandInput,
  CommandItem,
  CommandList,
  CommandSeparator,
} from "@/components/ui/command"
import { usePermissions } from "@/hooks/use-cluster"
import { useCurrentUser, useLogout } from "@/hooks/use-session"
import { visibleGroups } from "@/lib/nav"
import { useTheme } from "@/lib/theme"
import { useDnsLookup } from "./dns-lookup"

// Predictable matching: every typed word must start a word of the item
// (case and accent insensitive). Title matches rank above keyword matches.
const norm = (s: string) => s.normalize("NFD").replace(/\p{Diacritic}/gu, "").toLowerCase()
function paletteFilter(value: string, search: string, keywords?: string[]) {
  const terms = norm(search).split(/\s+/).filter(Boolean)
  if (terms.length === 0) return 1
  const words = (text: string) => norm(text).split(/[\s'’.-]+/)
  const title = words(value)
  const all = title.concat(words((keywords ?? []).join(" ")))
  if (!terms.every((t) => all.some((w) => w.startsWith(t)))) return 0
  return terms.every((t) => title.some((w) => w.startsWith(t))) ? 1 : 0.5
}

type Ctx = { open: boolean; setOpen: (o: boolean) => void }
const CommandPaletteContext = React.createContext<Ctx>({ open: false, setOpen: () => {} })
export const useCommandPalette = () => React.useContext(CommandPaletteContext)

export function CommandPaletteProvider({ children }: { children: React.ReactNode }) {
  const [open, setOpen] = React.useState(false)

  React.useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if (e.key.toLowerCase() === "k" && (e.metaKey || e.ctrlKey)) {
        e.preventDefault()
        setOpen((o) => !o)
      }
    }
    window.addEventListener("keydown", onKey)
    return () => window.removeEventListener("keydown", onKey)
  }, [])

  return (
    <CommandPaletteContext.Provider value={{ open, setOpen }}>
      {children}
      <CommandPalette open={open} setOpen={setOpen} />
    </CommandPaletteContext.Provider>
  )
}

function CommandPalette({ open, setOpen }: Ctx) {
  const navigate = useNavigate()
  const user = useCurrentUser()
  const logout = useLogout()
  const { setTheme } = useTheme()
  const groups = visibleGroups(user?.role)
  const { openLookup } = useDnsLookup()
  // Role AND node writability: config actions disappear on a cluster secondary.
  const { can, allowed, view: cluster } = usePermissions()
  // Zones are listed for quick jumps; fetched only while the palette is open.
  const zones = useQuery({ ...zonesQuery, enabled: open, staleTime: 30_000 })
  const scopes = useQuery({ ...scopesQuery, enabled: open, staleTime: 30_000, refetchInterval: false })
  const flush = useMutation({
    mutationFn: () => api.post("/dns/cache/flush", { body: {} }),
    onSuccess: (r) => toast.success(`Cache DNS vidé : ${r?.removed ?? 0} entrée(s) supprimée(s).`),
  })

  // Set when an action opens another dialog: the palette must not give the
  // focus back to the page when it closes, or it would steal it from that dialog.
  const keepFocus = React.useRef(false)
  const run = (fn: () => void, opensDialog = false) => {
    keepFocus.current = opensDialog
    setOpen(false)
    fn()
  }

  return (
    <CommandDialog
      open={open}
      onOpenChange={setOpen}
      filter={paletteFilter}
      onCloseAutoFocus={(e) => {
        if (keepFocus.current) e.preventDefault()
        keepFocus.current = false
      }}
    >
      <CommandInput placeholder="Chercher une page ou une action…" />
      <CommandList>
        <CommandEmpty>Aucun résultat.</CommandEmpty>
        {groups.map((g) => (
          <CommandGroup key={g.label} heading={g.label}>
            {g.items.map((item) => (
              <CommandItem
                key={item.path}
                value={item.title}
                keywords={[g.label, ...(item.keywords ?? [])]}
                onSelect={() => run(() => navigate(item.path))}
              >
                <item.icon /> {item.title}
              </CommandItem>
            ))}
          </CommandGroup>
        ))}
        {(zones.data?.items ?? []).length > 0 && (
          <CommandGroup heading="Zones DNS">
            {(zones.data?.items ?? []).map((z) => (
              <CommandItem
                key={z.id}
                value={`Zone ${z.name}`}
                keywords={["zone", "dns", "enregistrements"]}
                onSelect={() => run(() => navigate(`/dns/zones/${encodeURIComponent(z.id ?? "")}`))}
              >
                <Globe /> {z.name}
              </CommandItem>
            ))}
          </CommandGroup>
        )}
        {(scopes.data?.items ?? []).length > 0 && (
          <CommandGroup heading="Étendues DHCP">
            {(scopes.data?.items ?? []).map((sc) => (
              <CommandItem
                key={sc.id}
                value={`Étendue ${sc.name}`}
                keywords={["dhcp", "baux", "scope", sc.network ?? "", sc.vlanId != null ? `vlan ${sc.vlanId}` : ""]}
                onSelect={() => run(() => navigate(`/dhcp/leases?scope=${encodeURIComponent(sc.id ?? "")}`))}
              >
                <Network /> {sc.name}
                <span className="ml-auto font-mono text-xs text-muted-foreground">{sc.network}</span>
              </CommandItem>
            ))}
          </CommandGroup>
        )}
        <CommandSeparator />
        <CommandGroup heading="DHCP">
          <CommandItem
            value="Rechercher un bail"
            keywords={["lease", "client", "IP", "MAC", "trouver", "appareil"]}
            onSelect={() => run(() => navigate("/dhcp/leases?search=1"), true)}
          >
            <TextSearch /> Rechercher un bail
          </CommandItem>
          {can("config.write") && (
            <CommandItem value="Nouvelle étendue" keywords={["créer", "ajouter", "scope", "plage", "dhcp"]} onSelect={() => run(() => navigate("/dhcp/scopes?new=1"), true)}>
              <Plus /> Nouvelle étendue
            </CommandItem>
          )}
          {can("leases.write") && (
            <CommandItem
              value="Nouvelle réservation"
              keywords={["créer", "ajouter", "IP fixe", "MAC", "dhcp"]}
              onSelect={() => run(() => navigate("/dhcp/reservations?new=1"), true)}
            >
              <BookmarkPlus /> Nouvelle réservation
            </CommandItem>
          )}
          {can("config.write") && (
            <CommandItem value="Nommer un VLAN" keywords={["vlan", "nom", "étiquette", "label"]} onSelect={() => run(() => navigate("/vlans?new=1"), true)}>
              <Tag /> Nommer un VLAN
            </CommandItem>
          )}
          {can("admin") && (
            <CommandItem
              value="Importer depuis Technitium"
              keywords={["import", "migration", "technitium", "zones", "redirecteurs"]}
              onSelect={() => run(() => navigate("/settings?tab=import"))}
            >
              <Download /> Importer depuis Technitium
            </CommandItem>
          )}
        </CommandGroup>
        <CommandSeparator />
        <CommandGroup heading="DNS">
          <CommandItem
            value="Tester une résolution DNS"
            keywords={["lookup", "dig", "nslookup", "résoudre", "nom"]}
            onSelect={() => run(() => openLookup(), true)}
          >
            <SearchCheck /> Tester une résolution DNS
          </CommandItem>
          {can("config.write") && (
            <CommandItem value="Nouvelle zone DNS" keywords={["créer", "ajouter", "domaine"]} onSelect={() => run(() => navigate("/dns/zones?new=1"), true)}>
              <Plus /> Nouvelle zone DNS
            </CommandItem>
          )}
          {can("config.write") && (
            <CommandItem
              value="Ajouter un redirecteur"
              keywords={["forwarder", "DoH", "DoT", "nouveau"]}
              onSelect={() => run(() => navigate("/dns/forwarders?new=1"), true)}
            >
              <Forward /> Ajouter un redirecteur
            </CommandItem>
          )}
          {can("cache.flush") && (
            <CommandItem value="Vider le cache DNS" keywords={["flush", "effacer"]} onSelect={() => run(() => flush.mutate())}>
              <Eraser /> Vider le cache DNS
            </CommandItem>
          )}
          {allowed("admin") && (
            <CommandItem
              value="Paramètres DNS"
              keywords={["cache", "TTL", "récursion", "écoute"]}
              onSelect={() => run(() => navigate("/settings?tab=dns"))}
            >
              <SlidersHorizontal /> Paramètres DNS
            </CommandItem>
          )}
        </CommandGroup>
        {cluster?.enabled && user?.role === "admin" && (
          <>
            <CommandSeparator />
            <CommandGroup heading="Haute disponibilité">
              <CommandItem
                value="Forcer la resynchro"
                keywords={["cluster", "HA", "synchro", "resync", "copier"]}
                onSelect={() => run(() => navigate("/cluster?confirm=resync"), true)}
              >
                <RefreshCw /> Forcer la resynchro
              </CommandItem>
              {cluster.role === "primary" && (
                <CommandItem
                  value="Rebasculer"
                  keywords={["cluster", "HA", "failback", "bascule", "primaire"]}
                  onSelect={() => run(() => navigate("/cluster?confirm=failback"), true)}
                >
                  <ArrowLeftRight /> Rebasculer vers l'autre nœud
                </CommandItem>
              )}
            </CommandGroup>
          </>
        )}
        <CommandSeparator />
        <CommandGroup heading="Actions">
          <CommandItem value="Mon compte" keywords={["profil", "passkey", "mot de passe", "jeton"]} onSelect={() => run(() => navigate("/account"))}>
            <UserRound /> Mon compte
          </CommandItem>
          <CommandItem value="Thème clair" keywords={["changer de thème", "light"]} onSelect={() => run(() => setTheme("light"))}>
            <Sun /> Changer de thème : clair
          </CommandItem>
          <CommandItem value="Thème sombre" keywords={["changer de thème", "dark"]} onSelect={() => run(() => setTheme("dark"))}>
            <Moon /> Changer de thème : sombre
          </CommandItem>
          <CommandItem value="Thème système" keywords={["changer de thème", "auto"]} onSelect={() => run(() => setTheme("system"))}>
            <Monitor /> Changer de thème : système
          </CommandItem>
          <CommandItem value="Se déconnecter" keywords={["logout", "quitter"]} onSelect={() => run(() => void logout())}>
            <LogOut /> Se déconnecter
          </CommandItem>
        </CommandGroup>
      </CommandList>
    </CommandDialog>
  )
}
