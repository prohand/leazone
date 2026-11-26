import { NavLink, useLocation, useNavigate } from "react-router"
import { ChevronsUpDown, LogOut, Monitor, Moon, Sun, UserRound } from "lucide-react"
import type { Role } from "@/api/types"
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuLabel,
  DropdownMenuRadioGroup,
  DropdownMenuRadioItem,
  DropdownMenuSeparator,
  DropdownMenuSub,
  DropdownMenuSubContent,
  DropdownMenuSubTrigger,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu"
import {
  Sidebar,
  SidebarContent,
  SidebarFooter,
  SidebarGroup,
  SidebarGroupLabel,
  SidebarHeader,
  SidebarMenu,
  SidebarMenuButton,
  SidebarMenuItem,
  useSidebar,
} from "@/components/ui/sidebar"
import { useCurrentUser, useLogout } from "@/hooks/use-session"
import { useModules } from "@/lib/modules"
import { visibleGroups } from "@/lib/nav"
import { roleLabel } from "@/lib/permissions"
import { useTheme, type Theme } from "@/lib/theme"
import { LogoMark } from "./logo"

function isActive(current: string, path: string) {
  return path === "/" ? current === "/" : current === path || current.startsWith(path + "/")
}

export function AppSidebar() {
  const user = useCurrentUser()
  const location = useLocation()
  const { setOpenMobile, isMobile } = useSidebar()
  const modules = useModules()
  const groups = visibleGroups(user?.role, modules)
  const closeOnMobile = () => isMobile && setOpenMobile(false)

  return (
    <Sidebar collapsible="icon">
      <SidebarHeader>
        <SidebarMenu>
          <SidebarMenuItem>
            <SidebarMenuButton size="lg" asChild>
              <NavLink to="/" onClick={closeOnMobile}>
                <div className="flex aspect-square size-8 items-center justify-center">
                  <LogoMark className="size-7" />
                </div>
                <span className="text-base font-semibold tracking-tight">Leazone</span>
              </NavLink>
            </SidebarMenuButton>
          </SidebarMenuItem>
        </SidebarMenu>
      </SidebarHeader>
      <SidebarContent>
        {groups.map((g) => (
          <SidebarGroup key={g.label}>
            <SidebarGroupLabel>{g.label}</SidebarGroupLabel>
            <SidebarMenu>
              {g.items.map((item) => (
                <SidebarMenuItem key={item.path}>
                  <SidebarMenuButton asChild isActive={isActive(location.pathname, item.path)} tooltip={item.title}>
                    <NavLink to={item.path} onClick={closeOnMobile}>
                      <item.icon />
                      <span>{item.title}</span>
                    </NavLink>
                  </SidebarMenuButton>
                </SidebarMenuItem>
              ))}
            </SidebarMenu>
          </SidebarGroup>
        ))}
      </SidebarContent>
      <SidebarFooter>
        <AccountMenu username={user?.username ?? ""} role={user?.role} onNavigate={closeOnMobile} />
      </SidebarFooter>
    </Sidebar>
  )
}

function AccountMenu({ username, role, onNavigate }: { username: string; role?: Role; onNavigate: () => void }) {
  const navigate = useNavigate()
  const logout = useLogout()
  const { theme, setTheme } = useTheme()
  const { isMobile } = useSidebar()
  const initials = username.slice(0, 2).toUpperCase()

  return (
    <SidebarMenu>
      <SidebarMenuItem>
        <DropdownMenu>
          <DropdownMenuTrigger asChild>
            <SidebarMenuButton size="lg" className="data-[state=open]:bg-sidebar-accent">
              <div className="flex size-8 shrink-0 items-center justify-center rounded-md border bg-background text-xs font-medium">
                {initials}
              </div>
              <div className="grid flex-1 text-left text-sm leading-tight">
                <span className="truncate font-medium">{username}</span>
                <span className="truncate text-xs text-muted-foreground">{role ? roleLabel[role] : ""}</span>
              </div>
              <ChevronsUpDown className="ml-auto size-4" />
            </SidebarMenuButton>
          </DropdownMenuTrigger>
          <DropdownMenuContent side={isMobile ? "top" : "right"} align="end" className="w-56">
            <DropdownMenuLabel className="font-normal">
              <div className="text-sm font-medium">{username}</div>
              <div className="text-xs text-muted-foreground">{role ? roleLabel[role] : ""}</div>
            </DropdownMenuLabel>
            <DropdownMenuSeparator />
            <DropdownMenuItem
              onSelect={() => {
                onNavigate()
                navigate("/account")
              }}
            >
              <UserRound /> Mon compte
            </DropdownMenuItem>
            <DropdownMenuSub>
              <DropdownMenuSubTrigger>
                <Sun /> Thème
              </DropdownMenuSubTrigger>
              <DropdownMenuSubContent>
                <DropdownMenuRadioGroup value={theme} onValueChange={(v) => setTheme(v as Theme)}>
                  <DropdownMenuRadioItem value="light">
                    <Sun /> Clair
                  </DropdownMenuRadioItem>
                  <DropdownMenuRadioItem value="dark">
                    <Moon /> Sombre
                  </DropdownMenuRadioItem>
                  <DropdownMenuRadioItem value="system">
                    <Monitor /> Système
                  </DropdownMenuRadioItem>
                </DropdownMenuRadioGroup>
              </DropdownMenuSubContent>
            </DropdownMenuSub>
            <DropdownMenuSeparator />
            <DropdownMenuItem onSelect={() => void logout()}>
              <LogOut /> Se déconnecter
            </DropdownMenuItem>
          </DropdownMenuContent>
        </DropdownMenu>
      </SidebarMenuItem>
    </SidebarMenu>
  )
}
