import { useState } from 'react'
import { NavLink, useLocation } from 'react-router-dom'
import { useAuth, type Role } from '@/lib/auth'
import { cn } from '@/lib/utils'
import { Button } from '@/components/ui/button'
import { Separator } from '@/components/ui/separator'
import {
  LayoutDashboard, FileText, Bot, Users, ClipboardList, Settings,
  Activity, AlertTriangle, Wrench, DollarSign, Shield, GitBranch,
  Home, PlusCircle, List, Package,
  ChevronLeft, ChevronRight, X, type LucideIcon,
} from 'lucide-react'

interface NavItem {
  to: string
  label: string
  icon: LucideIcon
}

const PLATFORM_ITEM: NavItem = { to: '/', label: 'Platform', icon: Home }

const NAV_BY_ROLE: Record<Role, { section: string; items: NavItem[] }[]> = {
  admin: [
    {
      section: 'Platform',
      items: [
        { to: '/admin', label: 'Dashboard', icon: LayoutDashboard },
        { to: '/admin/policies', label: 'Policies', icon: FileText },
        { to: '/admin/ai-agents', label: 'AI Agents', icon: Bot },
      ],
    },
    {
      section: 'Management',
      items: [
        { to: '/admin/users', label: 'Users', icon: Users },
        { to: '/admin/audit-log', label: 'Audit Log', icon: ClipboardList },
        { to: '/admin/system', label: 'System', icon: Settings },
      ],
    },
  ],
  operator: [
    {
      section: 'Operations',
      items: [
        { to: '/ops', label: 'Command Center', icon: Activity },
        { to: '/ops/findings', label: 'Findings', icon: AlertTriangle },
        { to: '/ops/remediation', label: 'Remediation', icon: Wrench },
      ],
    },
    {
      section: 'Intelligence',
      items: [
        { to: '/ops/costs', label: 'Spend', icon: DollarSign },
        { to: '/ops/compliance', label: 'Compliance', icon: Shield },
        { to: '/ops/attack-paths', label: 'Attack Paths', icon: GitBranch },
      ],
    },
  ],
  requester: [
    {
      section: 'Self-Service',
      items: [
        { to: '/portal', label: 'My Dashboard', icon: Home },
        { to: '/portal/request', label: 'New Request', icon: PlusCircle },
        { to: '/portal/requests', label: 'My Requests', icon: List },
        { to: '/portal/catalog', label: 'Catalog', icon: Package },
      ],
    },
  ],
  viewer: [],
}

function NavContent({ collapsed }: { collapsed: boolean }) {
  const { role } = useAuth()
  const location = useLocation()
  const sections = NAV_BY_ROLE[role]

  const platformActive = location.pathname === '/'

  return (
    <>
      <ul className="mb-3">
        <li>
          <NavLink
            to="/"
            end
            className={cn(
              'flex items-center gap-2.5 rounded-none px-2 py-1.5 text-sm transition-colors',
              platformActive
                ? 'bg-sidebar-accent text-sidebar-accent-foreground font-medium'
                : 'text-sidebar-foreground hover:bg-sidebar-accent/50'
            )}
            title={collapsed ? PLATFORM_ITEM.label : undefined}
          >
            <Home className="h-4 w-4 shrink-0" />
            {!collapsed && <span>{PLATFORM_ITEM.label}</span>}
          </NavLink>
        </li>
      </ul>
      <Separator className="mb-3" />
      {sections.map((section, si) => (
        <div key={section.section} className={cn(si > 0 && 'mt-4')}>
          {!collapsed && (
            <p className="mb-1 px-2 text-[10px] font-semibold uppercase tracking-widest text-muted-foreground">
              {section.section}
            </p>
          )}
          {si > 0 && collapsed && <Separator className="my-2" />}
          <ul className="space-y-0.5">
            {section.items.map(item => {
              const Icon = item.icon
              const active = location.pathname === item.to ||
                (item.to !== '/' && item.to !== '/admin' && item.to !== '/ops' && item.to !== '/portal' &&
                  location.pathname.startsWith(item.to))
              return (
                <li key={item.to}>
                  <NavLink
                    to={item.to}
                    end={item.to === '/admin' || item.to === '/ops' || item.to === '/portal'}
                    className={cn(
                      'flex items-center gap-2.5 rounded-none px-2 py-1.5 text-sm transition-colors',
                      active
                        ? 'bg-sidebar-accent text-sidebar-accent-foreground font-medium'
                        : 'text-sidebar-foreground hover:bg-sidebar-accent/50'
                    )}
                    title={collapsed ? item.label : undefined}
                  >
                    <Icon className="h-4 w-4 shrink-0" />
                    {!collapsed && <span>{item.label}</span>}
                  </NavLink>
                </li>
              )
            })}
          </ul>
        </div>
      ))}
    </>
  )
}

export function Sidebar({ mobileOpen, onMobileClose }: { mobileOpen: boolean; onMobileClose: () => void }) {
  const [collapsed, setCollapsed] = useState(false)

  return (
    <>
      {/* Desktop sidebar */}
      <aside
        className={cn(
          'relative hidden md:flex flex-col border-r border-border bg-sidebar-background transition-all duration-200',
          collapsed ? 'w-14' : 'w-48'
        )}
      >
        <nav className="flex-1 overflow-y-auto py-4 px-2">
          <NavContent collapsed={collapsed} />
        </nav>

        <Button
          variant="ghost"
          size="icon"
          className="absolute -right-3 top-6 h-6 w-6 rounded-full border border-border bg-background shadow-sm"
          onClick={() => setCollapsed(c => !c)}
          aria-label={collapsed ? "Expand sidebar" : "Collapse sidebar"}
          aria-expanded={!collapsed}
        >
          {collapsed ? <ChevronRight className="h-3 w-3" /> : <ChevronLeft className="h-3 w-3" />}
        </Button>
      </aside>

      {/* Mobile sidebar overlay */}
      {mobileOpen && (
        <div className="fixed inset-0 z-50 md:hidden">
          <div className="absolute inset-0 bg-black/40" onClick={onMobileClose} />
          <aside className="absolute left-0 top-0 h-full w-64 bg-sidebar-background border-r border-border shadow-lg">
            <div className="flex items-center justify-between px-4 py-3 border-b border-border">
              <span className="text-sm font-semibold text-sidebar-foreground">Navigation</span>
              <button onClick={onMobileClose} aria-label="Close menu" className="text-muted-foreground hover:text-foreground">
                <X className="h-4 w-4" />
              </button>
            </div>
            <nav className="overflow-y-auto py-4 px-2">
              <NavContent collapsed={false} />
            </nav>
          </aside>
        </div>
      )}
    </>
  )
}
