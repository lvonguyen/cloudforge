import { useState, useEffect } from 'react'
import { RoleSwitcher } from './RoleSwitcher'
import { ThemeToggle } from './ThemeToggle'
import { CommandPalette } from './CommandPalette'
import { useAuth } from '@/lib/auth'
import { useTerminalPanel } from '@/lib/terminal-context'
import { branding } from '@/lib/branding'
import { Button } from '@/components/ui/button'
import { cn } from '@/lib/utils'
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuLabel,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from '@/components/ui/dropdown-menu'
import { useNavigate } from 'react-router-dom'
import { Search, LogOut, User, Menu, TerminalSquare } from 'lucide-react'

const isDemo = import.meta.env.DEV || import.meta.env.VITE_DEMO_MODE === 'true'
const ROLE_STYLES: Record<string, string> = {
  admin: 'bg-emerald-600 text-white',
  operator: 'bg-orange-500 text-white',
  requester: 'bg-teal-500 text-white',
}
function avatarStyle(role: string): string {
  return isDemo ? (ROLE_STYLES[role] ?? 'bg-muted text-muted-foreground') : 'bg-foreground text-background'
}
function avatarLabel(user: { name: string; role: string }): string {
  if (isDemo) return user.role === 'admin' ? 'A' : user.role === 'operator' ? 'O' : user.role === 'requester' ? 'R' : 'V'
  return user.name ? user.name.split(' ').map(n => n[0]).join('') : '?'
}

export function TopNav({ onMenuClick }: { onMenuClick: () => void }) {
  const { user, logout } = useAuth()
  const terminalPanel = useTerminalPanel()
  const navigate = useNavigate()
  const [cmdOpen, setCmdOpen] = useState(false)
  const canAccessTerminal = user.role === 'operator' || user.role === 'admin'

  useEffect(() => {
    function handleKeyDown(e: KeyboardEvent) {
      if ((e.metaKey || e.ctrlKey) && e.key === 'k') {
        e.preventDefault()
        setCmdOpen(true)
      }
    }
    document.addEventListener('keydown', handleKeyDown)
    return () => document.removeEventListener('keydown', handleKeyDown)
  }, [])

  return (
    <header className="sticky top-0 z-40 flex h-14 items-center gap-4 border-b border-border bg-background px-6">
      {/* Mobile hamburger */}
      <button
        type="button"
        onClick={onMenuClick}
        aria-label="Open menu"
        className="md:hidden flex items-center justify-center h-8 w-8 text-muted-foreground hover:text-foreground transition-colors"
      >
        <Menu className="h-5 w-5" />
      </button>

      {/* Logo */}
      <div className="flex items-center gap-2.5 min-w-[180px]">
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5" className="h-7 w-7 text-primary">
          <path d="M12 2L3 7v5c0 5.55 3.84 10.74 9 12 5.16-1.26 9-6.45 9-12V7l-9-5z" />
          <circle cx="12" cy="12" r="3" />
          <path d="M12 7v2M12 15v2M7 12h2M15 12h2" />
        </svg>
        <span className="font-semibold text-base tracking-tight text-foreground">{branding.productName}</span>
      </div>

      {/* Search — opens command palette */}
      <div className="relative flex-1 max-w-sm">
        <button
          type="button"
          onClick={() => setCmdOpen(true)}
          aria-label="Search"
          className="flex w-full items-center gap-2 rounded-md border border-border bg-muted/50 px-3 h-8 text-sm text-muted-foreground hover:bg-muted transition-colors"
        >
          <Search className="h-4 w-4 shrink-0" />
          <span className="flex-1 text-left">Search...</span>
          <kbd className="pointer-events-none hidden sm:inline-flex h-5 items-center gap-0.5 rounded border border-border bg-background px-1.5 font-mono text-[10px] font-medium text-muted-foreground">
            ⌘K
          </kbd>
        </button>
      </div>

      {/* Right side */}
      <div className="ml-auto flex items-center gap-3">
        <ThemeToggle />
        {canAccessTerminal && (
          <Button
            type="button"
            variant="ghost"
            size="icon-sm"
            onClick={terminalPanel.toggle}
            aria-label={terminalPanel.state.isOpen ? 'Hide terminal panel' : 'Show terminal panel'}
            title="Cloud terminal"
            className={cn(
              'border border-transparent text-muted-foreground transition-colors',
              terminalPanel.state.isOpen
                ? 'border-border bg-accent text-accent-foreground'
                : 'hover:border-border/60 hover:text-foreground',
            )}
          >
            <TerminalSquare className="h-4 w-4" />
          </Button>
        )}
        {(import.meta.env.DEV || import.meta.env.VITE_DEMO_MODE === 'true') && <RoleSwitcher />}

        <DropdownMenu>
          <DropdownMenuTrigger aria-label="User menu" className={`flex items-center gap-2 rounded-full h-8 w-8 text-xs font-semibold hover:opacity-90 ${avatarStyle(user.role)}`}>
            <span className="w-full text-center">{avatarLabel(user)}</span>
          </DropdownMenuTrigger>
          <DropdownMenuContent align="end" className="w-48">
            <DropdownMenuLabel className="font-normal">
              <div className="flex flex-col gap-0.5">
                <p className="text-sm font-medium">{user.name}</p>
                <p className="text-xs text-muted-foreground">{user.email}</p>
              </div>
            </DropdownMenuLabel>
            <DropdownMenuSeparator />
            <DropdownMenuItem onClick={() => navigate('/profile')} className="text-sm gap-2">
              <User className="h-4 w-4" /> Profile
            </DropdownMenuItem>
            <DropdownMenuSeparator />
            <DropdownMenuItem onClick={logout} className="text-sm gap-2 text-destructive">
              <LogOut className="h-4 w-4" /> Log out
            </DropdownMenuItem>
          </DropdownMenuContent>
        </DropdownMenu>
      </div>

      <CommandPalette open={cmdOpen} onOpenChange={setCmdOpen} />
    </header>
  )
}
