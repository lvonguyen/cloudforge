import { RoleSwitcher } from './RoleSwitcher'
import { ThemeToggle } from './ThemeToggle'
import { useAuth } from '@/lib/auth'
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuLabel,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from '@/components/ui/dropdown-menu'
import { Shield, Search, LogOut, User, Menu } from 'lucide-react'

export function TopNav({ onMenuClick }: { onMenuClick: () => void }) {
  const { user, logout } = useAuth()

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
      <div className="flex items-center gap-2 min-w-[160px]">
        <Shield className="h-6 w-6 text-primary" />
        <span className="font-semibold text-sm tracking-tight text-foreground">CloudForge</span>
      </div>

      {/* Search — command palette placeholder */}
      <div className="relative flex-1 max-w-sm">
        <button
          type="button"
          disabled
          aria-label="Search"
          className="flex w-full items-center gap-2 rounded-md border border-border bg-muted/50 px-3 h-8 text-sm text-muted-foreground cursor-not-allowed"
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
        <RoleSwitcher />

        <DropdownMenu>
          <DropdownMenuTrigger aria-label="User menu" className="flex items-center gap-2 rounded-full h-8 w-8 bg-primary text-primary-foreground text-xs font-semibold hover:opacity-90">
            <span className="w-full text-center">
              {user.name.split(' ').map(n => n[0]).join('')}
            </span>
          </DropdownMenuTrigger>
          <DropdownMenuContent align="end" className="w-48">
            <DropdownMenuLabel className="font-normal">
              <div className="flex flex-col gap-0.5">
                <p className="text-sm font-medium">{user.name}</p>
                <p className="text-xs text-muted-foreground">{user.email}</p>
              </div>
            </DropdownMenuLabel>
            <DropdownMenuSeparator />
            <DropdownMenuItem className="text-sm gap-2">
              <User className="h-4 w-4" /> Profile
            </DropdownMenuItem>
            <DropdownMenuSeparator />
            <DropdownMenuItem onClick={logout} className="text-sm gap-2 text-destructive">
              <LogOut className="h-4 w-4" /> Log out
            </DropdownMenuItem>
          </DropdownMenuContent>
        </DropdownMenu>
      </div>
    </header>
  )
}
