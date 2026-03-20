import { useNavigate } from 'react-router-dom'
import { useAuth, type Role } from '@/lib/auth'
import { Badge } from '@/components/ui/badge'
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuLabel,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from '@/components/ui/dropdown-menu'
import { ChevronDown, Eye, ShieldCheck, Terminal, UserCircle } from 'lucide-react'

const ROLES: { value: Role; label: string; icon: React.ReactNode; color: string }[] = [
  { value: 'admin', label: 'Admin', icon: <ShieldCheck className="h-4 w-4" />, color: 'bg-purple-100 text-purple-800 dark:bg-purple-900/30 dark:text-purple-300' },
  { value: 'operator', label: 'Operator', icon: <Terminal className="h-4 w-4" />, color: 'bg-blue-100 text-blue-800 dark:bg-blue-900/30 dark:text-blue-300' },
  { value: 'requester', label: 'Requester', icon: <UserCircle className="h-4 w-4" />, color: 'bg-green-100 text-green-800 dark:bg-green-900/30 dark:text-green-300' },
  { value: 'viewer', label: 'Viewer', icon: <Eye className="h-4 w-4" />, color: 'bg-gray-100 text-gray-800 dark:bg-gray-900/30 dark:text-gray-300' },
]

const ROLE_HOME: Record<Role, string> = {
  admin: '/admin',
  operator: '/ops',
  requester: '/portal',
  viewer: '/ops/findings',
}

export function RoleSwitcher() {
  const navigate = useNavigate()
  const { role, setRole } = useAuth()
  const current = ROLES.find(r => r.value === role) ?? ROLES[0]

  return (
    <DropdownMenu>
      <DropdownMenuTrigger className="flex items-center gap-1.5 rounded-none border border-border px-2 py-1 text-xs text-foreground hover:bg-accent">
        {current.icon}
        <span className="font-medium">{current.label}</span>
        <ChevronDown className="h-3 w-3 opacity-60" />
      </DropdownMenuTrigger>
      <DropdownMenuContent align="end" className="w-44">
        <DropdownMenuLabel className="text-xs text-muted-foreground">Switch Role</DropdownMenuLabel>
        <DropdownMenuSeparator />
        {ROLES.map(r => (
          <DropdownMenuItem
            key={r.value}
            onClick={() => { setRole(r.value); navigate(ROLE_HOME[r.value]) }}
            className="flex items-center gap-2 text-sm"
          >
            {r.icon}
            <span>{r.label}</span>
            {role === r.value && (
              <Badge variant="secondary" className="ml-auto text-[10px] px-1 py-0">
                active
              </Badge>
            )}
          </DropdownMenuItem>
        ))}
      </DropdownMenuContent>
    </DropdownMenu>
  )
}
