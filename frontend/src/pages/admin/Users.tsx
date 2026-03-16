import { useState } from 'react'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import {
  Table, TableBody, TableCell, TableHead, TableHeader, TableRow,
} from '@/components/ui/table'
import { UserPlus } from 'lucide-react'
import { useUsers } from '@/hooks/useUsers'
import { useTracePanel } from '@/lib/trace-panel-context'
import { useActionCooldown } from '@/hooks/useActionCooldown'
import { useToast } from '@/hooks/useToast'
import { ToastStack } from '@/components/ui/ToastStack'
import { cn } from '@/lib/utils'

const ROLE_COLORS: Record<string, string> = {
  admin: 'bg-red-100 text-red-700 dark:bg-red-900/30 dark:text-red-300',
  operator: 'bg-blue-100 text-blue-700 dark:bg-blue-900/30 dark:text-blue-300',
  requester: 'bg-gray-100 text-gray-700 dark:bg-gray-900/30 dark:text-gray-300',
}

export default function Users() {
  const [roleFilter, setRoleFilter] = useState<string>('all')
  const { data: USERS = [] } = useUsers()
  const active = USERS.filter(u => u.status === 'active').length
  const filteredUsers = roleFilter === 'all' ? USERS : USERS.filter(u => u.role === roleFilter)
  const { openTimeline } = useTracePanel()
  const inviteCooldown = useActionCooldown({ key: 'invite-user', cooldownMs: 5_000 })
  const { toasts, toast, dismiss } = useToast()

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-xl font-semibold">User Management</h1>
          <p className="text-sm text-muted-foreground mt-0.5">{active} active users · {USERS.length} total</p>
        </div>
        <Button
          size="sm"
          variant="outline"
          className="text-xs gap-1.5"
          disabled={!inviteCooldown.canFire}
          onClick={() => {
            if (!inviteCooldown.canFire) return
            const now = new Date()
            openTimeline('Invite User', [
              {
                span_id: 'span-invite-1',
                name: 'Validating email format',
                type: 'tool',
                start_time: now.toISOString(),
                end_time: new Date(now.getTime() + 200).toISOString(),
                duration_ms: 200,
                status: 'ok',
                attributes: { step: 'validate-email' },
                events: [],
                data: {},
              },
              {
                span_id: 'span-invite-2',
                name: 'Checking existing user',
                type: 'tool',
                start_time: new Date(now.getTime() + 200).toISOString(),
                end_time: new Date(now.getTime() + 500).toISOString(),
                duration_ms: 300,
                status: 'ok',
                attributes: { step: 'check-existing' },
                events: [],
                data: {},
              },
              {
                span_id: 'span-invite-3',
                name: 'Provisioning RBAC role',
                type: 'tool',
                start_time: new Date(now.getTime() + 500).toISOString(),
                end_time: new Date(now.getTime() + 1000).toISOString(),
                duration_ms: 500,
                status: 'ok',
                attributes: { step: 'provision-rbac' },
                events: [],
                data: {},
              },
              {
                span_id: 'span-invite-4',
                name: 'Sending invitation email',
                type: 'tool',
                start_time: new Date(now.getTime() + 1000).toISOString(),
                end_time: new Date(now.getTime() + 1400).toISOString(),
                duration_ms: 400,
                status: 'ok',
                attributes: { step: 'send-email' },
                events: [],
                data: {},
              },
            ])
            inviteCooldown.fire()
            setTimeout(() => toast('Invitation sent to user'), 1400)
          }}
        >
          <UserPlus className="h-3.5 w-3.5" />{!inviteCooldown.canFire ? 'Inviting\u2026' : 'Invite User'}
        </Button>
      </div>

      <div className="flex gap-3">
        <button
          onClick={() => setRoleFilter('all')}
          className={cn(
            'px-3 py-1.5 rounded-none text-xs font-medium transition-colors',
            roleFilter === 'all' ? 'bg-foreground text-background' : 'bg-muted text-muted-foreground hover:bg-muted/80',
          )}
        >
          All ({USERS.length})
        </button>
        {(['admin', 'operator', 'requester'] as const).map(role => (
          <button
            key={role}
            onClick={() => setRoleFilter(prev => prev === role ? 'all' : role)}
            className={cn(
              'px-3 py-1.5 rounded-none text-xs font-medium transition-colors',
              roleFilter === role ? 'bg-foreground text-background' : cn(ROLE_COLORS[role], 'hover:opacity-80'),
            )}
          >
            {role.charAt(0).toUpperCase() + role.slice(1)}: {USERS.filter(u => u.role === role).length}
          </button>
        ))}
      </div>

      <Card>
        <CardHeader className="pb-2">
          <CardTitle className="text-xs font-medium uppercase tracking-wide text-muted-foreground">All Users</CardTitle>
        </CardHeader>
        <CardContent className="p-0 overflow-x-auto">
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead className="text-xs pl-4">Name</TableHead>
                <TableHead className="text-xs">Email</TableHead>
                <TableHead className="text-xs">Role</TableHead>
                <TableHead className="text-xs">Team</TableHead>
                <TableHead className="text-xs hidden lg:table-cell">Last Login</TableHead>
                <TableHead className="text-xs">Status</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {filteredUsers.map(user => (
                <TableRow key={user.id} className="hover:bg-muted/30">
                  <TableCell className="pl-4">
                    <div className="flex items-center gap-2">
                      <div className="h-7 w-7 rounded-full bg-muted flex items-center justify-center text-[10px] font-bold text-muted-foreground shrink-0">
                        {user.name.split(' ').map(n => n[0]).join('').slice(0, 2)}
                      </div>
                      <span className="text-xs font-medium">{user.name}</span>
                    </div>
                  </TableCell>
                  <TableCell className="text-xs text-muted-foreground">{user.email}</TableCell>
                  <TableCell>
                    <Badge variant="secondary" className={cn('text-[10px]', ROLE_COLORS[user.role])}>
                      {user.role}
                    </Badge>
                  </TableCell>
                  <TableCell className="text-xs">{user.team}</TableCell>
                  <TableCell className="text-xs text-muted-foreground hidden lg:table-cell">{user.last_login}</TableCell>
                  <TableCell>
                    <span className={cn(
                      'text-[10px] font-medium px-2 py-0.5 rounded-full',
                      user.status === 'active'
                        ? 'bg-green-100 text-green-700 dark:bg-green-900/30 dark:text-green-300'
                        : 'bg-gray-100 text-gray-500 dark:bg-gray-900/30 dark:text-gray-400',
                    )}>
                      {user.status}
                    </span>
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </CardContent>
      </Card>

      <ToastStack toasts={toasts} onDismiss={dismiss} />
    </div>
  )
}
