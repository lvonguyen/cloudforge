import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import {
  Table, TableBody, TableCell, TableHead, TableHeader, TableRow,
} from '@/components/ui/table'
import { UserPlus } from 'lucide-react'

interface UserRow {
  id: string
  name: string
  email: string
  role: 'admin' | 'operator' | 'requester'
  team: string
  last_login: string
  status: 'active' | 'inactive'
}

const USERS: UserRow[] = [
  { id: 'u-001', name: 'Admin One', email: 'admin1@contoso.dev', role: 'admin', team: 'Platform Security', last_login: '2026-02-26 09:14', status: 'active' },
  { id: 'u-002', name: 'Operator One', email: 'operator1@contoso.dev', role: 'operator', team: 'Cloud Ops', last_login: '2026-02-26 08:52', status: 'active' },
  { id: 'u-003', name: 'Operator Two', email: 'operator2@contoso.dev', role: 'operator', team: 'Cloud Ops', last_login: '2026-02-25 17:30', status: 'active' },
  { id: 'u-004', name: 'User One', email: 'user1@contoso.dev', role: 'requester', team: 'Data Platform', last_login: '2026-02-24 14:05', status: 'active' },
  { id: 'u-005', name: 'User Two', email: 'user2@contoso.dev', role: 'requester', team: 'Payments', last_login: '2026-02-20 11:42', status: 'inactive' },
]

const ROLE_COLORS: Record<string, string> = {
  admin: 'bg-red-100 text-red-700 dark:bg-red-900/30 dark:text-red-300',
  operator: 'bg-blue-100 text-blue-700 dark:bg-blue-900/30 dark:text-blue-300',
  requester: 'bg-gray-100 text-gray-700 dark:bg-gray-900/30 dark:text-gray-300',
}

export default function Users() {
  const active = USERS.filter(u => u.status === 'active').length

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-xl font-semibold">User Management</h1>
          <p className="text-sm text-muted-foreground mt-0.5">{active} active users · {USERS.length} total</p>
        </div>
        <Button size="sm" variant="outline" className="text-xs gap-1.5">
          <UserPlus className="h-3.5 w-3.5" />Invite User
        </Button>
      </div>

      {/* Role summary */}
      <div className="flex gap-3">
        {(['admin', 'operator', 'requester'] as const).map(role => (
          <div key={role} className={`px-3 py-1.5 rounded-none text-xs font-medium ${ROLE_COLORS[role]}`}>
            {role.charAt(0).toUpperCase() + role.slice(1)}: {USERS.filter(u => u.role === role).length}
          </div>
        ))}
      </div>

      <Card>
        <CardHeader className="pb-2">
          <CardTitle className="text-xs font-medium uppercase tracking-wide text-muted-foreground">All Users</CardTitle>
        </CardHeader>
        <CardContent className="p-0">
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead className="text-xs pl-4">Name</TableHead>
                <TableHead className="text-xs">Email</TableHead>
                <TableHead className="text-xs">Role</TableHead>
                <TableHead className="text-xs">Team</TableHead>
                <TableHead className="text-xs">Last Login</TableHead>
                <TableHead className="text-xs">Status</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {USERS.map(user => (
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
                    <Badge variant="secondary" className={`text-[10px] ${ROLE_COLORS[user.role]}`}>
                      {user.role}
                    </Badge>
                  </TableCell>
                  <TableCell className="text-xs">{user.team}</TableCell>
                  <TableCell className="text-xs text-muted-foreground">{user.last_login}</TableCell>
                  <TableCell>
                    <span className={`text-[10px] font-medium px-2 py-0.5 rounded-full ${user.status === 'active' ? 'bg-green-100 text-green-700 dark:bg-green-900/30 dark:text-green-300' : 'bg-gray-100 text-gray-500 dark:bg-gray-900/30 dark:text-gray-400'}`}>
                      {user.status}
                    </span>
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </CardContent>
      </Card>
    </div>
  )
}
