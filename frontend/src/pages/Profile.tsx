import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
import { Badge } from '@/components/ui/badge'
import { useAuth } from '@/lib/auth'
import { branding } from '@/lib/branding'
import { User, Shield, Key, Clock, Monitor, LogOut } from 'lucide-react'
import { Button } from '@/components/ui/button'

const ROLE_BADGE: Record<string, string> = {
  admin: 'bg-emerald-100 text-emerald-700 dark:bg-emerald-900/30 dark:text-emerald-300',
  operator: 'bg-orange-100 text-orange-700 dark:bg-orange-900/30 dark:text-orange-300',
  requester: 'bg-teal-100 text-teal-700 dark:bg-teal-900/30 dark:text-teal-300',
  viewer: 'bg-gray-100 text-gray-700 dark:bg-gray-900/30 dark:text-gray-300',
}

const DEMO_ENTITLEMENTS: Record<string, string[]> = {
  admin: ['Platform Settings', 'User Management', 'Policy Editor', 'Audit Log', 'Webhooks', 'Secrets Scan', 'All Ops Modules'],
  operator: ['Command Center', 'Findings', 'Remediation', 'Terminal', 'Spend', 'Compliance', 'Threat Intel', 'Attack Paths'],
  requester: ['Self-Service Dashboard', 'New Request', 'My Requests', 'Service Catalog'],
  viewer: ['All Modules (Read-Only)'],
}

const DEMO_ACTIVITY = [
  { action: 'Viewed findings dashboard', time: '2 minutes ago', icon: Monitor },
  { action: 'Switched role to Admin', time: '5 minutes ago', icon: Shield },
  { action: 'Authenticated via demo token', time: '12 minutes ago', icon: Key },
  { action: 'Session started', time: '15 minutes ago', icon: Clock },
]

export default function Profile() {
  const { user, logout } = useAuth()
  const isDemo = import.meta.env.DEV || import.meta.env.VITE_DEMO_MODE === 'true'

  return (
    <div className="space-y-6 max-w-4xl mx-auto">
      <h1 className="text-xl font-semibold tracking-tight">User Profile</h1>

      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        {/* Identity */}
        <Card>
          <CardHeader className="pb-3">
            <CardTitle className="text-sm flex items-center gap-2">
              <User className="h-4 w-4" /> Identity
            </CardTitle>
          </CardHeader>
          <CardContent className="space-y-3">
            <div className="flex items-center gap-3">
              <div className={`h-12 w-12 rounded-full flex items-center justify-center text-lg font-bold ${ROLE_BADGE[user.role] ?? 'bg-muted'}`}>
                {user.name?.split(' ').map(n => n[0]).join('') || '?'}
              </div>
              <div>
                <p className="text-sm font-medium">{user.name}</p>
                <p className="text-xs text-muted-foreground">{user.email}</p>
              </div>
            </div>
            <div className="flex items-center gap-2 pt-1">
              <span className="text-xs text-muted-foreground">Role:</span>
              <Badge className={ROLE_BADGE[user.role] ?? ''}>
                {user.role}
              </Badge>
            </div>
            {user.groups && user.groups.length > 0 && (
              <div className="flex items-center gap-2">
                <span className="text-xs text-muted-foreground">Groups:</span>
                <div className="flex flex-wrap gap-1">
                  {user.groups.map(g => (
                    <Badge key={g} variant="outline" className="text-[10px]">{g}</Badge>
                  ))}
                </div>
              </div>
            )}
            {isDemo && (
              <p className="text-[10px] text-muted-foreground pt-1 border-t">
                Demo session — role switching enabled for portfolio walkthrough
              </p>
            )}
          </CardContent>
        </Card>

        {/* Entitlements */}
        <Card>
          <CardHeader className="pb-3">
            <CardTitle className="text-sm flex items-center gap-2">
              <Key className="h-4 w-4" /> Entitlements
            </CardTitle>
          </CardHeader>
          <CardContent>
            <ul className="space-y-1.5">
              {(DEMO_ENTITLEMENTS[user.role] ?? DEMO_ENTITLEMENTS.viewer).map(e => (
                <li key={e} className="text-xs flex items-center gap-2">
                  <span className="h-1.5 w-1.5 rounded-full bg-green-500 shrink-0" />
                  {e}
                </li>
              ))}
            </ul>
          </CardContent>
        </Card>
      </div>

      {/* Session Info */}
      <Card>
        <CardHeader className="pb-3">
          <CardTitle className="text-sm flex items-center gap-2">
            <Clock className="h-4 w-4" /> Recent Activity
          </CardTitle>
        </CardHeader>
        <CardContent>
          <div className="space-y-2">
            {DEMO_ACTIVITY.map(({ action, time, icon: Icon }) => (
              <div key={action} className="flex items-center gap-3 text-xs">
                <Icon className="h-3.5 w-3.5 text-muted-foreground shrink-0" />
                <span className="flex-1">{action}</span>
                <span className="text-muted-foreground">{time}</span>
              </div>
            ))}
          </div>
        </CardContent>
      </Card>

      {/* Session Details */}
      <Card>
        <CardHeader className="pb-3">
          <CardTitle className="text-sm flex items-center gap-2">
            <Monitor className="h-4 w-4" /> Session
          </CardTitle>
        </CardHeader>
        <CardContent className="space-y-2 text-xs">
          <div className="flex justify-between">
            <span className="text-muted-foreground">Tenant</span>
            <span className="font-medium">{branding.companyName}</span>
          </div>
          <div className="flex justify-between">
            <span className="text-muted-foreground">Platform</span>
            <span className="font-medium">{branding.productName}</span>
          </div>
          <div className="flex justify-between">
            <span className="text-muted-foreground">Auth Method</span>
            <span className="font-medium">{isDemo ? 'Static JWT (Demo)' : 'OIDC / Okta SSO'}</span>
          </div>
          <div className="pt-3 border-t">
            <Button variant="destructive" size="sm" onClick={logout} className="gap-1.5">
              <LogOut className="h-3.5 w-3.5" /> Sign Out
            </Button>
          </div>
        </CardContent>
      </Card>
    </div>
  )
}
