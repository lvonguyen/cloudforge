import { Link } from 'react-router-dom'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { useAuth } from '@/lib/auth'
import { FileText, Clock, CheckCircle2, XCircle, Plus } from 'lucide-react'

const MY_REQUESTS = [
  { id: 'EXC-002', resource: 'EC2 m5.24xlarge in us-east-1', type: 'OVERSIZED_INSTANCE', status: 'PENDING', created: '2026-02-24' },
  { id: 'EXC-006', resource: 'S3 in ap-southeast-1', type: 'UNAPPROVED_REGION', status: 'APPROVED', created: '2026-02-18' },
  { id: 'EXC-007', resource: 'RDS db.r5.2xlarge', type: 'OVERSIZED_INSTANCE', status: 'REJECTED', created: '2026-02-10' },
]

const PENDING_APPROVALS = [
  { id: 'EXC-001', app: 'payments-api', resource: 'RDS in ap-southeast-3', requestor: 'priya@cloudforge.dev', since: '2h ago' },
  { id: 'EXC-004', app: 'auth-service', resource: 'SG port 22 open', requestor: 'jchen@cloudforge.dev', since: '4h ago' },
]

const STATUS_COLORS: Record<string, string> = {
  PENDING: 'bg-yellow-100 text-yellow-800',
  APPROVED: 'bg-green-100 text-green-800',
  REJECTED: 'bg-red-100 text-red-800',
}

const STATUS_ICONS: Record<string, typeof CheckCircle2> = {
  PENDING: Clock,
  APPROVED: CheckCircle2,
  REJECTED: XCircle,
}

export default function PortalDashboard() {
  const { user } = useAuth()

  const pending = MY_REQUESTS.filter(r => r.status === 'PENDING').length
  const approved = MY_REQUESTS.filter(r => r.status === 'APPROVED').length

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-xl font-semibold">My Dashboard</h1>
          <p className="text-sm text-muted-foreground mt-0.5">Welcome back, {user.name}</p>
        </div>
        <Link to="/portal/request">
          <Button size="sm" className="text-xs gap-1.5">
            <Plus className="h-3.5 w-3.5" />New Request
          </Button>
        </Link>
      </div>

      {/* Summary KPIs */}
      <div className="grid grid-cols-3 gap-4">
        <Card>
          <CardContent className="p-4">
            <div className="flex items-start gap-3">
              <FileText className="h-5 w-5 text-muted-foreground mt-0.5 shrink-0" />
              <div>
                <p className="text-2xl font-bold">{MY_REQUESTS.length}</p>
                <p className="text-xs text-muted-foreground">Total Requests</p>
              </div>
            </div>
          </CardContent>
        </Card>
        <Card>
          <CardContent className="p-4">
            <div className="flex items-start gap-3">
              <Clock className="h-5 w-5 text-yellow-600 mt-0.5 shrink-0" />
              <div>
                <p className="text-2xl font-bold text-yellow-600">{pending}</p>
                <p className="text-xs text-muted-foreground">Pending Approval</p>
              </div>
            </div>
          </CardContent>
        </Card>
        <Card>
          <CardContent className="p-4">
            <div className="flex items-start gap-3">
              <CheckCircle2 className="h-5 w-5 text-green-600 mt-0.5 shrink-0" />
              <div>
                <p className="text-2xl font-bold text-green-600">{approved}</p>
                <p className="text-xs text-muted-foreground">Approved</p>
              </div>
            </div>
          </CardContent>
        </Card>
      </div>

      {/* My recent requests */}
      <Card>
        <CardHeader className="pb-2">
          <div className="flex items-center justify-between">
            <CardTitle className="text-xs font-medium uppercase tracking-wide text-muted-foreground">My Recent Requests</CardTitle>
            <Link to="/portal/requests" className="text-xs text-primary hover:underline">View All →</Link>
          </div>
        </CardHeader>
        <CardContent className="space-y-3">
          {MY_REQUESTS.map(req => {
            const Icon = STATUS_ICONS[req.status] ?? Clock
            return (
              <Link key={req.id} to={`/portal/requests/${req.id}`} className="flex items-center gap-3 hover:bg-muted/30 rounded-md px-2 py-2 transition-colors">
                <Icon className={`h-4 w-4 shrink-0 ${req.status === 'APPROVED' ? 'text-green-600' : req.status === 'REJECTED' ? 'text-red-600' : 'text-yellow-600'}`} />
                <div className="flex-1 min-w-0">
                  <p className="text-xs font-medium">{req.resource}</p>
                  <p className="text-[10px] text-muted-foreground">{req.id} · {req.created}</p>
                </div>
                <div className="flex items-center gap-2 shrink-0">
                  <Badge variant="outline" className="text-[10px]">{req.type}</Badge>
                  <span className={`text-[10px] font-medium px-2 py-0.5 rounded-full ${STATUS_COLORS[req.status]}`}>{req.status}</span>
                </div>
              </Link>
            )
          })}
        </CardContent>
      </Card>

      {/* Pending approvals (if admin/operator) */}
      {user.role !== 'requester' && (
        <Card>
          <CardHeader className="pb-2">
            <div className="flex items-center justify-between">
              <CardTitle className="text-xs font-medium uppercase tracking-wide text-muted-foreground">
                Pending Approvals
                <Badge variant="outline" className="ml-2 text-[10px] bg-yellow-100 text-yellow-800">{PENDING_APPROVALS.length}</Badge>
              </CardTitle>
              <Link to="/ops/command-center" className="text-xs text-primary hover:underline">Ops Center →</Link>
            </div>
          </CardHeader>
          <CardContent className="space-y-2">
            {PENDING_APPROVALS.map(appr => (
              <div key={appr.id} className="flex items-center gap-3 text-sm">
                <Clock className="h-3.5 w-3.5 text-yellow-600 shrink-0" />
                <div className="flex-1 min-w-0">
                  <p className="text-xs font-medium">{appr.app}: {appr.resource}</p>
                  <p className="text-[10px] text-muted-foreground">{appr.requestor} · {appr.since}</p>
                </div>
                <span className="text-[10px] font-mono text-muted-foreground">{appr.id}</span>
              </div>
            ))}
          </CardContent>
        </Card>
      )}
    </div>
  )
}
