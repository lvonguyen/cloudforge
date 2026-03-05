import { useState } from 'react'
import { Link } from 'react-router-dom'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import {
  Table, TableBody, TableCell, TableHead, TableHeader, TableRow,
} from '@/components/ui/table'
import { Plus, Clock, CheckCircle2, XCircle, AlertTriangle } from 'lucide-react'

interface RequestRow {
  id: string
  resource: string
  type: string
  provider: string
  status: 'PENDING' | 'APPROVED' | 'REJECTED' | 'EXPIRED'
  created: string
  updated: string
  approver?: string
  expiry?: string
}

const REQUESTS: RequestRow[] = [
  { id: 'EXC-002', resource: 'EC2 m5.24xlarge in us-east-1', type: 'OVERSIZED_INSTANCE', provider: 'aws', status: 'PENDING', created: '2026-02-24', updated: '2026-02-24', approver: '—' },
  { id: 'EXC-006', resource: 'S3 bucket in ap-southeast-1', type: 'UNAPPROVED_REGION', provider: 'aws', status: 'APPROVED', created: '2026-02-18', updated: '2026-02-19', approver: 'admin1@contoso.dev', expiry: '2026-05-19' },
  { id: 'EXC-007', resource: 'RDS db.r5.2xlarge prod', type: 'OVERSIZED_INSTANCE', provider: 'aws', status: 'REJECTED', created: '2026-02-10', updated: '2026-02-11', approver: 'admin1@contoso.dev' },
  { id: 'EXC-009', resource: 'AKS private cluster eastus', type: 'RESTRICTED_SERVICE', provider: 'azure', status: 'APPROVED', created: '2026-01-15', updated: '2026-01-16', approver: 'operator1@contoso.dev', expiry: '2026-04-15' },
  { id: 'EXC-011', resource: 'GKE node pool us-central1-a', type: 'OVERSIZED_INSTANCE', provider: 'gcp', status: 'EXPIRED', created: '2025-11-01', updated: '2026-02-01', approver: 'operator1@contoso.dev' },
]

const STATUS_CONFIG: Record<string, { icon: typeof CheckCircle2; className: string; badge: string }> = {
  PENDING: { icon: Clock, className: 'text-yellow-600 dark:text-yellow-400', badge: 'bg-yellow-100 text-yellow-800 dark:bg-yellow-900/30 dark:text-yellow-300' },
  APPROVED: { icon: CheckCircle2, className: 'text-green-600 dark:text-green-400', badge: 'bg-green-100 text-green-800 dark:bg-green-900/30 dark:text-green-300' },
  REJECTED: { icon: XCircle, className: 'text-red-600 dark:text-red-400', badge: 'bg-red-100 text-red-800 dark:bg-red-900/30 dark:text-red-300' },
  EXPIRED: { icon: AlertTriangle, className: 'text-gray-500 dark:text-gray-400', badge: 'bg-gray-100 text-gray-600 dark:bg-gray-900/30 dark:text-gray-400' },
}

const PROVIDER_COLORS: Record<string, string> = {
  aws: 'bg-orange-100 text-orange-700 dark:bg-orange-900/30 dark:text-orange-300',
  azure: 'bg-blue-100 text-blue-700 dark:bg-blue-900/30 dark:text-blue-300',
  gcp: 'bg-green-100 text-green-700 dark:bg-green-900/30 dark:text-green-300',
}

export default function MyRequests() {
  const [statusFilter, setStatusFilter] = useState('ALL')

  const filtered = statusFilter === 'ALL' ? REQUESTS : REQUESTS.filter(r => r.status === statusFilter)

  const counts = REQUESTS.reduce<Record<string, number>>((acc, r) => {
    acc[r.status] = (acc[r.status] ?? 0) + 1
    return acc
  }, {})

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-xl font-semibold">My Requests</h1>
          <p className="text-sm text-muted-foreground mt-0.5">{REQUESTS.length} total exception requests</p>
        </div>
        <Link to="/portal/request">
          <Button size="sm" className="text-xs gap-1.5">
            <Plus className="h-3.5 w-3.5" />New Request
          </Button>
        </Link>
      </div>

      {/* Status filter tabs */}
      <div className="flex gap-1 flex-wrap">
        {(['ALL', 'PENDING', 'APPROVED', 'REJECTED', 'EXPIRED'] as const).map(s => (
          <button
            key={s}
            onClick={() => setStatusFilter(s)}
            className={`px-3 py-1 text-xs rounded-none font-medium transition-colors ${
              statusFilter === s ? 'bg-foreground text-background' : 'bg-muted text-muted-foreground hover:bg-muted/80'
            }`}
          >
            {s} ({s === 'ALL' ? REQUESTS.length : (counts[s] ?? 0)})
          </button>
        ))}
      </div>

      <Card>
        <CardHeader className="pb-2">
          <CardTitle className="text-xs font-medium uppercase tracking-wide text-muted-foreground">{filtered.length} requests</CardTitle>
        </CardHeader>
        <CardContent className="p-0">
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead className="text-xs pl-4">ID</TableHead>
                <TableHead className="text-xs">Resource</TableHead>
                <TableHead className="text-xs">Type</TableHead>
                <TableHead className="text-xs">Provider</TableHead>
                <TableHead className="text-xs">Status</TableHead>
                <TableHead className="text-xs">Created</TableHead>
                <TableHead className="text-xs">Approver</TableHead>
                <TableHead className="text-xs">Expiry</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {filtered.map(req => {
                const { icon: Icon, className, badge } = STATUS_CONFIG[req.status] ?? STATUS_CONFIG.PENDING
                return (
                  <TableRow key={req.id} className="hover:bg-muted/30">
                    <TableCell className="pl-4">
                      <Link to={`/portal/requests/${req.id}`} className="text-xs font-mono text-primary hover:underline">
                        {req.id}
                      </Link>
                    </TableCell>
                    <TableCell className="text-xs">{req.resource}</TableCell>
                    <TableCell><Badge variant="outline" className="text-[10px]">{req.type}</Badge></TableCell>
                    <TableCell>
                      <Badge variant="secondary" className={`text-[10px] ${PROVIDER_COLORS[req.provider] ?? ''}`}>
                        {req.provider.toUpperCase()}
                      </Badge>
                    </TableCell>
                    <TableCell>
                      <div className="flex items-center gap-1">
                        <Icon className={`h-3 w-3 ${className}`} />
                        <span className={`text-[10px] font-medium px-2 py-0.5 rounded-full ${badge}`}>{req.status}</span>
                      </div>
                    </TableCell>
                    <TableCell className="text-xs text-muted-foreground">{req.created}</TableCell>
                    <TableCell className="text-xs text-muted-foreground max-w-[140px] truncate" title={req.approver ?? '—'}>
                      {req.approver ? req.approver.split('@')[0] : '—'}
                    </TableCell>
                    <TableCell className={`text-xs ${req.expiry ? 'text-foreground' : 'text-muted-foreground'}`}>{req.expiry ?? '—'}</TableCell>
                  </TableRow>
                )
              })}
            </TableBody>
          </Table>
        </CardContent>
      </Card>
    </div>
  )
}
