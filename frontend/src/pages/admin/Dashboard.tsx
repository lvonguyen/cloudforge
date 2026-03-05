import { Link } from 'react-router-dom'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
import { Badge } from '@/components/ui/badge'
import {
  Table, TableBody, TableCell, TableHead, TableHeader, TableRow,
} from '@/components/ui/table'
import { ShieldCheck, Bot, AlertTriangle, FileText, TrendingUp } from 'lucide-react'

const KPI_CARDS = [
  { label: 'Active Policies', value: 42, sub: '3 pending review', icon: FileText, color: 'text-blue-600 dark:text-blue-400', bg: 'bg-blue-50 dark:bg-blue-950/20', link: '/admin/policies' },
  { label: 'AI Agents', value: 7, sub: '5 active, 2 idle', icon: Bot, color: 'text-indigo-600 dark:text-indigo-400', bg: 'bg-indigo-50 dark:bg-indigo-950/20', link: '/admin/ai-agents' },
  { label: 'Compliance Score', value: '84%', sub: '+2% this week', icon: ShieldCheck, color: 'text-green-600 dark:text-green-400', bg: 'bg-green-50 dark:bg-green-950/20', link: '/ops/compliance' },
  { label: 'Open Exceptions', value: 12, sub: '3 critical SLA', icon: AlertTriangle, color: 'text-orange-600 dark:text-orange-400', bg: 'bg-orange-50 dark:bg-orange-950/20', link: '/ops' },
]

const EXCEPTION_QUEUE = [
  { id: 'EXC-001', app: 'payments-api', type: 'UNAPPROVED_REGION', resource: 'RDS in ap-southeast-3', status: 'PENDING', created: '2026-02-25', sla: '1d' },
  { id: 'EXC-002', app: 'data-pipeline', type: 'OVERSIZED_INSTANCE', resource: 'EC2 m5.24xlarge', status: 'PENDING', created: '2026-02-24', sla: '2d' },
  { id: 'EXC-003', app: 'ml-training', type: 'RESTRICTED_SERVICE', resource: 'Bedrock us-gov-west-1', status: 'APPROVED', created: '2026-02-23', sla: '—' },
  { id: 'EXC-004', app: 'auth-service', type: 'NETWORK_EXPOSURE', resource: 'SG sg-0abc1234 port 22', status: 'PENDING', created: '2026-02-22', sla: '4h' },
]

const STATUS_COLORS: Record<string, string> = {
  PENDING: 'bg-yellow-100 text-yellow-800 dark:bg-yellow-900/30 dark:text-yellow-300',
  APPROVED: 'bg-green-100 text-green-800 dark:bg-green-900/30 dark:text-green-300',
  REJECTED: 'bg-red-100 text-red-800 dark:bg-red-900/30 dark:text-red-300',
  EXPIRED: 'bg-gray-100 text-gray-700 dark:bg-gray-900/30 dark:text-gray-300',
}

const TREND = [
  { label: 'Policies Evaluated', value: '18,432', change: '+12%' },
  { label: 'Auto-Remediations', value: '341', change: '+8%' },
  { label: 'Exceptions Approved', value: '7', change: '-3%' },
]

export default function AdminDashboard() {
  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-xl font-semibold">Admin Dashboard</h1>
          <p className="text-sm text-muted-foreground mt-0.5">Platform overview — Feb 2026</p>
        </div>
        <Badge variant="secondary" className="text-xs">Live</Badge>
      </div>

      {/* KPI Cards */}
      <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
        {KPI_CARDS.map(({ label, value, sub, icon: Icon, color, bg, link }) => (
          <Link key={label} to={link} className="group">
            <Card className="hover:border-accent/50 hover:-translate-y-0.5 transition-all duration-200">
              <CardContent className="p-4">
                <div className="flex items-start justify-between">
                  <div>
                    <p className={`text-2xl font-bold ${color}`}>{value}</p>
                    <p className="text-xs font-medium mt-0.5">{label}</p>
                    <p className="text-[10px] text-muted-foreground mt-0.5">{sub}</p>
                  </div>
                  <div className={`h-9 w-9 rounded-none ${bg} flex items-center justify-center shrink-0`}>
                    <Icon className={`h-4 w-4 ${color}`} />
                  </div>
                </div>
              </CardContent>
            </Card>
          </Link>
        ))}
      </div>

      {/* Trend row */}
      <div className="grid grid-cols-3 gap-4">
        {TREND.map(({ label, value, change }) => (
          <Card key={label}>
            <CardContent className="p-4 flex items-center gap-3">
              <TrendingUp className="h-4 w-4 text-muted-foreground shrink-0" />
              <div>
                <p className="text-sm font-semibold">{value}</p>
                <p className="text-[10px] text-muted-foreground">{label}</p>
              </div>
              <span className={`ml-auto text-xs font-medium ${change.startsWith('+') ? 'text-green-600 dark:text-green-400' : 'text-red-600 dark:text-red-400'}`}>{change}</span>
            </CardContent>
          </Card>
        ))}
      </div>

      {/* Exception queue preview */}
      <Card>
        <CardHeader className="pb-2">
          <div className="flex items-center justify-between">
            <CardTitle className="text-xs font-medium uppercase tracking-wide text-muted-foreground">Exception Queue</CardTitle>
            <Link to="/ops/command-center" className="text-xs text-primary hover:underline">View All →</Link>
          </div>
        </CardHeader>
        <CardContent className="p-0">
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead className="text-xs pl-4">ID</TableHead>
                <TableHead className="text-xs">Application</TableHead>
                <TableHead className="text-xs">Type</TableHead>
                <TableHead className="text-xs">Resource</TableHead>
                <TableHead className="text-xs">Status</TableHead>
                <TableHead className="text-xs">SLA</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {EXCEPTION_QUEUE.map(exc => (
                <TableRow key={exc.id}>
                  <TableCell className="text-xs pl-4"><Link to={`/portal/requests/${exc.id}`} className="text-primary hover:underline font-mono">{exc.id}</Link></TableCell>
                  <TableCell className="text-xs">{exc.app}</TableCell>
                  <TableCell><Badge variant="outline" className="text-[10px]">{exc.type}</Badge></TableCell>
                  <TableCell className="text-xs text-muted-foreground">{exc.resource}</TableCell>
                  <TableCell>
                    <span className={`text-[10px] font-medium px-2 py-0.5 rounded-full ${STATUS_COLORS[exc.status] ?? 'bg-gray-100 text-gray-700 dark:bg-gray-900/30 dark:text-gray-300'}`}>
                      {exc.status}
                    </span>
                  </TableCell>
                  <TableCell className={`text-xs font-medium ${exc.sla === '—' ? 'text-muted-foreground' : 'text-orange-600 dark:text-orange-400'}`}>{exc.sla}</TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </CardContent>
      </Card>
    </div>
  )
}
