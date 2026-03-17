import { Fragment, useState } from 'react'
import { Link } from 'react-router-dom'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
import { Badge } from '@/components/ui/badge'
import {
  Table, TableBody, TableCell, TableHead, TableHeader, TableRow,
} from '@/components/ui/table'
import { ShieldCheck, Bot, AlertTriangle, FileText, TrendingUp, Loader2 } from 'lucide-react'
import { EXCEPTION_STATUS_COLORS as STATUS_COLORS } from '@/lib/severity'
import { usePolicies } from '@/hooks/usePolicies'
import { useAgents } from '@/hooks/useAgents'
import { useCompliance } from '@/hooks/useCompliance'
import { useExceptions } from '@/hooks/useExceptions'
import { useRemediations } from '@/hooks/useRemediations'
import type { ExceptionRequest } from '@/types/grc'

// Fallback values when hooks haven't loaded (demo/offline mode)
const FALLBACK_KPI = { policies: 42, agents: 7, compliance: 84, exceptions: 12, drafts: 3, active: 5 } as const

const FALLBACK_EXCEPTION_QUEUE = [
  { id: 'EXC-001', app: 'payments-api', type: 'UNAPPROVED_REGION', resource: 'RDS in ap-southeast-3', status: 'PENDING', created: '2026-02-25', sla: '1d' },
  { id: 'EXC-002', app: 'data-pipeline', type: 'OVERSIZED_INSTANCE', resource: 'EC2 m5.24xlarge', status: 'PENDING', created: '2026-02-24', sla: '2d' },
  { id: 'EXC-003', app: 'ml-training', type: 'RESTRICTED_SERVICE', resource: 'Bedrock us-gov-west-1', status: 'APPROVED', created: '2026-02-23', sla: '—' },
  { id: 'EXC-004', app: 'auth-service', type: 'NETWORK_EXPOSURE', resource: 'SG sg-0abc1234 port 22', status: 'PENDING', created: '2026-02-22', sla: '4h' },
]

// Fallback trend values when hooks haven't loaded
const FALLBACK_TREND = { policies: '18,432', remediations: '341', approved: '7' } as const

const SLA_WINDOW_HOURS = 72 // Default exception review SLA: 72 hours

function computeExceptionSLA(e: ExceptionRequest): string {
  if (e.status !== 'PENDING') return '—'
  const deadline = e.expiration_date
    ? new Date(e.expiration_date).getTime()
    : new Date(e.created_at).getTime() + SLA_WINDOW_HOURS * 60 * 60 * 1000
  const remainMs = deadline - Date.now()
  if (remainMs <= 0) return 'overdue'
  const remainH = Math.floor(remainMs / (1000 * 60 * 60))
  if (remainH < 24) return `${remainH}h`
  return `${Math.floor(remainH / 24)}d`
}

export default function AdminDashboard() {
  const [expandedExc, setExpandedExc] = useState<string | null>(null)
  const { data: policies, isLoading: polLoading } = usePolicies()
  const { data: agents, isLoading: agentLoading } = useAgents()
  const { data: frameworks, isLoading: compLoading } = useCompliance()
  const { data: exceptions, isLoading: excLoading } = useExceptions()
  const { data: remediations, isLoading: remLoading } = useRemediations()

  const isLoading = polLoading || agentLoading || compLoading || excLoading || remLoading

  const activePolicies = policies?.filter(p => p.status === 'active').length ?? FALLBACK_KPI.policies
  const agentCount = agents?.length ?? FALLBACK_KPI.agents
  const avgCompliance = frameworks && frameworks.length > 0
    ? Math.round(frameworks.reduce((s, f) => s + f.score, 0) / frameworks.length)
    : FALLBACK_KPI.compliance
  const openExceptions = exceptions?.length ?? FALLBACK_KPI.exceptions

  const activeAgents = agents?.filter(a => a.status === 'active').length ?? FALLBACK_KPI.active
  const idleAgents = (agents?.length ?? FALLBACK_KPI.agents) - activeAgents

  const KPI_CARDS = [
    { label: 'Active Policies', value: activePolicies, sub: `${(policies?.filter(p => p.status === 'draft').length ?? FALLBACK_KPI.drafts)} pending review`, icon: FileText, color: 'text-blue-600 dark:text-blue-400', bg: 'bg-blue-50 dark:bg-blue-950/20', link: '/admin/policies' },
    { label: 'AI Agents', value: agentCount, sub: `${activeAgents} active, ${idleAgents} idle`, icon: Bot, color: 'text-indigo-600 dark:text-indigo-400', bg: 'bg-indigo-50 dark:bg-indigo-950/20', link: '/admin/ai-agents' },
    { label: 'Compliance Score', value: `${avgCompliance}%`, sub: 'avg across frameworks', icon: ShieldCheck, color: 'text-green-600 dark:text-green-400', bg: 'bg-green-50 dark:bg-green-950/20', link: '/ops/compliance' },
    { label: 'Open Exceptions', value: openExceptions, sub: `${exceptions?.filter(e => e.status === 'PENDING').length ?? FALLBACK_KPI.drafts} pending`, icon: AlertTriangle, color: 'text-orange-600 dark:text-orange-400', bg: 'bg-orange-50 dark:bg-orange-950/20', link: '/ops/remediation' },
  ]

  // SLA summary — how many pending exceptions are within SLA
  const pendingExceptions = exceptions?.filter(e => e.status === 'PENDING') ?? []
  const withinSLA = pendingExceptions.filter(e => computeExceptionSLA(e) !== 'overdue').length
  const overdueSLA = pendingExceptions.length - withinSLA
  const slaPct = pendingExceptions.length > 0 ? Math.round((withinSLA / pendingExceptions.length) * 100) : 100

  // Trend metrics — computed from hooks, static fallbacks for values without API data
  const trendPolicies = policies?.length?.toLocaleString() ?? FALLBACK_TREND.policies
  const trendRemediations = (remediations?.filter(r => r.status === 'completed').length ?? 341).toLocaleString()
  const trendApproved = (exceptions?.filter(e => e.status === 'APPROVED').length ?? 7).toLocaleString()
  // Change percentages: static until time-series API is available
  const TREND = [
    { label: 'Policies Evaluated', value: trendPolicies, change: '+12%' },
    { label: 'Auto-Remediations', value: trendRemediations, change: '+8%' },
    { label: 'Exceptions Approved', value: trendApproved, change: '-3%' },
  ]

  const EXCEPTION_QUEUE = exceptions
    ? exceptions.slice(0, 4).map(e => ({
        id: e.id,
        app: e.application_id,
        type: e.request_type,
        resource: e.resource_requested,
        status: e.status,
        created: e.created_at.slice(0, 10),
        sla: computeExceptionSLA(e),
      }))
    : FALLBACK_EXCEPTION_QUEUE

  if (isLoading) {
    return (
      <div className="flex items-center gap-2 text-sm text-muted-foreground p-4">
        <Loader2 className="h-4 w-4 animate-spin" />Loading dashboard…
      </div>
    )
  }

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-xl font-semibold">Admin Dashboard</h1>
          <p className="text-sm text-muted-foreground mt-0.5">Platform overview — {new Date().toLocaleDateString('en-US', { month: 'short', year: 'numeric' })}</p>
        </div>
        <Badge variant="secondary" className="text-xs">Live</Badge>
      </div>

      {/* KPI Cards */}
      <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
        {KPI_CARDS.map(({ label, value, sub, icon: Icon, color, bg, link }) => (
          <Link key={label} to={link} className="group">
            <Card className="hover:border-primary/40 hover:-translate-y-0.5 hover:shadow-lg transition-all duration-200">
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

      {/* SLA overview */}
      {pendingExceptions.length > 0 && (
        <Card>
          <CardContent className="p-4">
            <div className="flex items-center justify-between mb-2">
              <p className="text-xs font-medium uppercase tracking-wide text-muted-foreground">Exception SLA Compliance</p>
              <span className={`text-sm font-bold tabular-nums ${slaPct >= 80 ? 'text-green-600 dark:text-green-400' : slaPct >= 50 ? 'text-yellow-600 dark:text-yellow-400' : 'text-red-600 dark:text-red-400'}`}>{slaPct}%</span>
            </div>
            <div className="h-2 bg-muted rounded-full overflow-hidden">
              <div
                className={`h-full rounded-full transition-all ${slaPct >= 80 ? 'bg-green-500' : slaPct >= 50 ? 'bg-yellow-500' : 'bg-red-500'}`}
                style={{ width: `${slaPct}%` }}
              />
            </div>
            <div className="flex justify-between mt-1.5 text-[10px] text-muted-foreground">
              <span>{withinSLA} within SLA</span>
              {overdueSLA > 0 && <span className="text-red-600 dark:text-red-400">{overdueSLA} overdue</span>}
            </div>
          </CardContent>
        </Card>
      )}

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
            <Link to="/ops/remediation" className="text-xs text-primary hover:underline">View All →</Link>
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
                <Fragment key={exc.id}>
                  <TableRow>
                    <TableCell className="text-xs pl-4">
                      <button
                        type="button"
                        onClick={() => setExpandedExc(expandedExc === exc.id ? null : exc.id)}
                        className="text-primary hover:underline font-mono cursor-pointer bg-transparent border-none p-0"
                      >
                        {exc.id}
                      </button>
                    </TableCell>
                    <TableCell className="text-xs">{exc.app}</TableCell>
                    <TableCell><Badge variant="outline" className="text-[10px]">{exc.type}</Badge></TableCell>
                    <TableCell className="text-xs text-muted-foreground">{exc.resource}</TableCell>
                    <TableCell>
                      <span className={`text-[10px] font-medium px-2 py-0.5 rounded-none ${STATUS_COLORS[exc.status] ?? 'bg-gray-100 text-gray-700 dark:bg-gray-900/30 dark:text-gray-300'}`}>
                        {exc.status}
                      </span>
                    </TableCell>
                    <TableCell className={`text-xs font-medium ${exc.sla === '—' ? 'text-muted-foreground' : exc.sla === 'overdue' ? 'text-red-600 dark:text-red-400' : 'text-orange-600 dark:text-orange-400'}`}>{exc.sla}</TableCell>
                  </TableRow>
                  {expandedExc === exc.id && (
                    <TableRow key={`${exc.id}-detail`}>
                      <TableCell colSpan={6} className="bg-muted/30 px-4 py-3">
                        <div className="grid grid-cols-3 gap-x-6 gap-y-2 text-xs">
                          <div><span className="text-muted-foreground">Application:</span> <span className="font-medium">{exc.app}</span></div>
                          <div><span className="text-muted-foreground">Type:</span> <span className="font-mono">{exc.type}</span></div>
                          <div><span className="text-muted-foreground">Resource:</span> <span className="font-medium">{exc.resource}</span></div>
                          <div><span className="text-muted-foreground">Status:</span> <span className={`font-medium px-1.5 py-0.5 rounded-none ${STATUS_COLORS[exc.status] ?? ''}`}>{exc.status}</span></div>
                          <div><span className="text-muted-foreground">SLA:</span> <span className={`font-medium ${exc.sla === '—' ? '' : exc.sla === 'overdue' ? 'text-red-600 dark:text-red-400' : 'text-orange-600 dark:text-orange-400'}`}>{exc.sla}</span></div>
                          <div><span className="text-muted-foreground">Created:</span> <span className="font-medium">{exc.created}</span></div>
                        </div>
                      </TableCell>
                    </TableRow>
                  )}
                </Fragment>
              ))}
            </TableBody>
          </Table>
        </CardContent>
      </Card>
    </div>
  )
}
