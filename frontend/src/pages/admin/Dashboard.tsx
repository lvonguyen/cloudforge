import { Fragment, useMemo, useState } from 'react'
import { Link } from 'react-router-dom'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
import { Badge } from '@/components/ui/badge'
import {
  Select, SelectContent, SelectItem, SelectTrigger, SelectValue,
} from '@/components/ui/select'
import {
  Table, TableBody, TableCell, TableHead, TableHeader, TableRow,
} from '@/components/ui/table'
import { ShieldCheck, Bot, AlertTriangle, FileText, TrendingUp, TrendingDown, Minus, Loader2 } from 'lucide-react'
import { ShieldX } from 'lucide-react'
import { EXCEPTION_STATUS_COLORS as STATUS_COLORS } from '@/lib/severity'
import { branding } from '@/lib/branding'
import { usePolicies } from '@/hooks/usePolicies'
import { useAgents } from '@/hooks/useAgents'
import { useCompliance } from '@/hooks/useCompliance'
import { useExceptions } from '@/hooks/useExceptions'
import { useRemediations } from '@/hooks/useRemediations'
import { useAttackPaths } from '@/hooks/useAttackPaths'
import { ApiError } from '@/lib/api'
import { ProviderBadge } from '@/components/ui/ProviderBadge'
import { Target } from 'lucide-react'
import type { ExceptionRequest } from '@/types/grc'

// Widget preset definitions
type WidgetId = 'kpi' | 'sla' | 'trend' | 'chokepoints' | 'exceptions'
type PresetId = 'default' | 'security' | 'operations' | 'executive'

interface DashboardPreset {
  id: PresetId
  label: string
  widgets: WidgetId[]
}

const PRESETS: DashboardPreset[] = [
  { id: 'default', label: 'All Widgets', widgets: ['kpi', 'sla', 'trend', 'chokepoints', 'exceptions'] },
  { id: 'security', label: 'Security Focus', widgets: ['kpi', 'chokepoints', 'exceptions'] },
  { id: 'operations', label: 'Operations', widgets: ['kpi', 'sla', 'trend', 'exceptions'] },
  { id: 'executive', label: 'Executive', widgets: ['kpi', 'trend'] },
]

const PRESET_STORAGE_KEY = `${branding.storagePrefix}:dashboard-preset`

function getInitialPreset(): PresetId {
  const stored = localStorage.getItem(PRESET_STORAGE_KEY)
  if (stored && PRESETS.some(p => p.id === stored)) return stored as PresetId
  return 'default'
}

// Fallback values when hooks haven't loaded (demo/offline mode)
const FALLBACK_KPI = { policies: 42, agents: 7, compliance: 84, exceptions: 4, drafts: 3, active: 5 } as const

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
  const [presetId, setPresetId] = useState<PresetId>(getInitialPreset)
  const activePreset = PRESETS.find(p => p.id === presetId) ?? PRESETS[0]
  const showWidget = (id: WidgetId) => activePreset.widgets.includes(id)

  function handlePresetChange(value: string) {
    const id = value as PresetId
    setPresetId(id)
    localStorage.setItem(PRESET_STORAGE_KEY, id)
  }
  const { data: policies, isLoading: polLoading, error: polError } = usePolicies()
  const { data: agents, isLoading: agentLoading, error: agentError } = useAgents()
  const { data: frameworks, isLoading: compLoading, error: compError } = useCompliance()
  const { data: exceptions, isLoading: excLoading, error: excError } = useExceptions()
  const { data: remediations, isLoading: remLoading, error: remError } = useRemediations()
  const { data: attackPathsResponse } = useAttackPaths(1, 100)

  const isLoading = polLoading || agentLoading || compLoading || excLoading || remLoading

  // SEC-B08: Detect 403 from any hook and show Access Denied instead of fallback data
  const authError = [polError, agentError, compError, excError, remError].find(
    e => e instanceof ApiError && e.status === 403
  )
  if (!isLoading && authError) {
    return (
      <div className="flex items-center justify-center min-h-[400px]">
        <Card className="border-red-200 dark:border-red-800 max-w-md">
          <CardContent className="p-8 text-center">
            <ShieldX className="h-10 w-10 text-red-500 mx-auto mb-3" />
            <h2 className="text-lg font-semibold">Access Denied</h2>
            <p className="text-sm text-muted-foreground mt-1">
              You do not have permission to view the admin dashboard.
              Contact your administrator if you believe this is an error.
            </p>
          </CardContent>
        </Card>
      </div>
    )
  }

  const activePolicies = policies?.filter(p => p.status === 'active').length ?? FALLBACK_KPI.policies
  const agentCount = agents?.length ?? FALLBACK_KPI.agents
  const avgCompliance = frameworks && frameworks.length > 0
    ? Math.round(frameworks.reduce((s, f) => s + f.score, 0) / frameworks.length)
    : FALLBACK_KPI.compliance
  const openExceptions = exceptions?.length ?? FALLBACK_KPI.exceptions

  const activeAgents = agents?.filter(a => a.status === 'active').length ?? FALLBACK_KPI.active
  const idleAgents = (agents?.length ?? FALLBACK_KPI.agents) - activeAgents

  const KPI_CARDS_BASE = [
    { label: 'Active Policies', value: activePolicies, sub: `${(policies?.filter(p => p.status === 'draft').length ?? FALLBACK_KPI.drafts)} pending review`, deltaKey: 'pol' as const, icon: FileText, color: 'text-blue-600 dark:text-blue-400', bg: 'bg-blue-50 dark:bg-blue-950/20', link: '/admin/policies' },
    { label: 'AI Agents', value: agentCount, sub: `${activeAgents} active, ${idleAgents} idle`, deltaKey: null, icon: Bot, color: 'text-indigo-600 dark:text-indigo-400', bg: 'bg-indigo-50 dark:bg-indigo-950/20', link: '/admin/ai-agents' },
    { label: 'Compliance Score', value: `${avgCompliance}%`, sub: 'avg across frameworks', deltaKey: null, icon: ShieldCheck, color: 'text-green-600 dark:text-green-400', bg: 'bg-green-50 dark:bg-green-950/20', link: '/ops/compliance' },
    { label: 'Open Exceptions', value: openExceptions, sub: `${exceptions?.filter(e => e.status === 'PENDING').length ?? FALLBACK_KPI.drafts} pending`, deltaKey: 'exc' as const, icon: AlertTriangle, color: 'text-orange-600 dark:text-orange-400', bg: 'bg-orange-50 dark:bg-orange-950/20', link: '/admin/exceptions' },
  ]

  // SLA summary — how many pending exceptions are within SLA
  const pendingExceptions = exceptions?.filter(e => e.status === 'PENDING') ?? []
  const withinSLA = pendingExceptions.filter(e => computeExceptionSLA(e) !== 'overdue').length
  const overdueSLA = pendingExceptions.length - withinSLA
  const slaPct = pendingExceptions.length > 0 ? Math.round((withinSLA / pendingExceptions.length) * 100) : 100

  // Trend metrics — computed from hooks, with temporal comparison where possible
  const trendPolicies = policies?.length?.toLocaleString() ?? FALLBACK_TREND.policies
  const completedRemediations = remediations?.filter(r => r.status === 'completed') ?? []
  const trendRemediations = completedRemediations.length > 0 ? completedRemediations.length.toLocaleString() : FALLBACK_TREND.remediations
  const approvedExceptions = exceptions?.filter(e => e.status === 'APPROVED') ?? []
  const trendApproved = approvedExceptions.length > 0 ? approvedExceptions.length.toLocaleString() : FALLBACK_TREND.approved

  // Temporal comparison: last 7 days vs prior 7 days using created_at
  const now = Date.now()
  const WEEK_MS = 7 * 24 * 60 * 60 * 1000
  function recentVsPrior(items: { created_at: string }[]): string | null {
    const recent = items.filter(i => now - new Date(i.created_at).getTime() < WEEK_MS).length
    const prior = items.filter(i => {
      const age = now - new Date(i.created_at).getTime()
      return age >= WEEK_MS && age < WEEK_MS * 2
    }).length
    if (prior === 0 && recent === 0) return null
    if (prior === 0) return '+100%'
    const pct = Math.round(((recent - prior) / prior) * 100)
    return pct >= 0 ? `+${pct}%` : `${pct}%`
  }

  const remChange = remediations ? recentVsPrior(completedRemediations) : null
  const excChange = exceptions ? recentVsPrior(approvedExceptions) : null

  // KPI card deltas
  const kpiDeltas: Record<string, string | null> = {
    pol: policies ? recentVsPrior(policies.filter(p => p.status === 'active').map(p => ({ created_at: p.last_updated }))) : null,
    exc: exceptions ? recentVsPrior(exceptions) : null,
  }
  const KPI_CARDS = KPI_CARDS_BASE.map(card => ({
    ...card,
    delta: card.deltaKey ? kpiDeltas[card.deltaKey] : null,
  }))

  const TREND = [
    { label: 'Policies Evaluated', value: trendPolicies, change: null as string | null },
    { label: 'Auto-Remediations', value: trendRemediations, change: remChange },
    { label: 'Exceptions Approved', value: trendApproved, change: excChange },
  ]

  // Choke points — resources appearing in multiple attack paths (GAP-02)
  const SEVERITY_PRIORITY: Record<string, number> = { CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3 }
  const chokePoints = useMemo(() => {
    const paths = attackPathsResponse?.data ?? []
    const resourceMap = new Map<string, { name: string; type: string; provider: string; pathCount: number; severity: string }>()
    for (const p of paths) {
      const seen = new Set<string>()
      for (const n of p.nodes) {
        if (seen.has(n.resource_id)) continue
        seen.add(n.resource_id)
        const existing = resourceMap.get(n.resource_id)
        if (existing) {
          existing.pathCount++
          if ((SEVERITY_PRIORITY[n.severity] ?? 9) < (SEVERITY_PRIORITY[existing.severity] ?? 9)) {
            existing.severity = n.severity
          }
        } else {
          resourceMap.set(n.resource_id, { name: n.resource_name, type: n.resource_type, provider: n.provider ?? '', pathCount: 1, severity: n.severity })
        }
      }
    }
    return [...resourceMap.entries()].filter(([, v]) => v.pathCount > 1).sort((a, b) => b[1].pathCount - a[1].pathCount).slice(0, 5)
  }, [attackPathsResponse])

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
        <div className="flex items-center gap-2">
          <Select value={presetId} onValueChange={handlePresetChange}>
            <SelectTrigger className="h-7 w-36 text-xs">
              <SelectValue />
            </SelectTrigger>
            <SelectContent>
              {PRESETS.map(p => (
                <SelectItem key={p.id} value={p.id} className="text-xs">{p.label}</SelectItem>
              ))}
            </SelectContent>
          </Select>
          <Badge variant="secondary" className="text-xs">Live</Badge>
        </div>
      </div>

      {/* KPI Cards */}
      {showWidget('kpi') && (
      <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
        {KPI_CARDS.map(({ label, value, sub, delta, icon: Icon, color, bg, link }) => (
          <Link key={label} to={link} className="group">
            <Card className="hover:border-primary/40 hover:-translate-y-0.5 hover:shadow-lg transition-all duration-200">
              <CardContent className="p-4">
                <div className="flex items-start justify-between">
                  <div>
                    <div className="flex items-baseline gap-2">
                      <p className={`text-2xl font-bold ${color}`}>{value}</p>
                      {delta && (
                        <span className={`text-[10px] font-medium ${delta.startsWith('+') ? 'text-green-600 dark:text-green-400' : delta.startsWith('-') ? 'text-red-600 dark:text-red-400' : 'text-muted-foreground'}`}>
                          {delta} 7d
                        </span>
                      )}
                    </div>
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
      )}

      {/* SLA overview */}
      {showWidget('sla') && pendingExceptions.length > 0 && (
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
      {showWidget('trend') && (
      <div className="grid grid-cols-3 gap-4">
        {TREND.map(({ label, value, change }) => {
          const isPositive = change?.startsWith('+')
          const TrendIcon = change == null ? Minus : isPositive ? TrendingUp : TrendingDown
          const trendColor = change == null ? 'text-muted-foreground' : isPositive ? 'text-green-600 dark:text-green-400' : 'text-red-600 dark:text-red-400'
          return (
            <Card key={label}>
              <CardContent className="p-4 flex items-center gap-3">
                <TrendIcon className={`h-4 w-4 shrink-0 ${trendColor}`} />
                <div>
                  <p className="text-sm font-semibold">{value}</p>
                  <p className="text-[10px] text-muted-foreground">{label}</p>
                </div>
                <span className={`ml-auto text-xs font-medium ${trendColor}`}>{change ?? '—'}</span>
              </CardContent>
            </Card>
          )
        })}
      </div>
      )}

      {/* Choke points — GAP-02 */}
      {showWidget('chokepoints') && chokePoints.length > 0 && (
        <Card className="rounded-none border-amber-200 dark:border-amber-900/40">
          <CardHeader className="pb-2 pt-3 px-4">
            <div className="flex items-center justify-between">
              <span className="text-xs font-semibold uppercase tracking-wide text-amber-600 dark:text-amber-400 flex items-center gap-1.5">
                <Target className="h-3.5 w-3.5" />Choke Points
              </span>
              <Link to="/ops" className="text-xs text-primary hover:underline">View All</Link>
            </div>
            <span className="text-[10px] text-muted-foreground">Resources appearing in multiple attack paths</span>
          </CardHeader>
          <CardContent className="px-4 pb-3">
            <div className="space-y-1.5">
              {chokePoints.map(([id, cp]) => (
                <div key={id} className="flex items-center gap-2 text-xs">
                  <ProviderBadge provider={cp.provider} />
                  <span className="flex-1 truncate font-medium">{cp.name}</span>
                  <span className="text-[10px] text-muted-foreground">{cp.type}</span>
                  <Badge variant="outline" className="text-[10px] px-1.5 py-0 rounded-none">
                    in {cp.pathCount} paths
                  </Badge>
                </div>
              ))}
            </div>
          </CardContent>
        </Card>
      )}

      {/* Exception queue preview */}
      {showWidget('exceptions') && (
      <Card>

        <CardHeader className="pb-2">
          <div className="flex items-center justify-between">
            <CardTitle className="text-xs font-medium uppercase tracking-wide text-muted-foreground">Exception Requests</CardTitle>
            <Link to="/admin/exceptions" className="text-xs text-primary hover:underline">View All →</Link>
          </div>
        </CardHeader>
        <CardContent className="p-0 overflow-x-auto">
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
      )}
    </div>
  )
}
