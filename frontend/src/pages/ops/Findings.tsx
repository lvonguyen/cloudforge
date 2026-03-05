import { useMemo, useState, useCallback } from 'react'
import { useNavigate } from 'react-router-dom'
import { Download, ChevronLeft, ChevronRight, ArrowUp, ArrowDown, X } from 'lucide-react'
import { useFindings } from '@/hooks/useFindings'
import { SeverityBadge } from '@/components/findings/SeverityBadge'
import { SLACountdown } from '@/components/findings/SLACountdown'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import {
  Select, SelectContent, SelectItem, SelectTrigger, SelectValue,
} from '@/components/ui/select'
import {
  Table, TableBody, TableCell, TableHead, TableHeader, TableRow,
} from '@/components/ui/table'
import type { Finding } from '@/types/compliance'

const SEVERITY_ORDER: Record<string, number> = { CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3 }

const SEVERITY_TABS = ['ALL', 'CRITICAL', 'HIGH', 'MEDIUM', 'LOW'] as const
type SeverityTab = (typeof SEVERITY_TABS)[number]

const SEVERITY_COLORS: Record<string, string> = {
  CRITICAL: 'bg-red-100 text-red-800 dark:bg-red-900/30 dark:text-red-300',
  HIGH: 'bg-orange-100 text-orange-800 dark:bg-orange-900/30 dark:text-orange-300',
  MEDIUM: 'bg-yellow-100 text-yellow-800 dark:bg-yellow-900/30 dark:text-yellow-300',
  LOW: 'bg-blue-100 text-blue-800 dark:bg-blue-900/30 dark:text-blue-300',
}

const CATEGORY_COLORS: Record<string, string> = {
  VULNERABILITY: 'bg-red-100 text-red-700 dark:bg-red-900/30 dark:text-red-300',
  MISCONFIGURATION: 'bg-orange-100 text-orange-700 dark:bg-orange-900/30 dark:text-orange-300',
  COMPLIANCE: 'bg-blue-100 text-blue-700 dark:bg-blue-900/30 dark:text-blue-300',
  IDENTITY: 'bg-purple-100 text-purple-700 dark:bg-purple-900/30 dark:text-purple-300',
  NETWORK: 'bg-yellow-100 text-yellow-700 dark:bg-yellow-900/30 dark:text-yellow-300',
}

const WORKFLOW_COLORS: Record<string, string> = {
  new: 'bg-blue-100 text-blue-700 dark:bg-blue-900/30 dark:text-blue-300',
  triaged: 'bg-yellow-100 text-yellow-700 dark:bg-yellow-900/30 dark:text-yellow-300',
  assigned: 'bg-indigo-100 text-indigo-700 dark:bg-indigo-900/30 dark:text-indigo-300',
  in_progress: 'bg-orange-100 text-orange-700 dark:bg-orange-900/30 dark:text-orange-300',
  resolved: 'bg-green-100 text-green-700 dark:bg-green-900/30 dark:text-green-300',
}

const SIDEBAR_CATEGORIES = ['VULNERABILITY', 'MISCONFIGURATION', 'COMPLIANCE', 'IDENTITY', 'NETWORK'] as const
const SIDEBAR_PROVIDERS = ['aws', 'azure', 'gcp'] as const
const SIDEBAR_STATUSES = ['open', 'in_progress', 'resolved'] as const

const STATUS_LABELS: Record<string, string> = {
  open: 'Open',
  in_progress: 'In Progress',
  resolved: 'Resolved',
}

type SortColumn = 'severity' | 'title' | 'category' | 'provider' | 'resource' | 'region' | 'status' | 'sla'
type SortDir = 'asc' | 'desc'

function toggleSet<T>(set: Set<T>, value: T): Set<T> {
  const next = new Set(set)
  if (next.has(value)) next.delete(value)
  else next.add(value)
  return next
}

function formatWorkflowStatus(ws: string): string {
  return ws.replace(/_/g, ' ').replace(/\b\w/g, c => c.toUpperCase())
}

function exportCSV(findings: Finding[]) {
  const headers = ['ID', 'Title', 'Severity', 'Category', 'Provider', 'Resource', 'Region', 'Status', 'SLA Due Date', 'First Found', 'Remediation']
  const rows = findings.map(f => [
    f.id,
    `"${f.title.replace(/"/g, '""')}"`,
    f.severity,
    f.category,
    f.cloud_provider.toUpperCase(),
    f.resource_name,
    f.region,
    f.workflow_status,
    f.due_date ?? '',
    f.first_found_at,
    `"${f.remediation.replace(/"/g, '""')}"`,
  ])
  const csv = [headers.join(','), ...rows.map(r => r.join(','))].join('\n')
  const blob = new Blob([csv], { type: 'text/csv;charset=utf-8;' })
  const url = URL.createObjectURL(blob)
  const a = document.createElement('a')
  const now = new Date()
  const ts = `${now.getFullYear()}${String(now.getMonth() + 1).padStart(2, '0')}${String(now.getDate()).padStart(2, '0')}_${String(now.getHours()).padStart(2, '0')}${String(now.getMinutes()).padStart(2, '0')}${String(now.getSeconds()).padStart(2, '0')}`
  a.href = url
  a.download = `findings_export_${ts}.csv`
  document.body.appendChild(a)
  a.click()
  document.body.removeChild(a)
  URL.revokeObjectURL(url)
}

export default function Findings() {
  const navigate = useNavigate()
  const { data: allFindings = [], isLoading } = useFindings()

  // Sidebar filters
  const [selectedCategories, setSelectedCategories] = useState<Set<string>>(new Set())
  const [selectedProviders, setSelectedProviders] = useState<Set<string>>(new Set())
  const [selectedStatuses, setSelectedStatuses] = useState<Set<string>>(new Set())

  // Severity tab
  const [severityTab, setSeverityTab] = useState<SeverityTab>('ALL')

  // Sort
  const [sortCol, setSortCol] = useState<SortColumn>('severity')
  const [sortDir, setSortDir] = useState<SortDir>('asc')

  // Pagination
  const [page, setPage] = useState(0)
  const [rowsPerPage, setRowsPerPage] = useState(10)

  const hasFilters = selectedCategories.size > 0 || selectedProviders.size > 0 || selectedStatuses.size > 0

  const clearFilters = useCallback(() => {
    setSelectedCategories(new Set())
    setSelectedProviders(new Set())
    setSelectedStatuses(new Set())
    setPage(0)
  }, [])

  // Counts for sidebar (computed from full dataset before any sidebar filter)
  const categoryCounts = useMemo(() => {
    const m: Record<string, number> = {}
    for (const f of allFindings) m[f.category] = (m[f.category] ?? 0) + 1
    return m
  }, [allFindings])

  const providerCounts = useMemo(() => {
    const m: Record<string, number> = {}
    for (const f of allFindings) m[f.cloud_provider] = (m[f.cloud_provider] ?? 0) + 1
    return m
  }, [allFindings])

  const statusCounts = useMemo(() => {
    const m: Record<string, number> = {}
    for (const f of allFindings) m[f.status] = (m[f.status] ?? 0) + 1
    return m
  }, [allFindings])

  // Severity summary (always from full dataset)
  const severityCounts = useMemo(() => {
    const m: Record<string, number> = {}
    for (const f of allFindings) m[f.severity] = (m[f.severity] ?? 0) + 1
    return m
  }, [allFindings])

  // Filter pipeline
  const filtered = useMemo(() => {
    let result = allFindings

    // Sidebar: category (OR within group)
    if (selectedCategories.size > 0) {
      result = result.filter(f => selectedCategories.has(f.category))
    }
    // Sidebar: provider (OR within group)
    if (selectedProviders.size > 0) {
      result = result.filter(f => selectedProviders.has(f.cloud_provider))
    }
    // Sidebar: status (OR within group)
    if (selectedStatuses.size > 0) {
      result = result.filter(f => selectedStatuses.has(f.status))
    }
    // Severity tab
    if (severityTab !== 'ALL') {
      result = result.filter(f => f.severity === severityTab)
    }

    return result
  }, [allFindings, selectedCategories, selectedProviders, selectedStatuses, severityTab])

  // Sort
  const sorted = useMemo(() => {
    const arr = [...filtered]
    const dir = sortDir === 'asc' ? 1 : -1

    arr.sort((a, b) => {
      switch (sortCol) {
        case 'severity':
          return ((SEVERITY_ORDER[a.severity] ?? 9) - (SEVERITY_ORDER[b.severity] ?? 9)) * dir
        case 'title':
          return a.title.localeCompare(b.title) * dir
        case 'category':
          return a.category.localeCompare(b.category) * dir
        case 'provider':
          return a.cloud_provider.localeCompare(b.cloud_provider) * dir
        case 'resource':
          return a.resource_name.localeCompare(b.resource_name) * dir
        case 'region':
          return a.region.localeCompare(b.region) * dir
        case 'status':
          return a.workflow_status.localeCompare(b.workflow_status) * dir
        case 'sla': {
          const aTime = a.due_date ? new Date(a.due_date).getTime() : Infinity
          const bTime = b.due_date ? new Date(b.due_date).getTime() : Infinity
          return (aTime - bTime) * dir
        }
        default:
          return 0
      }
    })
    return arr
  }, [filtered, sortCol, sortDir])

  // Paginate
  const totalPages = Math.max(1, Math.ceil(sorted.length / rowsPerPage))
  const paginated = sorted.slice(page * rowsPerPage, (page + 1) * rowsPerPage)
  const rangeStart = sorted.length === 0 ? 0 : page * rowsPerPage + 1
  const rangeEnd = Math.min((page + 1) * rowsPerPage, sorted.length)

  function handleSort(col: SortColumn) {
    if (sortCol === col) {
      setSortDir(d => (d === 'asc' ? 'desc' : 'asc'))
    } else {
      setSortCol(col)
      setSortDir('asc')
    }
  }

  function handleFilterChange() {
    setPage(0)
  }

  function SortIcon({ col }: { col: SortColumn }) {
    if (sortCol !== col) return null
    return sortDir === 'asc'
      ? <ArrowUp className="inline h-3 w-3 ml-0.5" />
      : <ArrowDown className="inline h-3 w-3 ml-0.5" />
  }

  return (
    <div className="flex gap-0 h-full">
      {/* Left sidebar */}
      <aside className="w-[220px] shrink-0 border-r border-border pr-4 mr-4 space-y-5 overflow-y-auto">
        <div className="flex items-center justify-between">
          <span className="text-xs font-semibold uppercase tracking-wide text-muted-foreground">Quick Filters</span>
          {hasFilters && (
            <button
              onClick={clearFilters}
              className="text-[11px] text-blue-600 hover:text-blue-700 dark:text-blue-400 dark:hover:text-blue-300"
            >
              Clear all
            </button>
          )}
        </div>

        {/* Category */}
        <div>
          <h3 className="text-xs font-semibold uppercase tracking-wide text-foreground mb-2">Category</h3>
          <div className="space-y-1">
            {SIDEBAR_CATEGORIES.map(cat => (
              <label key={cat} className="flex items-center gap-2 text-xs cursor-pointer group">
                <input
                  type="checkbox"
                  checked={selectedCategories.has(cat)}
                  onChange={() => {
                    setSelectedCategories(s => toggleSet(s, cat))
                    handleFilterChange()
                  }}
                  className="rounded-none accent-foreground"
                />
                <span className="text-foreground group-hover:text-foreground/80 flex-1">{cat}</span>
                <span className="text-muted-foreground tabular-nums">{categoryCounts[cat] ?? 0}</span>
              </label>
            ))}
          </div>
        </div>

        {/* Provider */}
        <div>
          <h3 className="text-xs font-semibold uppercase tracking-wide text-foreground mb-2">Provider</h3>
          <div className="space-y-1">
            {SIDEBAR_PROVIDERS.map(prov => (
              <label key={prov} className="flex items-center gap-2 text-xs cursor-pointer group">
                <input
                  type="checkbox"
                  checked={selectedProviders.has(prov)}
                  onChange={() => {
                    setSelectedProviders(s => toggleSet(s, prov))
                    handleFilterChange()
                  }}
                  className="rounded-none accent-foreground"
                />
                <span className="text-foreground group-hover:text-foreground/80 flex-1">{prov.toUpperCase()}</span>
                <span className="text-muted-foreground tabular-nums">{providerCounts[prov] ?? 0}</span>
              </label>
            ))}
          </div>
        </div>

        {/* Status */}
        <div>
          <h3 className="text-xs font-semibold uppercase tracking-wide text-foreground mb-2">Status</h3>
          <div className="space-y-1">
            {SIDEBAR_STATUSES.map(st => (
              <label key={st} className="flex items-center gap-2 text-xs cursor-pointer group">
                <input
                  type="checkbox"
                  checked={selectedStatuses.has(st)}
                  onChange={() => {
                    setSelectedStatuses(s => toggleSet(s, st))
                    handleFilterChange()
                  }}
                  className="rounded-none accent-foreground"
                />
                <span className="text-foreground group-hover:text-foreground/80 flex-1">{STATUS_LABELS[st] ?? st}</span>
                <span className="text-muted-foreground tabular-nums">{statusCounts[st] ?? 0}</span>
              </label>
            ))}
          </div>
        </div>
      </aside>

      {/* Main content */}
      <div className="flex-1 min-w-0 space-y-4">
        {/* Top bar */}
        <div className="flex items-center justify-between">
          <div>
            <h1 className="text-xl font-semibold font-mono">Findings</h1>
            <p className="text-sm text-muted-foreground mt-0.5">{allFindings.length} total findings</p>
          </div>
          <div className="flex items-center gap-3">
            <div className="flex gap-1.5">
              {(['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'] as const).map(sev => (
                <Badge key={sev} variant="outline" className={`text-[10px] px-1.5 py-0 rounded-none ${SEVERITY_COLORS[sev]}`}>
                  {sev} {severityCounts[sev] ?? 0}
                </Badge>
              ))}
            </div>
            <Button
              variant="outline"
              size="sm"
              onClick={() => exportCSV(sorted)}
              className="gap-1.5"
            >
              <Download className="h-3.5 w-3.5" />
              Export
            </Button>
          </div>
        </div>

        {/* Severity tabs */}
        <div className="flex items-center gap-1">
          {SEVERITY_TABS.map(tab => (
            <button
              key={tab}
              onClick={() => { setSeverityTab(tab); setPage(0) }}
              className={`px-3 py-1 text-xs rounded-none font-medium transition-colors ${
                severityTab === tab
                  ? 'bg-foreground text-background'
                  : 'bg-muted text-muted-foreground hover:bg-muted/80'
              }`}
            >
              {tab}
            </button>
          ))}
          {filtered.length !== allFindings.length && (
            <span className="text-xs text-muted-foreground ml-3">{filtered.length} matching</span>
          )}
        </div>

        {/* Table */}
        {isLoading && (
          <p className="text-sm text-muted-foreground py-8">Loading findings...</p>
        )}
        {!isLoading && sorted.length === 0 && (
          <div className="flex flex-col items-center justify-center py-16 text-muted-foreground">
            <X className="h-8 w-8 mb-2 opacity-40" />
            <p className="text-sm">No findings match the selected filters.</p>
            {hasFilters && (
              <button onClick={clearFilters} className="text-xs text-blue-600 dark:text-blue-400 mt-1 hover:underline">
                Clear all filters
              </button>
            )}
          </div>
        )}
        {!isLoading && sorted.length > 0 && (
          <>
            <Table>
              <TableHeader>
                <TableRow className="bg-muted/30">
                  <TableHead className="cursor-pointer select-none w-[100px]" onClick={() => handleSort('severity')}>
                    Severity <SortIcon col="severity" />
                  </TableHead>
                  <TableHead className="cursor-pointer select-none min-w-[240px]" onClick={() => handleSort('title')}>
                    Title <SortIcon col="title" />
                  </TableHead>
                  <TableHead className="cursor-pointer select-none w-[140px]" onClick={() => handleSort('category')}>
                    Category <SortIcon col="category" />
                  </TableHead>
                  <TableHead className="cursor-pointer select-none w-[80px]" onClick={() => handleSort('provider')}>
                    Provider <SortIcon col="provider" />
                  </TableHead>
                  <TableHead className="cursor-pointer select-none w-[160px]" onClick={() => handleSort('resource')}>
                    Resource <SortIcon col="resource" />
                  </TableHead>
                  <TableHead className="cursor-pointer select-none w-[120px]" onClick={() => handleSort('region')}>
                    Region <SortIcon col="region" />
                  </TableHead>
                  <TableHead className="cursor-pointer select-none w-[110px]" onClick={() => handleSort('status')}>
                    Status <SortIcon col="status" />
                  </TableHead>
                  <TableHead className="cursor-pointer select-none w-[100px]" onClick={() => handleSort('sla')}>
                    SLA <SortIcon col="sla" />
                  </TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {paginated.map(f => (
                  <TableRow
                    key={f.id}
                    className="cursor-pointer"
                    onClick={() => navigate(`/ops/findings/${f.id}`)}
                  >
                    <TableCell>
                      <SeverityBadge severity={f.severity} size="xs" />
                    </TableCell>
                    <TableCell>
                      <div className="flex items-center gap-2">
                        <span className="text-sm font-medium text-foreground hover:underline truncate max-w-[320px]">
                          {f.title}
                        </span>
                        {f.auto_remediatable && (
                          <Badge variant="outline" className="text-[9px] px-1 py-0 rounded-none bg-green-100 text-green-700 border-green-300 dark:bg-green-900/30 dark:text-green-300 dark:border-green-800 shrink-0">
                            AUTO
                          </Badge>
                        )}
                      </div>
                    </TableCell>
                    <TableCell>
                      <Badge variant="outline" className={`text-[10px] px-1.5 py-0 rounded-none ${CATEGORY_COLORS[f.category] ?? ''}`}>
                        {f.category}
                      </Badge>
                    </TableCell>
                    <TableCell className="text-xs font-mono uppercase text-muted-foreground">
                      {f.cloud_provider.toUpperCase()}
                    </TableCell>
                    <TableCell className="text-xs text-muted-foreground truncate max-w-[160px]">
                      {f.resource_name}
                    </TableCell>
                    <TableCell className="text-xs text-muted-foreground font-mono">
                      {f.region}
                    </TableCell>
                    <TableCell>
                      <Badge variant="outline" className={`text-[10px] px-1.5 py-0 rounded-none ${WORKFLOW_COLORS[f.workflow_status] ?? ''}`}>
                        {formatWorkflowStatus(f.workflow_status)}
                      </Badge>
                    </TableCell>
                    <TableCell>
                      <SLACountdown dueDate={f.due_date} slaBreach={f.sla_breach_date} />
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>

            {/* Pagination footer */}
            <div className="flex items-center justify-between pt-2 border-t border-border">
              <span className="text-xs text-muted-foreground">
                {rangeStart}-{rangeEnd} of {sorted.length}
              </span>

              <div className="flex items-center gap-2">
                <span className="text-xs text-muted-foreground">Rows per page</span>
                <Select
                  value={String(rowsPerPage)}
                  onValueChange={v => { setRowsPerPage(Number(v)); setPage(0) }}
                >
                  <SelectTrigger className="h-7 w-16 text-xs">
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value="10">10</SelectItem>
                    <SelectItem value="25">25</SelectItem>
                    <SelectItem value="50">50</SelectItem>
                  </SelectContent>
                </Select>
              </div>

              <div className="flex items-center gap-1">
                <Button
                  variant="outline"
                  size="icon-xs"
                  disabled={page === 0}
                  onClick={() => setPage(p => p - 1)}
                >
                  <ChevronLeft className="h-3.5 w-3.5" />
                </Button>
                <span className="text-xs text-muted-foreground px-2">
                  {page + 1} / {totalPages}
                </span>
                <Button
                  variant="outline"
                  size="icon-xs"
                  disabled={page >= totalPages - 1}
                  onClick={() => setPage(p => p + 1)}
                >
                  <ChevronRight className="h-3.5 w-3.5" />
                </Button>
              </div>
            </div>
          </>
        )}
      </div>
    </div>
  )
}
