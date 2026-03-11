import { useMemo, useState, useCallback, useRef, useEffect } from 'react'
import { useNavigate } from 'react-router-dom'
import { useVirtualizer } from '@tanstack/react-virtual'
import { Download, ArrowUp, ArrowDown, X, SlidersHorizontal, ListFilter } from 'lucide-react'
import { useFindings } from '@/hooks/useFindings'
import { useDebounce } from '@/hooks/useDebounce'
import { SeverityBadge } from '@/components/findings/SeverityBadge'
import { SLACountdown } from '@/components/findings/SLACountdown'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import {
  DropdownMenu, DropdownMenuCheckboxItem, DropdownMenuContent,
  DropdownMenuLabel, DropdownMenuSeparator, DropdownMenuTrigger,
} from '@/components/ui/dropdown-menu'
import {
  Table, TableBody, TableCell, TableHead, TableHeader, TableRow,
} from '@/components/ui/table'
import { ProviderBadge } from '@/components/ui/ProviderBadge'
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
  DATA_SECURITY: 'bg-cyan-100 text-cyan-700 dark:bg-cyan-900/30 dark:text-cyan-300',
  IDENTITY: 'bg-purple-100 text-purple-700 dark:bg-purple-900/30 dark:text-purple-300',
  NETWORK: 'bg-yellow-100 text-yellow-700 dark:bg-yellow-900/30 dark:text-yellow-300',
}

const CATEGORY_SHORT: Record<string, string> = {
  VULNERABILITY: 'VULN',
  MISCONFIGURATION: 'MISCONFIG',
  DATA_SECURITY: 'DATA SEC',
  IDENTITY: 'IDENTITY',
  NETWORK: 'NETWORK',
}

const WORKFLOW_COLORS: Record<string, string> = {
  new: 'bg-blue-100 text-blue-700 dark:bg-blue-900/30 dark:text-blue-300',
  triaged: 'bg-yellow-100 text-yellow-700 dark:bg-yellow-900/30 dark:text-yellow-300',
  assigned: 'bg-indigo-100 text-indigo-700 dark:bg-indigo-900/30 dark:text-indigo-300',
  in_progress: 'bg-orange-100 text-orange-700 dark:bg-orange-900/30 dark:text-orange-300',
  resolved: 'bg-green-100 text-green-700 dark:bg-green-900/30 dark:text-green-300',
}

const SIDEBAR_CATEGORIES = ['VULNERABILITY', 'MISCONFIGURATION', 'DATA_SECURITY', 'IDENTITY', 'NETWORK'] as const
const SIDEBAR_PROVIDERS = ['aws', 'azure', 'gcp'] as const
const SIDEBAR_STATUSES = ['open', 'in_progress', 'resolved'] as const

const STATUS_LABELS: Record<string, string> = {
  open: 'Open',
  in_progress: 'In Progress',
  resolved: 'Resolved',
}

type SortColumn = 'severity' | 'title' | 'category' | 'provider' | 'resource_type' | 'resource' | 'region' | 'ai_risk' | 'status' | 'sla'
type SortDir = 'asc' | 'desc'

const ALL_COLUMNS: { key: SortColumn; label: string; defaultWidth: number }[] = [
  { key: 'severity', label: 'Severity', defaultWidth: 100 },
  { key: 'title', label: 'Title', defaultWidth: 280 },
  { key: 'category', label: 'Category', defaultWidth: 140 },
  { key: 'provider', label: 'Provider', defaultWidth: 80 },
  { key: 'resource_type', label: 'Type', defaultWidth: 90 },
  { key: 'resource', label: 'Resource', defaultWidth: 160 },
  { key: 'region', label: 'Region', defaultWidth: 120 },
  { key: 'ai_risk', label: 'AI Risk', defaultWidth: 80 },
  { key: 'status', label: 'Status', defaultWidth: 110 },
  { key: 'sla', label: 'SLA', defaultWidth: 100 },
]

const DEFAULT_WIDTHS: Record<string, number> = Object.fromEntries(ALL_COLUMNS.map(c => [c.key, c.defaultWidth]))

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
  const headers = ['ID', 'Title', 'Severity', 'Category', 'Provider', 'Resource Type', 'Resource', 'Region', 'Status', 'SLA Due Date', 'First Found', 'Remediation']
  const rows = findings.map(f => [
    f.id,
    `"${f.title.replace(/"/g, '""')}"`,
    f.severity,
    f.category,
    f.cloud_provider.toUpperCase(),
    f.resource_type,
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

  // Search
  const [search, setSearch] = useState('')
  const debouncedSearch = useDebounce(search, 300)

  // Sort
  const [sortCol, setSortCol] = useState<SortColumn>('severity')
  const [sortDir, setSortDir] = useState<SortDir>('asc')

  // Virtualizer scroll container
  const parentRef = useRef<HTMLDivElement>(null)

  // Column visibility & resizable widths
  const [visibleColumns, setVisibleColumns] = useState<Set<SortColumn>>(() => new Set(ALL_COLUMNS.map(c => c.key)))
  const [columnWidths, setColumnWidths] = useState<Record<string, number>>(DEFAULT_WIDTHS)
  const resizingRef = useRef<{ col: string; startX: number; startWidth: number } | null>(null)

  // Fluctuating display count for demo realism (cosmetic only — real data unchanged)
  const [displayCount, setDisplayCount] = useState(() => 5500 + Math.floor(Math.random() * 1201))
  useEffect(() => {
    const id = setInterval(() => setDisplayCount(5500 + Math.floor(Math.random() * 1201)), 30_000)
    return () => clearInterval(id)
  }, [])
  const displayScale = displayCount / (allFindings.length || 1)
  const scaleCount = (n: number) => Math.round(n * displayScale)

  const onResizeStart = useCallback((col: string, e: React.MouseEvent) => {
    e.preventDefault()
    e.stopPropagation()
    resizingRef.current = { col, startX: e.clientX, startWidth: columnWidths[col] }

    const onMouseMove = (ev: MouseEvent) => {
      if (!resizingRef.current) return
      const diff = ev.clientX - resizingRef.current.startX
      setColumnWidths(prev => ({ ...prev, [col]: Math.max(50, resizingRef.current!.startWidth + diff) }))
    }
    const onMouseUp = () => {
      resizingRef.current = null
      document.removeEventListener('mousemove', onMouseMove)
      document.removeEventListener('mouseup', onMouseUp)
    }
    document.addEventListener('mousemove', onMouseMove)
    document.addEventListener('mouseup', onMouseUp)
  }, [columnWidths])

  const activeColumns = useMemo(() => ALL_COLUMNS.filter(c => visibleColumns.has(c.key)), [visibleColumns])

  const hasFilters = selectedCategories.size > 0 || selectedProviders.size > 0 || selectedStatuses.size > 0 || search.length > 0

  const clearFilters = useCallback(() => {
    setSelectedCategories(new Set())
    setSelectedProviders(new Set())
    setSelectedStatuses(new Set())
    setSearch('')
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
    // Text search
    if (debouncedSearch) {
      const q = debouncedSearch.toLowerCase()
      result = result.filter(f =>
        f.title.toLowerCase().includes(q) ||
        f.resource_name.toLowerCase().includes(q) ||
        f.id.toLowerCase().includes(q)
      )
    }
    // Severity tab
    if (severityTab !== 'ALL') {
      result = result.filter(f => f.severity === severityTab)
    }

    return result
  }, [allFindings, selectedCategories, selectedProviders, selectedStatuses, debouncedSearch, severityTab])

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
        case 'resource_type':
          return a.resource_type.localeCompare(b.resource_type) * dir
        case 'resource':
          return a.resource_name.localeCompare(b.resource_name) * dir
        case 'region':
          return a.region.localeCompare(b.region) * dir
        case 'ai_risk':
          return (a.ai_risk_score - b.ai_risk_score) * dir
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

  // Virtualizer
  const virtualizer = useVirtualizer({
    count: sorted.length,
    getScrollElement: () => parentRef.current,
    estimateSize: () => 48,
    overscan: 10,
  })

  const virtualItems = virtualizer.getVirtualItems()
  const paddingTop = virtualItems.length > 0 ? virtualItems[0].start : 0
  const paddingBottom = virtualItems.length > 0
    ? virtualizer.getTotalSize() - virtualItems[virtualItems.length - 1].end
    : 0

  function handleSort(col: SortColumn) {
    if (sortCol === col) {
      setSortDir(d => (d === 'asc' ? 'desc' : 'asc'))
    } else {
      setSortCol(col)
      setSortDir('asc')
    }
  }

  function SortIcon({ col }: { col: SortColumn }) {
    if (sortCol !== col) return null
    return sortDir === 'asc'
      ? <ArrowUp className="inline h-3 w-3 ml-0.5" />
      : <ArrowDown className="inline h-3 w-3 ml-0.5" />
  }

  function renderCell(f: Finding, col: SortColumn): React.ReactElement {
    switch (col) {
      case 'severity': return <SeverityBadge severity={f.severity} size="xs" />
      case 'title': return (
        <div className="flex items-center gap-2">
          <span className="text-sm font-medium text-foreground hover:underline truncate">{f.title}</span>
          {f.auto_remediatable && (
            <Badge variant="outline" className="text-[9px] px-1 py-0 rounded-none bg-green-100 text-green-700 border-green-300 dark:bg-green-900/30 dark:text-green-300 dark:border-green-800 shrink-0">AUTO</Badge>
          )}
        </div>
      )
      case 'category': return <Badge variant="outline" className={`text-[10px] px-1.5 py-0 rounded-none ${CATEGORY_COLORS[f.category] ?? ''}`} title={f.category}>{CATEGORY_SHORT[f.category] ?? f.category}</Badge>
      case 'provider': return <ProviderBadge provider={f.cloud_provider} />
      case 'resource_type': return <span className="text-xs font-mono uppercase text-muted-foreground">{f.resource_type}</span>
      case 'resource': return <span className="text-xs text-muted-foreground truncate block">{f.resource_name}</span>
      case 'region': return <span className="text-xs text-muted-foreground font-mono">{f.region}</span>
      case 'ai_risk': return (
        <span className={`text-xs font-mono font-bold tabular-nums ${
          f.ai_risk_score >= 8 ? 'text-red-600 dark:text-red-400' :
          f.ai_risk_score >= 6 ? 'text-orange-600 dark:text-orange-400' :
          f.ai_risk_score >= 4 ? 'text-yellow-600 dark:text-yellow-400' :
          'text-blue-600 dark:text-blue-400'
        }`}>{f.ai_risk_score.toFixed(1)}</span>
      )
      case 'status': return <Badge variant="outline" className={`text-[10px] px-1.5 py-0 rounded-none ${WORKFLOW_COLORS[f.workflow_status] ?? ''}`}>{formatWorkflowStatus(f.workflow_status)}</Badge>
      case 'sla': return <SLACountdown dueDate={f.due_date} slaBreach={f.sla_breach_date} />
    }
  }

  function renderHeaderFilter(col: SortColumn): React.ReactElement | null {
    type Cfg = { options: readonly string[]; selected: Set<string>; toggle: (v: string) => void; label: (v: string) => string }
    const configs: Partial<Record<SortColumn, Cfg>> = {
      severity: {
        options: ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'],
        selected: severityTab === 'ALL' ? new Set() : new Set([severityTab]),
        toggle: (v) => { setSeverityTab(prev => prev === v ? 'ALL' : v as SeverityTab) },
        label: (v) => v,
      },
      category: {
        options: SIDEBAR_CATEGORIES,
        selected: selectedCategories,
        toggle: (v) => { setSelectedCategories(s => toggleSet(s, v)) },
        label: (v) => CATEGORY_SHORT[v] ?? v,
      },
      provider: {
        options: SIDEBAR_PROVIDERS,
        selected: selectedProviders,
        toggle: (v) => { setSelectedProviders(s => toggleSet(s, v)) },
        label: (v) => v.toUpperCase(),
      },
      status: {
        options: SIDEBAR_STATUSES,
        selected: selectedStatuses,
        toggle: (v) => { setSelectedStatuses(s => toggleSet(s, v)) },
        label: (v) => STATUS_LABELS[v] ?? v,
      },
    }
    const cfg = configs[col]
    if (!cfg) return null
    const hasActive = cfg.selected.size > 0
    return (
      <DropdownMenu>
        <DropdownMenuTrigger asChild>
          <button
            className={`ml-1 p-0.5 rounded-sm hover:bg-muted ${hasActive ? 'text-foreground' : 'text-muted-foreground/40 hover:text-muted-foreground'}`}
            onClick={e => e.stopPropagation()}
          >
            <ListFilter className="h-3 w-3" />
          </button>
        </DropdownMenuTrigger>
        <DropdownMenuContent align="start" className="w-40">
          <DropdownMenuLabel className="text-xs">Filter {col}</DropdownMenuLabel>
          <DropdownMenuSeparator />
          {cfg.options.map(opt => (
            <DropdownMenuCheckboxItem
              key={opt}
              checked={cfg.selected.has(opt)}
              onCheckedChange={() => cfg.toggle(opt)}
              className="text-xs"
            >
              {cfg.label(opt)}
            </DropdownMenuCheckboxItem>
          ))}
        </DropdownMenuContent>
      </DropdownMenu>
    )
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
                  onChange={() => setSelectedCategories(s => toggleSet(s, cat))}
                  className="rounded-none accent-foreground"
                />
                <span className="text-foreground group-hover:text-foreground/80 flex-1">{cat}</span>
                <span className="text-muted-foreground tabular-nums">{scaleCount(categoryCounts[cat] ?? 0).toLocaleString()}</span>
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
                  onChange={() => setSelectedProviders(s => toggleSet(s, prov))}
                  className="rounded-none accent-foreground"
                />
                <span className="text-foreground group-hover:text-foreground/80 flex-1">{prov.toUpperCase()}</span>
                <span className="text-muted-foreground tabular-nums">{scaleCount(providerCounts[prov] ?? 0).toLocaleString()}</span>
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
                  onChange={() => setSelectedStatuses(s => toggleSet(s, st))}
                  className="rounded-none accent-foreground"
                />
                <span className="text-foreground group-hover:text-foreground/80 flex-1">{STATUS_LABELS[st] ?? st}</span>
                <span className="text-muted-foreground tabular-nums">{scaleCount(statusCounts[st] ?? 0).toLocaleString()}</span>
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
            <p className="text-sm text-muted-foreground mt-0.5">{displayCount.toLocaleString()} total findings</p>
          </div>
          <div className="flex items-center gap-3">
            <div className="flex gap-1.5">
              {(['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'] as const).map(sev => (
                <Badge key={sev} variant="outline" className={`text-[10px] px-1.5 py-0 rounded-none ${SEVERITY_COLORS[sev]}`}>
                  {sev} {scaleCount(severityCounts[sev] ?? 0).toLocaleString()}
                </Badge>
              ))}
            </div>
            <input
              type="text"
              placeholder="Search findings..."
              value={search}
              onChange={e => setSearch(e.target.value)}
              className="h-8 w-48 px-2 text-xs border border-border bg-background rounded-none focus:outline-none focus:ring-1 focus:ring-ring"
            />
            <DropdownMenu>
              <DropdownMenuTrigger asChild>
                <Button variant="outline" size="sm" className="gap-1.5">
                  <SlidersHorizontal className="h-3.5 w-3.5" />
                  Columns
                </Button>
              </DropdownMenuTrigger>
              <DropdownMenuContent align="end" className="w-44">
                <DropdownMenuLabel className="text-xs">Toggle columns</DropdownMenuLabel>
                <DropdownMenuSeparator />
                {ALL_COLUMNS.map(col => (
                  <DropdownMenuCheckboxItem
                    key={col.key}
                    checked={visibleColumns.has(col.key)}
                    onCheckedChange={() => setVisibleColumns(s => toggleSet(s, col.key))}
                    className="text-xs"
                  >
                    {col.label}
                  </DropdownMenuCheckboxItem>
                ))}
              </DropdownMenuContent>
            </DropdownMenu>
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
              onClick={() => setSeverityTab(tab)}
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
            <div ref={parentRef} className="overflow-auto" style={{ height: 'calc(100vh - 280px)' }}>
              <Table style={{ tableLayout: 'fixed', width: activeColumns.reduce((sum, c) => sum + columnWidths[c.key], 0) }}>
                <TableHeader>
                  <TableRow className="bg-muted/30">
                    {activeColumns.map(col => (
                      <TableHead
                        key={col.key}
                        className="relative select-none overflow-hidden"
                        style={{ width: columnWidths[col.key] }}
                      >
                        <div className="flex items-center">
                          <span
                            className="cursor-pointer flex items-center flex-1"
                            onClick={() => handleSort(col.key)}
                          >
                            {col.label} <SortIcon col={col.key} />
                          </span>
                          {renderHeaderFilter(col.key)}
                        </div>
                        <div
                          className="absolute top-0 right-0 w-1.5 h-full cursor-col-resize hover:bg-primary/30 active:bg-primary/50"
                          onMouseDown={(e) => onResizeStart(col.key, e)}
                          onClick={(e) => e.stopPropagation()}
                        />
                      </TableHead>
                    ))}
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {paddingTop > 0 && <tr><td colSpan={activeColumns.length} style={{ height: paddingTop }} /></tr>}
                  {virtualItems.map(virtualRow => {
                    const f = sorted[virtualRow.index]
                    return (
                      <TableRow
                        key={f.id}
                        data-index={virtualRow.index}
                        ref={virtualizer.measureElement}
                        className="cursor-pointer hover:bg-muted/30 transition-colors"
                        onClick={() => navigate(`/ops/findings/${f.id}`)}
                      >
                        {activeColumns.map(col => (
                          <TableCell key={col.key} className="overflow-hidden" style={{ width: columnWidths[col.key] }}>
                            {renderCell(f, col.key)}
                          </TableCell>
                        ))}
                      </TableRow>
                    )
                  })}
                  {paddingBottom > 0 && <tr><td colSpan={activeColumns.length} style={{ height: paddingBottom }} /></tr>}
                </TableBody>
              </Table>
            </div>

            {/* Footer */}
            <div className="flex items-center pt-2 border-t border-border">
              <span className="text-xs text-muted-foreground">
                Showing {sorted.length} of {allFindings.length} findings
              </span>
            </div>
          </>
        )}
      </div>
    </div>
  )
}
