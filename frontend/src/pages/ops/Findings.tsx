import { useMemo, useState, useCallback, useRef, useDeferredValue, useEffect } from 'react'
import { useNavigate } from 'react-router-dom'
import { useVirtualizer } from '@tanstack/react-virtual'
import { Download, ArrowUp, ArrowDown, X, SlidersHorizontal, ListFilter, ChevronDown, ChevronRight, ChevronLeft, ChevronsLeft, ChevronsRight } from 'lucide-react'
import { useFindings, useFindingsStats } from '@/hooks/useFindings'
import FindingDetail from '@/pages/ops/FindingDetail'
import { useMediaQuery } from '@/hooks/useMediaQuery'
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
import { SEVERITY_COLORS } from '@/lib/severity'
import { exportCSV } from '@/lib/export-csv'
import { NLQueryBar } from '@/components/ops/NLQueryBar'
import { findingMatchesNLQExclusion, hasNLQExclusions } from '@/lib/nlq-filters'
import type { NLQExclusions, NLQFilters } from '@/types/nlq'

const SEVERITY_ORDER: Record<string, number> = { CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3 }

const SEVERITY_TABS = ['ALL', 'CRITICAL', 'HIGH', 'MEDIUM', 'LOW'] as const
type SeverityTab = (typeof SEVERITY_TABS)[number]


const CATEGORY_COLORS: Record<string, string> = {
  VULNERABILITY: 'bg-red-100 text-red-700 dark:bg-red-900/30 dark:text-red-300',
  MISCONFIGURATION: 'bg-orange-100 text-orange-700 dark:bg-orange-900/30 dark:text-orange-300',
  DATA_PROTECTION: 'bg-cyan-100 text-cyan-700 dark:bg-cyan-900/30 dark:text-cyan-300',
  IDENTITY: 'bg-purple-100 text-purple-700 dark:bg-purple-900/30 dark:text-purple-300',
  NETWORK: 'bg-yellow-100 text-yellow-700 dark:bg-yellow-900/30 dark:text-yellow-300',
}

const CATEGORY_SHORT: Record<string, string> = {
  VULNERABILITY: 'VULN',
  MISCONFIGURATION: 'MISCONFIG',
  DATA_PROTECTION: 'DATA PROT',
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

const SIDEBAR_CATEGORIES = ['VULNERABILITY', 'MISCONFIGURATION', 'DATA_PROTECTION', 'IDENTITY', 'NETWORK'] as const
const SIDEBAR_PROVIDERS = ['aws', 'azure', 'gcp'] as const
const SIDEBAR_STATUSES = ['open', 'in_progress', 'resolved'] as const

const STATUS_LABELS: Record<string, string> = {
  open: 'Open',
  in_progress: 'In Progress',
  resolved: 'Resolved',
}

type SortColumn = 'severity' | 'title' | 'category' | 'provider' | 'resource_type' | 'resource' | 'resource_id' | 'region' | 'ai_risk' | 'status' | 'sla' | 'first_found'
type SortDir = 'asc' | 'desc'

function relativeTime(dateStr: string): string {
  const diff = Date.now() - new Date(dateStr).getTime()
  const mins = Math.floor(diff / 60000)
  if (mins < 60) return `${mins}m ago`
  const hrs = Math.floor(mins / 60)
  if (hrs < 24) return `${hrs}h ago`
  const days = Math.floor(hrs / 24)
  if (days < 30) return `${days}d ago`
  const months = Math.floor(days / 30)
  if (months < 12) return `${months}mo ago`
  return `${Math.floor(months / 12)}y ago`
}

const ALL_COLUMNS: { key: SortColumn; label: string; defaultWidth: number }[] = [
  { key: 'severity', label: 'Severity', defaultWidth: 100 },
  { key: 'title', label: 'Title', defaultWidth: 280 },
  { key: 'category', label: 'Category', defaultWidth: 140 },
  { key: 'provider', label: 'Provider', defaultWidth: 80 },
  { key: 'resource_type', label: 'Type', defaultWidth: 90 },
  { key: 'resource', label: 'Resource', defaultWidth: 160 },
  { key: 'resource_id', label: 'Resource ID', defaultWidth: 140 },
  { key: 'region', label: 'Region', defaultWidth: 120 },
  { key: 'ai_risk', label: 'AI Risk', defaultWidth: 80 },
  { key: 'status', label: 'Status', defaultWidth: 110 },
  { key: 'sla', label: 'SLA', defaultWidth: 100 },
  { key: 'first_found', label: 'First Observed', defaultWidth: 110 },
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

export default function Findings() {
  const navigate = useNavigate()

  // Sidebar filters
  const [selectedCategories, setSelectedCategories] = useState<Set<string>>(new Set())
  const [selectedProviders, setSelectedProviders] = useState<Set<string>>(new Set())
  const [selectedStatuses, setSelectedStatuses] = useState<Set<string>>(new Set())
  const [excludedFilters, setExcludedFilters] = useState<NLQExclusions>({})

  // Metric card filters
  const [filterSLABreached, setFilterSLABreached] = useState(false)
  const [filterAutoRem, setFilterAutoRem] = useState(false)

  // Severity tab
  const [severityTab, setSeverityTab] = useState<SeverityTab>('ALL')

  // Search
  const [search, setSearch] = useState('')
  const debouncedSearch = useDebounce(search, 300)
  const deferredSearch = useDeferredValue(debouncedSearch)

  // Sort
  const [sortCol, setSortCol] = useState<SortColumn>('severity')
  const [sortDir, setSortDir] = useState<SortDir>('asc')

  // Virtualizer scroll container
  const parentRef = useRef<HTMLDivElement>(null)

  // Sidebar collapse
  const [sidebarCollapsed, setSidebarCollapsed] = useState(true)

  // Preview panel
  const [previewId, setPreviewId] = useState<string | null>(null)
  const isSmUp = useMediaQuery('(min-width: 640px)')
  const isDesktop = useMediaQuery('(min-width: 1024px)')
  const isMobile = !isSmUp

  // Group by
  const [groupBy, setGroupBy] = useState<'none' | 'rule' | 'resource' | 'provider' | 'category'>('none')
  const [collapsedGroups, setCollapsedGroups] = useState<Set<string>>(new Set())

  // Pagination
  const [page, setPage] = useState(1)
  const [pageSize, setPageSize] = useState(100)

  // Column visibility & resizable widths
  const [visibleColumns, setVisibleColumns] = useState<Set<SortColumn>>(() => {
    const defaults = new Set(ALL_COLUMNS.map(c => c.key))
    defaults.delete('resource_id') // verbose — opt-in via column picker
    return defaults
  })
  const [columnWidths, setColumnWidths] = useState<Record<string, number>>(DEFAULT_WIDTHS)
  const resizingRef = useRef<{ col: string; startX: number; startWidth: number } | null>(null)

  const serverSortField = useMemo(() => {
    switch (sortCol) {
      case 'severity':
        return 'severity'
      case 'title':
        return 'title'
      case 'status':
        return 'status'
      case 'ai_risk':
        return 'ai_risk'
      case 'first_found':
        return 'first_found_at'
      default:
        return undefined
    }
  }, [sortCol])
  const singleProviderFilter = selectedProviders.size === 1 ? Array.from(selectedProviders)[0] : undefined
  const singleStatusFilter = selectedStatuses.size === 1 ? Array.from(selectedStatuses)[0] : undefined
  const severityFilter = severityTab !== 'ALL' ? severityTab : undefined
  const { data: allFindings = [], isLoading, total: pageTotal, totalPages: apiTotalPages } = useFindings({
    page,
    perPage: pageSize,
    sort: serverSortField,
    order: sortDir,
    severity: severityFilter,
    provider: singleProviderFilter,
    status: singleStatusFilter,
  })
  const { data: stats } = useFindingsStats()

  const displayCount = stats?.total ?? pageTotal ?? allFindings.length

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

  // Compact columns for list-detail split (hide verbose columns when detail panel is open)
  const COMPACT_KEYS: Set<SortColumn> = useMemo(() => new Set(['severity', 'title', 'provider', 'status'] as SortColumn[]), [])
  const compactColumns = useMemo(() => ALL_COLUMNS.filter(c => COMPACT_KEYS.has(c.key)), [COMPACT_KEYS])
  const MOBILE_KEYS: Set<SortColumn> = useMemo(() => new Set(['severity', 'title', 'status'] as SortColumn[]), [])
  const mobileColumns = useMemo(() => ALL_COLUMNS.filter(c => MOBILE_KEYS.has(c.key)), [MOBILE_KEYS])
  const mobileColumnWidths = useMemo<Record<SortColumn, number>>(() => ({
    severity: 72,
    title: 204,
    status: 104,
    category: DEFAULT_WIDTHS.category,
    provider: DEFAULT_WIDTHS.provider,
    resource_type: DEFAULT_WIDTHS.resource_type,
    resource: DEFAULT_WIDTHS.resource,
    resource_id: DEFAULT_WIDTHS.resource_id,
    region: DEFAULT_WIDTHS.region,
    ai_risk: DEFAULT_WIDTHS.ai_risk,
    sla: DEFAULT_WIDTHS.sla,
    first_found: DEFAULT_WIDTHS.first_found,
  }), [])

  const hasExcludedFilters = useMemo(() => hasNLQExclusions(excludedFilters), [excludedFilters])
  const hasFilters = selectedCategories.size > 0 || selectedProviders.size > 0 || selectedStatuses.size > 0 || search.length > 0 || filterSLABreached || filterAutoRem || hasExcludedFilters

  const clearFilters = useCallback(() => {
    setSelectedCategories(new Set())
    setSelectedProviders(new Set())
    setSelectedStatuses(new Set())
    setExcludedFilters({})
    setSearch('')
    setFilterSLABreached(false)
    setFilterAutoRem(false)
  }, [])

  // Counts for sidebar (computed from full dataset before any sidebar filter)
  const categoryCounts = useMemo(() => {
    if (stats?.by_category) return stats.by_category
    const m: Record<string, number> = {}
    for (const f of allFindings) m[f.category] = (m[f.category] ?? 0) + 1
    return m
  }, [allFindings, stats?.by_category])

  const providerCounts = useMemo(() => {
    if (stats?.by_provider) return stats.by_provider
    const m: Record<string, number> = {}
    for (const f of allFindings) m[f.cloud_provider] = (m[f.cloud_provider] ?? 0) + 1
    return m
  }, [allFindings, stats?.by_provider])

  const statusCounts = useMemo(() => {
    if (stats?.by_status) return stats.by_status
    const m: Record<string, number> = {}
    for (const f of allFindings) m[f.status] = (m[f.status] ?? 0) + 1
    return m
  }, [allFindings, stats?.by_status])

  // Base filtered: sidebar + search + severity tab (excludes metric card toggles)
  // KPI cards derive from this so clicking SLA/AutoRem doesn't zero their own counts
  const baseFiltered = useMemo(() => {
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
    // RQL exclusion filters: field!=value.
    if (hasExcludedFilters) {
      result = result.filter(f => !findingMatchesNLQExclusion(f, excludedFilters))
    }
    // Text search
    if (deferredSearch) {
      const q = deferredSearch.toLowerCase()
      result = result.filter(f =>
        f.title.toLowerCase().includes(q) ||
        f.resource_name.toLowerCase().includes(q) ||
        f.id.toLowerCase().includes(q) ||
        f.description?.toLowerCase().includes(q) ||
        f.cloud_provider?.toLowerCase().includes(q) ||
        f.category?.toLowerCase().includes(q) ||
        f.resource_type?.toLowerCase().includes(q) ||
        f.region?.toLowerCase().includes(q) ||
        f.account_name?.toLowerCase().includes(q)
      )
    }
    // Severity tab
    if (severityTab !== 'ALL') {
      result = result.filter(f => f.severity === severityTab)
    }

    return result
  }, [allFindings, selectedCategories, selectedProviders, selectedStatuses, hasExcludedFilters, excludedFilters, deferredSearch, severityTab])

  // KPI summaries (from baseFiltered — respects sidebar/search/severity but not metric toggles)
  const severityCounts = useMemo(() => {
    const m: Record<string, number> = {}
    for (const f of baseFiltered) m[f.severity] = (m[f.severity] ?? 0) + 1
    return m
  }, [baseFiltered])

  const severitySummaryCounts = useMemo(
    () => (hasFilters ? severityCounts : (stats?.by_severity ?? severityCounts)),
    [hasFilters, severityCounts, stats?.by_severity],
  )

  const slaBreachedCount = useMemo(() => {
    const now = Date.now()
    return baseFiltered.filter(f => f.sla_breach_date && new Date(f.sla_breach_date).getTime() < now).length
  }, [baseFiltered])

  const autoRemCount = useMemo(
    () => baseFiltered.filter(f => f.auto_remediatable).length,
    [baseFiltered],
  )

  // Full filter pipeline (baseFiltered + metric card toggles)
  const filtered = useMemo(() => {
    let result = baseFiltered

    // Metric card filters
    if (filterSLABreached) {
      const now = Date.now()
      result = result.filter(f => f.sla_breach_date && new Date(f.sla_breach_date).getTime() < now)
    }
    if (filterAutoRem) {
      result = result.filter(f => f.auto_remediatable)
    }

    return result
  }, [baseFiltered, filterSLABreached, filterAutoRem])

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
        case 'resource_id':
          return a.resource_id.localeCompare(b.resource_id) * dir
        case 'first_found': {
          const aFF = a.first_found_at ? new Date(a.first_found_at).getTime() : Infinity
          const bFF = b.first_found_at ? new Date(b.first_found_at).getTime() : Infinity
          return (aFF - bFF) * dir
        }
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

  // Pagination — slice sorted into current page
  const totalPages = Math.max(apiTotalPages, 1)
  const currentPage = Math.min(page, totalPages)
  const paged = sorted

  // Reset to page 1 when filter inputs change
  useEffect(() => { setPage(1) }, [selectedCategories, selectedProviders, selectedStatuses, deferredSearch, severityTab, filterSLABreached, filterAutoRem, pageSize])
  useEffect(() => {
    if (page > totalPages) setPage(totalPages)
  }, [page, totalPages])

  // Clear stale previewId when the selected finding is filtered out
  useEffect(() => {
    if (previewId && sorted.length > 0 && !sorted.some(f => f.id === previewId)) {
      setPreviewId(null)
    }
  }, [sorted, previewId])

  // Grouped data for GROUP BY view
  const groupedFindings = useMemo(() => {
    if (groupBy === 'none') return null
    const groups = new Map<string, Finding[]>()
    const keyFn = (f: Finding) => {
      switch (groupBy) {
        case 'rule': return f.canonical_rule_id || f.type
        case 'resource': return f.resource_type
        case 'provider': return f.cloud_provider.toUpperCase()
        case 'category': return f.category
      }
    }
    for (const f of sorted) {
      const key = keyFn(f)
      const arr = groups.get(key)
      if (arr) arr.push(f)
      else groups.set(key, [f])
    }
    return [...groups.entries()].sort((a, b) => b[1].length - a[1].length)
  }, [sorted, groupBy])

  // Virtualizer — operates on current page slice
  const virtualizer = useVirtualizer({
    count: paged.length,
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
      case 'resource_id': return <span className="text-xs font-mono text-muted-foreground truncate block" title={f.resource_id}>{f.resource_id}</span>
      case 'first_found': return (
        <span className="text-xs text-muted-foreground tabular-nums" title={f.first_found_at ? new Date(f.first_found_at).toLocaleString() : ''}>
          {f.first_found_at ? relativeTime(f.first_found_at) : '—'}
        </span>
      )
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
            aria-label={`Filter by ${col}`}
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
      {!sidebarCollapsed && (
      <aside className="w-[220px] shrink-0 border-r border-border pr-4 mr-4 space-y-5 overflow-y-auto" aria-label="Findings filters">
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
          <p className="text-xs font-semibold uppercase tracking-wide text-foreground mb-2">Category</p>
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
                <span className="text-muted-foreground tabular-nums">{(categoryCounts[cat] ?? 0).toLocaleString()}</span>
              </label>
            ))}
          </div>
        </div>

        {/* Provider */}
        <div>
          <p className="text-xs font-semibold uppercase tracking-wide text-foreground mb-2">Provider</p>
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
                <span className="text-muted-foreground tabular-nums">{(providerCounts[prov] ?? 0).toLocaleString()}</span>
              </label>
            ))}
          </div>
        </div>

        {/* Status */}
        <div>
          <p className="text-xs font-semibold uppercase tracking-wide text-foreground mb-2">Status</p>
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
                <span className="text-muted-foreground tabular-nums">{(statusCounts[st] ?? 0).toLocaleString()}</span>
              </label>
            ))}
          </div>
        </div>
        <button
          onClick={() => setSidebarCollapsed(true)}
          className="text-[10px] text-muted-foreground hover:text-foreground mt-2"
        >
          Collapse sidebar
        </button>
      </aside>
      )}

      {/* Main content */}
      <div className="flex-1 min-w-0 space-y-4">
        {/* NLQ bar */}
        <NLQueryBar onApplyFilters={(filters: NLQFilters) => {
          setExcludedFilters(filters.exclude ?? {})
          if (filters.severity?.length) setSeverityTab(filters.severity[0] as SeverityTab)
          if (filters.category?.length) setSelectedCategories(new Set(filters.category))
          if (filters.provider?.length) setSelectedProviders(new Set(filters.provider))
          if (filters.status?.length) setSelectedStatuses(new Set(filters.status))
          if (filters.text) setSearch(filters.text)
        }} />

        {/* Filter pills (when sidebar collapsed) */}
        {sidebarCollapsed && (
          <div className="flex items-center gap-2 flex-wrap">
            {/* Category pill */}
            <div className="flex items-center">
              <DropdownMenu>
                <DropdownMenuTrigger asChild>
                  <button className={`flex items-center gap-1 px-2.5 py-1 text-xs border transition-colors ${
                    selectedCategories.size > 0
                      ? 'border-foreground/30 bg-muted/50 font-medium'
                      : 'border-border text-muted-foreground hover:bg-muted/30'
                  }`}>
                    Category
                    {selectedCategories.size > 0 && (
                      <span className="text-[9px] bg-foreground text-background px-1">{selectedCategories.size}</span>
                    )}
                    <ChevronDown className="h-3 w-3" />
                  </button>
                </DropdownMenuTrigger>
                <DropdownMenuContent align="start" className="w-48">
                  <DropdownMenuLabel className="text-xs">Category</DropdownMenuLabel>
                  <DropdownMenuSeparator />
                  {SIDEBAR_CATEGORIES.map(cat => (
                    <DropdownMenuCheckboxItem
                      key={cat}
                      checked={selectedCategories.has(cat)}
                      onCheckedChange={() => setSelectedCategories(s => toggleSet(s, cat))}
                      className="text-xs"
                    >
                      {CATEGORY_SHORT[cat] ?? cat}
                    </DropdownMenuCheckboxItem>
                  ))}
                </DropdownMenuContent>
              </DropdownMenu>
              {selectedCategories.size > 0 && (
                <button onClick={() => setSelectedCategories(new Set())} className="p-0.5 text-muted-foreground hover:text-foreground">
                  <X className="h-3 w-3" />
                </button>
              )}
            </div>
            {/* Provider pill */}
            <div className="flex items-center">
              <DropdownMenu>
                <DropdownMenuTrigger asChild>
                  <button className={`flex items-center gap-1 px-2.5 py-1 text-xs border transition-colors ${
                    selectedProviders.size > 0
                      ? 'border-foreground/30 bg-muted/50 font-medium'
                      : 'border-border text-muted-foreground hover:bg-muted/30'
                  }`}>
                    Provider
                    {selectedProviders.size > 0 && (
                      <span className="text-[9px] bg-foreground text-background px-1">{selectedProviders.size}</span>
                    )}
                    <ChevronDown className="h-3 w-3" />
                  </button>
                </DropdownMenuTrigger>
                <DropdownMenuContent align="start" className="w-40">
                  <DropdownMenuLabel className="text-xs">Provider</DropdownMenuLabel>
                  <DropdownMenuSeparator />
                  {SIDEBAR_PROVIDERS.map(prov => (
                    <DropdownMenuCheckboxItem
                      key={prov}
                      checked={selectedProviders.has(prov)}
                      onCheckedChange={() => setSelectedProviders(s => toggleSet(s, prov))}
                      className="text-xs"
                    >
                      {prov.toUpperCase()}
                    </DropdownMenuCheckboxItem>
                  ))}
                </DropdownMenuContent>
              </DropdownMenu>
              {selectedProviders.size > 0 && (
                <button onClick={() => setSelectedProviders(new Set())} className="p-0.5 text-muted-foreground hover:text-foreground">
                  <X className="h-3 w-3" />
                </button>
              )}
            </div>
            {/* Status pill */}
            <div className="flex items-center">
              <DropdownMenu>
                <DropdownMenuTrigger asChild>
                  <button className={`flex items-center gap-1 px-2.5 py-1 text-xs border transition-colors ${
                    selectedStatuses.size > 0
                      ? 'border-foreground/30 bg-muted/50 font-medium'
                      : 'border-border text-muted-foreground hover:bg-muted/30'
                  }`}>
                    Status
                    {selectedStatuses.size > 0 && (
                      <span className="text-[9px] bg-foreground text-background px-1">{selectedStatuses.size}</span>
                    )}
                    <ChevronDown className="h-3 w-3" />
                  </button>
                </DropdownMenuTrigger>
                <DropdownMenuContent align="start" className="w-40">
                  <DropdownMenuLabel className="text-xs">Status</DropdownMenuLabel>
                  <DropdownMenuSeparator />
                  {SIDEBAR_STATUSES.map(st => (
                    <DropdownMenuCheckboxItem
                      key={st}
                      checked={selectedStatuses.has(st)}
                      onCheckedChange={() => setSelectedStatuses(s => toggleSet(s, st))}
                      className="text-xs"
                    >
                      {STATUS_LABELS[st] ?? st}
                    </DropdownMenuCheckboxItem>
                  ))}
                </DropdownMenuContent>
              </DropdownMenu>
              {selectedStatuses.size > 0 && (
                <button onClick={() => setSelectedStatuses(new Set())} className="p-0.5 text-muted-foreground hover:text-foreground">
                  <X className="h-3 w-3" />
                </button>
              )}
            </div>
            {hasFilters && (
              <button onClick={clearFilters} className="text-[11px] text-blue-600 hover:text-blue-700 dark:text-blue-400">Clear all</button>
            )}
            <button
              onClick={() => setSidebarCollapsed(false)}
              className="ml-auto flex items-center gap-1 text-xs text-muted-foreground hover:text-foreground border border-border px-2 py-1 hover:bg-muted/30 transition-colors"
            >
              <SlidersHorizontal className="h-3 w-3" />Filters
            </button>
          </div>
        )}

        {/* Top bar */}
        <div className="flex flex-col gap-3 xl:flex-row xl:items-start xl:justify-between">
          <div>
            <h1 className="text-xl font-semibold font-mono">Findings</h1>
            <p className="text-sm text-muted-foreground mt-0.5">
              {displayCount.toLocaleString()} total findings{hasFilters ? ` (${filtered.length.toLocaleString()} visible in current page window)` : ''}
            </p>
          </div>
          <div className="flex w-full flex-wrap items-center gap-2 xl:w-auto xl:justify-end">
            <div className="flex flex-wrap gap-1.5">
              {(['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'] as const).map(sev => (
                <Badge key={sev} variant="outline" className={`text-[10px] px-1.5 py-0 rounded-none ${SEVERITY_COLORS[sev]}`}>
                  {sev} {(severitySummaryCounts[sev] ?? 0).toLocaleString()}
                </Badge>
              ))}
            </div>
            <input
              type="text"
              placeholder="Search findings..."
              aria-label="Search findings"
              value={search}
              onChange={e => setSearch(e.target.value)}
              className="h-8 min-w-0 flex-1 px-2 text-xs border border-border bg-background rounded-none focus:outline-none focus:ring-1 focus:ring-ring sm:flex-none sm:w-48"
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

        {/* Metric cards */}
        <div className="grid grid-cols-3 md:grid-cols-6 gap-2">
          {(['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'] as const).map(sev => {
            const count = severitySummaryCounts[sev] ?? 0
            const isActive = severityTab === sev
            return (
              <button
                key={sev}
                onClick={() => setSeverityTab(prev => prev === sev ? 'ALL' : sev)}
                className={`border p-2.5 text-left transition-colors ${
                  isActive
                    ? 'border-foreground/30 bg-muted/50'
                    : 'border-border hover:bg-muted/30'
                }`}
              >
                <p className="text-[10px] text-muted-foreground uppercase tracking-wide">{sev}</p>
                <p className={`text-lg font-semibold tabular-nums mt-0.5 ${
                  sev === 'CRITICAL' ? 'text-red-600 dark:text-red-400' :
                  sev === 'HIGH' ? 'text-orange-600 dark:text-orange-400' :
                  sev === 'MEDIUM' ? 'text-yellow-600 dark:text-yellow-400' :
                  'text-blue-600 dark:text-blue-400'
                }`}>{count.toLocaleString()}</p>
              </button>
            )
          })}
          <button
            onClick={() => setFilterSLABreached(prev => !prev)}
            className={`border p-2.5 text-left transition-colors ${
              filterSLABreached
                ? 'border-red-300 dark:border-red-800 bg-red-50 dark:bg-red-950/30'
                : 'border-border hover:bg-muted/30'
            }`}
          >
            <p className="text-[10px] text-muted-foreground uppercase tracking-wide">SLA Breached</p>
            <p className="text-lg font-semibold tabular-nums mt-0.5 text-red-600 dark:text-red-400">{(slaBreachedCount).toLocaleString()}</p>
          </button>
          <button
            onClick={() => setFilterAutoRem(prev => !prev)}
            className={`border p-2.5 text-left transition-colors ${
              filterAutoRem
                ? 'border-green-300 dark:border-green-800 bg-green-50 dark:bg-green-950/30'
                : 'border-border hover:bg-muted/30'
            }`}
          >
            <p className="text-[10px] text-muted-foreground uppercase tracking-wide">Auto-Rem</p>
            <p className="text-lg font-semibold tabular-nums mt-0.5 text-green-600 dark:text-green-400">{(autoRemCount).toLocaleString()}</p>
          </button>
        </div>

        {/* Severity tabs */}
        <div className="flex items-center gap-1 overflow-x-auto pb-1">
          {SEVERITY_TABS.map(tab => (
            <button
              key={tab}
              onClick={() => setSeverityTab(tab)}
              className={`shrink-0 px-3 py-1 text-xs rounded-none font-medium transition-colors ${
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

        {/* Group By tabs */}
        <div className="flex items-center gap-1 overflow-x-auto pb-1">
          <span className="mr-1 shrink-0 text-[10px] text-muted-foreground uppercase tracking-wide">Group:</span>
          {([['none', 'All'], ['rule', 'Rule'], ['resource', 'Resource'], ['provider', 'Provider'], ['category', 'Category']] as const).map(([key, label]) => (
            <button
              key={key}
              onClick={() => { setGroupBy(key); setCollapsedGroups(new Set()) }}
              className={`shrink-0 px-2 py-0.5 text-[10px] rounded-none font-medium transition-colors ${
                groupBy === key
                  ? 'bg-primary text-primary-foreground'
                  : 'bg-muted text-muted-foreground hover:bg-muted/80'
              }`}
            >
              {label}
            </button>
          ))}
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
        {/* Grouped view */}
        {!isLoading && groupedFindings && groupedFindings.length > 0 && (
          <div className="overflow-auto" style={{ height: 'calc(100vh - 320px)' }}>
            <div className="space-y-1">
              {groupedFindings.map(([groupKey, items]) => {
                const isCollapsed = collapsedGroups.has(groupKey)
                return (
                  <div key={groupKey}>
                    <button
                      type="button"
                      className="w-full flex items-center gap-2 px-3 py-2 text-xs font-medium bg-muted/50 hover:bg-muted transition-colors text-left"
                      onClick={() => setCollapsedGroups(prev => {
                        const next = new Set(prev)
                        if (next.has(groupKey)) next.delete(groupKey)
                        else next.add(groupKey)
                        return next
                      })}
                    >
                      {isCollapsed ? <ChevronRight className="h-3 w-3 shrink-0" /> : <ChevronDown className="h-3 w-3 shrink-0" />}
                      <span>{groupKey}</span>
                      <Badge variant="secondary" className="text-[10px] ml-auto">{items.length}</Badge>
                    </button>
                    {!isCollapsed && (
                      <div className="divide-y divide-border">
                        {items.slice(0, 20).map(f => (
                          <button
                            key={f.id}
                            type="button"
                            className="w-full grid grid-cols-[1fr_80px_100px_80px] gap-2 px-6 py-2 text-xs items-center hover:bg-muted/30 transition-colors text-left"
                            onClick={() => navigate(`/ops/findings/${f.id}`)}
                          >
                            <span className="truncate">{f.title}</span>
                            <SeverityBadge severity={f.severity} />
                            <span className="text-muted-foreground truncate">{f.resource_name}</span>
                            <span className="text-muted-foreground">{f.cloud_provider.toUpperCase()}</span>
                          </button>
                        ))}
                        {items.length > 20 && (
                          <p className="px-6 py-1.5 text-[10px] text-muted-foreground">+ {items.length - 20} more</p>
                        )}
                      </div>
                    )}
                  </div>
                )
              })}
            </div>
          </div>
        )}

        {/* Flat table view */}
        {!isLoading && sorted.length > 0 && groupBy === 'none' && (() => {
          const isCompact = isMobile || !!(previewId && isDesktop)
          const cols = isMobile ? mobileColumns : (isCompact ? compactColumns : activeColumns)
          const getColumnWidth = (col: SortColumn) => isMobile ? mobileColumnWidths[col] : columnWidths[col]
          return (
          <div className="flex gap-0 flex-1 min-h-0 overflow-hidden">
            {/* West: Table */}
            <div className={isMobile
              ? 'flex-1 min-w-0 overflow-y-auto'
              : isCompact
                ? 'w-[380px] shrink-0 overflow-y-auto border-r border-border transition-all'
                : 'flex-1 min-w-0 transition-all'}>
              <div ref={parentRef} className="overflow-auto [&_[data-slot=table-container]]:overflow-visible" style={{ height: 'calc(100vh - 280px)' }}>
                <Table style={{ tableLayout: 'fixed', width: cols.reduce((sum, c) => sum + getColumnWidth(c.key), 0) }}>
                  <TableHeader className="sticky top-0 z-10 bg-background">
                    <TableRow className="bg-muted/30">
                      {cols.map(col => (
                        <TableHead
                          key={col.key}
                          className="relative select-none overflow-hidden"
                          style={{ width: getColumnWidth(col.key) }}
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
                          {!isCompact && (
                            <div
                              className="absolute top-0 right-0 w-1.5 h-full cursor-col-resize hover:bg-primary/30 active:bg-primary/50"
                              onMouseDown={(e) => onResizeStart(col.key, e)}
                              onClick={(e) => e.stopPropagation()}
                            />
                          )}
                        </TableHead>
                      ))}
                    </TableRow>
                  </TableHeader>
                  <TableBody>
                    {paddingTop > 0 && <tr><td colSpan={cols.length} style={{ height: paddingTop }} /></tr>}
                    {virtualItems.map(virtualRow => {
                      const f = paged[virtualRow.index]
                      const isSelected = f.id === previewId
                      return (
                        <TableRow
                          key={f.id}
                          data-index={virtualRow.index}
                          ref={virtualizer.measureElement}
                          className={`cursor-pointer hover:bg-muted/30 transition-colors ${isSelected ? 'bg-primary/10 ring-1 ring-inset ring-primary/20' : ''}`}
                          tabIndex={0}
                          role="link"
                          onClick={() => {
                            if (isDesktop) {
                              setPreviewId(f.id)
                            } else {
                              navigate(`/ops/findings/${f.id}`)
                            }
                          }}
                          onDoubleClick={() => navigate(`/ops/findings/${f.id}`)}
                          onKeyDown={(e) => {
                            if (e.key === 'Enter') { navigate(`/ops/findings/${f.id}`) }
                            else if (e.key === 'Escape') { setPreviewId(null) }
                            else if (e.key === 'ArrowDown') { e.preventDefault(); if (virtualRow.index < paged.length - 1) setPreviewId(paged[virtualRow.index + 1].id) }
                            else if (e.key === 'ArrowUp') { e.preventDefault(); if (virtualRow.index > 0) setPreviewId(paged[virtualRow.index - 1].id) }
                          }}
                        >
                          {cols.map(col => (
                            <TableCell key={col.key} className="overflow-hidden" style={{ width: getColumnWidth(col.key) }}>
                              {renderCell(f, col.key)}
                            </TableCell>
                          ))}
                        </TableRow>
                      )
                    })}
                    {paddingBottom > 0 && <tr><td colSpan={cols.length} style={{ height: paddingBottom }} /></tr>}
                  </TableBody>
                </Table>
              </div>

              {/* Pagination footer */}
              <div className="flex flex-col gap-2 border-t border-border pt-2 sm:flex-row sm:items-center sm:justify-between">
                <div className="flex items-center gap-2">
                  <span className="text-xs text-muted-foreground">Rows per page</span>
                  <select
                    value={pageSize}
                    onChange={(e) => setPageSize(Number(e.target.value))}
                    className="h-7 text-xs border border-border bg-background px-1 rounded-none focus:outline-none focus:ring-1 focus:ring-ring"
                    aria-label="Page size"
                  >
                    {[25, 50, 100, 150].map(n => <option key={n} value={n}>{n}</option>)}
                  </select>
                </div>
                <span className="text-xs text-muted-foreground tabular-nums">
                  {sorted.length === 0
                    ? '0 visible'
                    : `Page ${currentPage} · ${sorted.length.toLocaleString()} visible`}
                  {' '}of {displayCount.toLocaleString()}
                </span>
                <div className="flex items-center gap-0.5 self-end sm:self-auto">
                  <Button variant="ghost" size="icon" className="h-7 w-7" disabled={currentPage <= 1} onClick={() => setPage(1)} aria-label="First page">
                    <ChevronsLeft className="h-3.5 w-3.5" />
                  </Button>
                  <Button variant="ghost" size="icon" className="h-7 w-7" disabled={currentPage <= 1} onClick={() => setPage(p => p - 1)} aria-label="Previous page">
                    <ChevronLeft className="h-3.5 w-3.5" />
                  </Button>
                  <span className="text-xs tabular-nums px-2">
                    {currentPage} / {totalPages}
                  </span>
                  <Button variant="ghost" size="icon" className="h-7 w-7" disabled={currentPage >= totalPages} onClick={() => setPage(p => p + 1)} aria-label="Next page">
                    <ChevronRight className="h-3.5 w-3.5" />
                  </Button>
                  <Button variant="ghost" size="icon" className="h-7 w-7" disabled={currentPage >= totalPages} onClick={() => setPage(totalPages)} aria-label="Last page">
                    <ChevronsRight className="h-3.5 w-3.5" />
                  </Button>
                </div>
              </div>
            </div>

            {/* East: Detail panel */}
            {previewId && isDesktop && (
              <div className="flex-1 min-w-0 overflow-hidden border-l border-border">
                <FindingDetail mode="inline" findingId={previewId} onClose={() => setPreviewId(null)} />
              </div>
            )}
          </div>
          )
        })()}
      </div>
    </div>
  )
}
