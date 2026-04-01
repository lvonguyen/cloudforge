import { useEffect, useMemo, useCallback, useId, useState, type KeyboardEvent as ReactKeyboardEvent } from 'react'
import {
  ReactFlow,
  Background,
  Controls,
  MiniMap,
  type Node,
} from '@xyflow/react'
import '@xyflow/react/dist/style.css'
import { useNavigate } from 'react-router-dom'
import {
  CommandCenterProvider,
  useCommandCenter,
  parseLayerKey,
} from '@/contexts/CommandCenterContext'
import { DataLayersPanel } from '@/components/ops/DataLayersPanel'
import { EntityDetailPanel } from '@/components/ops/EntityDetailPanel'
import { NLQueryBar } from '@/components/ops/NLQueryBar'
import { StatusBar } from '@/components/ops/StatusBar'
import { FindingsSummaryChart } from '@/components/ops/FindingsSummaryChart'
import { ShortcutOverlay } from '@/components/ops/ShortcutOverlay'
import { pathToFlow } from '@/components/ops/AttackPathFlow'
import { useFindings, useFindingsStats } from '@/hooks/useFindings'
import { useAttackPaths, useAttackPathStats } from '@/hooks/useAttackPaths'
import { useRemediations } from '@/hooks/useRemediations'
import { Badge } from '@/components/ui/badge'
import { SEVERITY_COLORS_BORDERED as SEVERITY_COLORS, SEVERITY_HEX, SEVERITY_NEUTRAL_HEX } from '@/lib/severity'
import { ProviderBadge } from '@/components/ui/ProviderBadge'
import {
  ArrowLeft,
  ChevronRight,
  Layers,
  Shield,
  Sparkles,
} from 'lucide-react'
import type { AttackPath } from '@/types/attack-path'
import type { Finding } from '@/types/compliance'

interface NLQFilters {
  severity?: string[]
  provider?: string[]
  category?: string[]
  status?: string[]
  environment?: string[]
  text?: string
}

function getFindingQueueScore(finding: Finding): number {
  const severityScore: Record<string, number> = {
    CRITICAL: 40,
    HIGH: 28,
    MEDIUM: 16,
    LOW: 8,
  }

  return (
    (severityScore[finding.severity] ?? 0) +
    Math.round(finding.ai_risk_score * 5) +
    (finding.toxic_combo_details ? 24 : 0) +
    (finding.exploit_available ? 18 : 0) +
    Math.min(finding.impacted_resources?.length ?? 0, 5) * 3 +
    Math.min(finding.compliance_mappings?.length ?? 0, 4) * 2 +
    (finding.environment_type === 'production' ? 6 : 0)
  )
}

function summarizeFindingQueueContext(finding: Finding): string {
  if (finding.toxic_combo_details) {
    return `Toxic combo · ${finding.toxic_combo_details.combo_type}`
  }
  if (finding.exploit_available) {
    return 'Exploit path available'
  }
  if ((finding.impacted_resources?.length ?? 0) > 0) {
    return `${finding.impacted_resources?.length ?? 0} downstream resource${finding.impacted_resources?.length === 1 ? '' : 's'}`
  }
  if ((finding.compliance_mappings?.length ?? 0) > 0) {
    return `${finding.compliance_mappings?.length ?? 0} mapped control${finding.compliance_mappings?.length === 1 ? '' : 's'}`
  }
  return finding.ai_contextual_factors?.[0] ?? finding.category.replaceAll('_', ' ')
}

// ---------------------------------------------------------------------------
// Compact attack path card (for the grid view)
// ---------------------------------------------------------------------------

function PathCard({
  path,
  onClick,
}: {
  path: AttackPath
  onClick: () => void
}) {
  return (
    <button
      type="button"
      onClick={onClick}
      className="w-full text-left border border-[#1e2330] bg-[#0d0d14] p-3 hover:bg-[#161b22]/60 transition-colors"
      aria-label={`${path.title}, ${path.severity.toLowerCase()} severity, ${path.hop_count} hops`}
    >
      <div className="flex items-center gap-2 mb-1.5 flex-wrap">
        <Badge variant="outline" className={`text-[10px] px-1.5 py-0 ${SEVERITY_COLORS[path.severity] ?? ''}`}>
          {path.severity}
        </Badge>
        <span className="text-[11px] text-gray-500 font-mono">
          {path.hop_count} hop{path.hop_count !== 1 ? 's' : ''} · {path.score.toFixed(0)}
        </span>
        {path.nodes.length > 0 && <ProviderBadge provider={path.nodes[0].provider} size="sm" />}
        {path.ai_enriched && (
          <Sparkles className="h-3 w-3 text-violet-400" />
        )}
      </div>
      <div className="text-sm text-gray-200 font-medium truncate">{path.title}</div>
      <div className="text-xs text-gray-500 mt-0.5 line-clamp-1">
        {path.entry_point.resource_name} → {path.target.resource_name}
      </div>
    </button>
  )
}

// ---------------------------------------------------------------------------
// Center pane — attack path grid or graph
// ---------------------------------------------------------------------------

function CenterPane({
  attackPaths,
  allFindings,
  filteredFindings,
  totalFindings,
  stats,
}: {
  attackPaths: AttackPath[]
  allFindings: Finding[]
  filteredFindings: Finding[]
  totalFindings: number
  stats?: { total_paths: number; critical_paths: number }
}) {
  const { state, dispatch } = useCommandCenter()
  const navigate = useNavigate()
  const { selectedPathId } = state
  const centerViewId = useId()
  const chartsTabId = `${centerViewId}-charts-tab`
  const queueTabId = `${centerViewId}-queue-tab`
  const chartsPanelId = `${centerViewId}-charts-panel`
  const queuePanelId = `${centerViewId}-queue-panel`

  const selectedPath = useMemo(
    () => attackPaths.find(p => p.id === selectedPathId) ?? null,
    [attackPaths, selectedPathId],
  )

  const { nodes, edges } = useMemo(
    () => selectedPath ? pathToFlow(selectedPath) : { nodes: [], edges: [] },
    [selectedPath],
  )

  const onNodeClick = useCallback(
    (_: React.MouseEvent, node: Node) => {
      const fid = node.data?.findingId as string | undefined
      if (!fid) return
      const finding = allFindings.find(f => f.id === fid)
      if (finding) {
        dispatch({ type: 'SELECT_ENTITY', payload: { type: 'finding', data: finding } })
      }
    },
    [allFindings, dispatch],
  )

  const selectPath = useCallback(
    (path: AttackPath) => {
      dispatch({ type: 'SELECT_PATH', payload: path.id })
      dispatch({ type: 'SELECT_ENTITY', payload: { type: 'attack-path', data: path } })
    },
    [dispatch],
  )

  const goBack = useCallback(() => {
    dispatch({ type: 'SELECT_PATH', payload: null })
    dispatch({ type: 'SELECT_ENTITY', payload: null })
  }, [dispatch])

  const onSelectFinding = useCallback(
    (f: Finding) => {
      dispatch({ type: 'SELECT_ENTITY', payload: { type: 'finding', data: f } })
    },
    [dispatch],
  )

  const queuedFindings = useMemo(
    () =>
      [...filteredFindings]
        .sort((a, b) => getFindingQueueScore(b) - getFindingQueueScore(a))
        .slice(0, 24),
    [filteredFindings],
  )

  const handleViewTabKeyDown = useCallback(
    (event: ReactKeyboardEvent<HTMLButtonElement>, currentView: 'charts' | 'queue') => {
      const advanceKeys = ['ArrowRight', 'ArrowDown']
      const retreatKeys = ['ArrowLeft', 'ArrowUp']

      if (!advanceKeys.includes(event.key) && !retreatKeys.includes(event.key) && event.key !== 'Home' && event.key !== 'End') {
        return
      }

      event.preventDefault()

      if (event.key === 'Home') {
        dispatch({ type: 'SET_CENTER_VIEW', payload: 'charts' })
        return
      }
      if (event.key === 'End') {
        dispatch({ type: 'SET_CENTER_VIEW', payload: 'queue' })
        return
      }

      dispatch({
        type: 'SET_CENTER_VIEW',
        payload: currentView === 'charts' ? 'queue' : 'charts',
      })
    },
    [dispatch],
  )

  return (
    <div className="flex flex-col h-full bg-[#0a0a0f]">
      {/* Context bar */}
      <div className="flex items-center gap-3 px-4 h-9 border-b border-[#1e2330] shrink-0">
        {selectedPath ? (
          <>
            <button
              type="button"
              onClick={goBack}
              className="flex items-center gap-1 text-xs text-gray-400 hover:text-gray-200 transition-colors"
              aria-label="Return to all attack paths"
            >
              <ArrowLeft className="h-3 w-3" /> All Paths
            </button>
            <Badge variant="outline" className={`text-[10px] px-1.5 py-0 ${SEVERITY_COLORS[selectedPath.severity] ?? ''}`}>
              {selectedPath.severity}
            </Badge>
            <span className="text-xs text-gray-300 truncate">{selectedPath.title}</span>
          </>
        ) : (
          <>
            <Shield className="h-3.5 w-3.5 text-gray-500" />
            <span className="text-xs font-semibold uppercase tracking-widest text-gray-500">
              Attack Paths
            </span>
            <span className="text-xs text-gray-600 font-mono">
              {attackPaths.length} paths
              {attackPaths.length > 0 && stats?.critical_paths != null ? ` · ${stats.critical_paths} critical` : ''}
            </span>
            <span className="text-xs text-gray-600 font-mono">
              {filteredFindings.length === totalFindings
                ? `${totalFindings.toLocaleString()} findings`
                : `${filteredFindings.length.toLocaleString()} visible · ${totalFindings.toLocaleString()} total`}
            </span>
            {/* Segmented center view control */}
            <div
              className="ml-auto flex border border-[#1e2330]"
              role="tablist"
              aria-label="Command center visualization view"
            >
              {(['charts', 'queue'] as const).map((view, i) => (
                <button
                  key={view}
                  type="button"
                  id={view === 'charts' ? chartsTabId : queueTabId}
                  role="tab"
                  aria-selected={state.centerView === view}
                  aria-controls={view === 'charts' ? chartsPanelId : queuePanelId}
                  tabIndex={state.centerView === view ? 0 : -1}
                  onClick={() => dispatch({ type: 'SET_CENTER_VIEW', payload: view })}
                  onKeyDown={(event) => handleViewTabKeyDown(event, view)}
                  className={`text-[10px] font-mono uppercase px-2 py-0.5 transition-colors ${
                    state.centerView === view
                      ? 'bg-[#1e2330] text-gray-200'
                      : 'text-gray-500 hover:text-gray-300'
                  }`}
                >
                  {i + 1} {view === 'charts' ? 'Charts' : 'Queue'}
                </button>
              ))}
            </div>
          </>
        )}
      </div>

      {/* Main area */}
      <div className="flex-1 overflow-hidden">
        {selectedPath ? (
          /* Graph view */
          <div role="region" aria-label={`Attack path graph for ${selectedPath.title}`} className="h-full">
            <ReactFlow
              nodes={nodes}
              edges={edges}
              onNodeClick={onNodeClick}
              fitView
              fitViewOptions={{ padding: 0.3 }}
              proOptions={{ hideAttribution: true }}
              nodesDraggable={false}
              nodesConnectable={false}
              elementsSelectable={false}
              minZoom={0.3}
              maxZoom={1.5}
            >
              <Background gap={20} size={1} color="#1a1e26" />
              <Controls showInteractive={false} />
              <MiniMap
                nodeColor={(n) => SEVERITY_HEX[(n.data?.severity as string) ?? ''] ?? SEVERITY_NEUTRAL_HEX}
                style={{ background: '#0d1117' }}
                maskColor="rgba(0,0,0,0.6)"
              />
            </ReactFlow>
          </div>
        ) : state.centerView === 'queue' ? (
          /* Operator findings queue */
          <div
            id={queuePanelId}
            role="tabpanel"
            aria-labelledby={queueTabId}
            className="h-full overflow-y-auto"
          >
            <div className="border-b border-[#1e2330] px-4 py-3">
              <p className="text-[10px] font-semibold uppercase tracking-[0.22em] text-gray-500">
                Investigation Queue
              </p>
              <p className="mt-1 text-xs text-gray-400">
                Highest-value findings first. Toxic combinations, exploit availability, production scope, and downstream impact push items to the top.
              </p>
            </div>
            <div className="divide-y divide-[#1e2330]">
              {queuedFindings.map((finding) => (
                <div
                  key={finding.id}
                  role="button"
                  tabIndex={0}
                  onClick={() => onSelectFinding(finding)}
                  onKeyDown={(event) => {
                    if (event.key === 'Enter' || event.key === ' ') {
                      event.preventDefault()
                      onSelectFinding(finding)
                    }
                  }}
                  className="flex w-full items-start gap-3 px-4 py-3 text-left transition-colors hover:bg-[#111827]"
                >
                  <div className="min-w-0 flex-1">
                    <div className="flex flex-wrap items-center gap-2">
                      <Badge variant="outline" className={`text-[10px] px-1.5 py-0 ${SEVERITY_COLORS[finding.severity] ?? ''}`}>
                        {finding.severity}
                      </Badge>
                      <ProviderBadge provider={finding.cloud_provider} size="sm" />
                      <span className="text-[10px] font-mono text-gray-500">{finding.id}</span>
                      <span className="text-[10px] font-mono text-cyan-300">Score {getFindingQueueScore(finding)}</span>
                    </div>
                    <p className="mt-2 text-sm font-medium text-gray-100">{finding.title}</p>
                    <p className="mt-1 text-xs text-gray-400">
                      {finding.resource_name} · {finding.resource_type} · {finding.environment_type}
                    </p>
                    <div className="mt-2 flex flex-wrap items-center gap-2 text-[10px] text-gray-400">
                      <span>{summarizeFindingQueueContext(finding)}</span>
                      {finding.assignee?.user_name && <span>Owner: {finding.assignee.user_name}</span>}
                    </div>
                  </div>
                  <div className="shrink-0">
                    <button
                      type="button"
                      onClick={(event) => {
                        event.stopPropagation()
                        navigate(`/ops/findings/${finding.id}`)
                      }}
                      className="inline-flex items-center gap-1 rounded border border-[#1f2937] px-2 py-1 text-[10px] uppercase tracking-wide text-gray-300 transition-colors hover:border-[#374151] hover:bg-[#0f172a]"
                    >
                      Open case
                      <ChevronRight className="h-3 w-3" />
                    </button>
                  </div>
                </div>
              ))}
            </div>
          </div>
        ) : attackPaths.length > 0 ? (
          /* Card grid with findings summary */
          <div
            id={chartsPanelId}
            role="tabpanel"
            aria-labelledby={chartsTabId}
            className="overflow-y-auto h-full"
          >
            <FindingsSummaryChart findings={filteredFindings} />
            <div className="px-4 pb-4">
              <div className="grid grid-cols-1 lg:grid-cols-2 xl:grid-cols-3 gap-2">
                {attackPaths.map(path => (
                  <PathCard key={path.id} path={path} onClick={() => selectPath(path)} />
                ))}
              </div>
            </div>
          </div>
        ) : (
          /* Findings summary when no attack paths */
          <div
            id={chartsPanelId}
            role="tabpanel"
            aria-labelledby={chartsTabId}
            className="overflow-y-auto h-full"
          >
            <FindingsSummaryChart findings={filteredFindings} />
          </div>
        )}
      </div>
    </div>
  )
}

// ---------------------------------------------------------------------------
// Shell — data fetching, filtering, layout, keyboard shortcuts
// ---------------------------------------------------------------------------

function CommandCenterShell() {
  const { state, dispatch, showDetailPanel } = useCommandCenter()
  const [queryFilters, setQueryFilters] = useState<Pick<NLQFilters, 'category' | 'status' | 'text'>>({})

  // Data fetching
  const { data: allFindings = [], isLoading: findingsLoading, isUsingMockData } = useFindings({
    page: 1,
    perPage: 200,
    sort: 'ai_risk',
    order: 'desc',
  })
  const { data: findingStats } = useFindingsStats()
  const { data: attackPathsResponse } = useAttackPaths(1, 100)
  const { data: stats } = useAttackPathStats()
  const { data: remediations = [] } = useRemediations()

  const attackPaths = attackPathsResponse?.data ?? []

  // Build enabled-value sets from flat activeLayers map
  const enabledByGroup = useMemo(() => {
    const map: Record<string, Set<string>> = {}
    for (const [key, on] of Object.entries(state.activeLayers)) {
      if (!on) continue
      const { group, value } = parseLayerKey(key)
      if (!map[group]) map[group] = new Set()
      map[group].add(value)
    }
    return map
  }, [state.activeLayers])

  // Filter findings by active layers (severity AND provider AND environment) + date range
  const filteredFindings = useMemo(() => {
    const sevs = enabledByGroup.severity
    const provs = enabledByGroup.provider
    const envs = enabledByGroup.environment
    const { start, end } = state.dateRange
    return allFindings.filter(f => {
      if (sevs && sevs.size > 0 && !sevs.has(f.severity)) return false
      if (provs && provs.size > 0 && !provs.has(f.cloud_provider)) return false
      if (envs && envs.size > 0 && !envs.has(f.environment_type)) return false
      if (queryFilters.category?.length && !queryFilters.category.includes(f.category)) return false
      if (queryFilters.status?.length && !queryFilters.status.includes(f.status) && !queryFilters.status.includes(f.workflow_status)) return false
      if (queryFilters.text) {
        const q = queryFilters.text.toLowerCase()
        const haystack = [
          f.title,
          f.resource_name,
          f.id,
          f.description,
          f.category,
          f.cloud_provider,
          f.resource_type,
          ...(f.ai_contextual_factors ?? []),
        ].join(' ').toLowerCase()
        if (!haystack.includes(q)) return false
      }
      if (start && f.first_found_at < start) return false
      if (end && f.first_found_at > end + 'T23:59:59Z') return false
      return true
    })
  }, [allFindings, enabledByGroup, queryFilters.category, queryFilters.status, queryFilters.text, state.dateRange])

  // Filter attack paths by active layers (provider/severity match on nodes)
  const filteredAttackPaths = useMemo(() => {
    const sevs = enabledByGroup.severity
    const provs = enabledByGroup.provider
    if ((!sevs || sevs.size === 0) && (!provs || provs.size === 0)) return attackPaths
    return attackPaths.filter(p => {
      if (sevs && sevs.size > 0 && !sevs.has(p.severity)) return false
      if (provs && provs.size > 0 && !p.nodes.some(n => provs.has(n.provider))) return false
      return true
    })
  }, [attackPaths, enabledByGroup])

  const toxicComboCount = useMemo(
    () => filteredFindings.filter(f => f.toxic_combo_details).length,
    [filteredFindings],
  )

  // Keyboard shortcuts
  useEffect(() => {
    function onKeyDown(e: KeyboardEvent) {
      // Escape: close overlay first, then deselect
      if (e.key === 'Escape') {
        if (state.showShortcutOverlay) {
          dispatch({ type: 'TOGGLE_SHORTCUT_OVERLAY' })
        } else {
          dispatch({ type: 'SELECT_PATH', payload: null })
          dispatch({ type: 'SELECT_ENTITY', payload: null })
        }
        return
      }

      // Guard: no letter/digit shortcuts while typing
      if (e.target instanceof HTMLInputElement || e.target instanceof HTMLTextAreaElement) return

      switch (e.key) {
        case 'l':
        case 'L':
          dispatch({ type: 'TOGGLE_LEFT_PANEL' })
          break
        case 'd':
        case 'D':
          dispatch({ type: 'SELECT_ENTITY', payload: null })
          break
        case '1':
          dispatch({ type: 'SET_CENTER_VIEW', payload: 'charts' })
          break
        case '2':
          dispatch({ type: 'SET_CENTER_VIEW', payload: 'queue' })
          break
        case '?':
          dispatch({ type: 'TOGGLE_SHORTCUT_OVERLAY' })
          break
      }
    }
    window.addEventListener('keydown', onKeyDown)
    return () => window.removeEventListener('keydown', onKeyDown)
  }, [dispatch, state.showShortcutOverlay])

  const handleNLQFilters = useCallback((filters: NLQFilters) => {
    const layers: Record<string, boolean> = {}
    if (filters.severity) {
      for (const s of ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']) {
        layers[`severity:${s}`] = filters.severity.includes(s)
      }
    }
    if (filters.provider) {
      for (const p of ['aws', 'azure', 'gcp']) {
        layers[`provider:${p}`] = filters.provider.includes(p)
      }
    }
    if (filters.environment) {
      for (const e of ['production', 'staging', 'development']) {
        layers[`environment:${e}`] = filters.environment.includes(e)
      }
    }
    setQueryFilters({
      category: filters.category && filters.category.length > 0 ? filters.category : undefined,
      status: filters.status && filters.status.length > 0 ? filters.status : undefined,
      text: filters.text?.trim() || undefined,
    })
    dispatch({ type: 'SET_LAYERS', payload: layers })
  }, [dispatch])

  if (findingsLoading) {
    return (
      <div className="flex items-center justify-center h-full bg-[#0a0a0f] text-gray-500 text-xs font-mono">
        Initializing command center…
      </div>
    )
  }

  return (
    <div className="dark flex h-full flex-col bg-[#0a0a0f]">
      {state.showShortcutOverlay && <ShortcutOverlay />}
      {/* NLQ bar — GAP-03 */}
      <div className="px-3 py-2 border-b border-[#1e2330] flex items-center gap-2">
        <NLQueryBar onApplyFilters={handleNLQFilters} />
        {isUsingMockData && (
          <Badge variant="outline" className="text-[9px] px-1.5 py-0 border-amber-600 text-amber-400 shrink-0">
            Demo data
          </Badge>
        )}
      </div>
      {/* Three-column layout — PaneLayout pattern */}
      <div className="flex flex-1 overflow-hidden">
        {/* Left panel — data layers */}
        <aside
          className="shrink-0 overflow-y-auto border-r border-[#1e2330] transition-all duration-200"
          style={{ width: state.leftPanelOpen ? 240 : 0 }}
          aria-label="Data layer filters"
        >
          {state.leftPanelOpen && (
            <DataLayersPanel findings={allFindings} attackPaths={attackPaths} />
          )}
        </aside>

        {/* Center — primary visualization */}
        <div className="flex-1 overflow-hidden relative">
          {/* Left panel toggle in center area */}
          {!state.leftPanelOpen && (
            <button
              type="button"
              onClick={() => dispatch({ type: 'TOGGLE_LEFT_PANEL' })}
              className="absolute z-10 left-1 top-1 p-1.5 bg-[#0d0d14] border border-[#1e2330] text-gray-400 hover:text-gray-200 transition-colors"
              aria-label="Show data layers"
              title="Show layers (L)"
            >
              <Layers className="h-3.5 w-3.5" />
            </button>
          )}
          <CenterPane
            attackPaths={filteredAttackPaths}
            allFindings={allFindings}
            filteredFindings={filteredFindings}
            totalFindings={findingStats?.total ?? allFindings.length}
            stats={stats ?? undefined}
          />
        </div>

        {/* Right panel — entity detail (slides in on selection) */}
        <aside
          className="shrink-0 overflow-y-auto border-l border-[#1e2330] transition-all duration-200"
          style={{ width: showDetailPanel ? 340 : 0 }}
          aria-label="Selected entity details"
        >
          {showDetailPanel && (
            <EntityDetailPanel
              attackPaths={attackPaths}
              remediations={remediations}
            />
          )}
        </aside>
      </div>

      {/* Bottom bar — classification legend */}
      <StatusBar
        filteredFindings={filteredFindings}
        totalFindings={findingStats?.total ?? allFindings.length}
        attackPathCount={attackPaths.length}
        toxicComboCount={toxicComboCount}
        dateRange={state.dateRange}
        onDateRangeChange={(dr) => dispatch({ type: 'SET_DATE_RANGE', payload: dr })}
        onShowShortcuts={() => dispatch({ type: 'TOGGLE_SHORTCUT_OVERLAY' })}
      />
    </div>
  )
}

// ---------------------------------------------------------------------------
// Default export — wraps shell in provider
// ---------------------------------------------------------------------------

export default function CommandCenter() {
  return (
    <CommandCenterProvider>
      <CommandCenterShell />
    </CommandCenterProvider>
  )
}
