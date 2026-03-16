import { useEffect, useMemo, useCallback } from 'react'
import {
  ReactFlow,
  Background,
  Controls,
  MiniMap,
  type Node,
  type Edge,
  Position,
  MarkerType,
} from '@xyflow/react'
import '@xyflow/react/dist/style.css'
import {
  CommandCenterProvider,
  useCommandCenter,
  parseLayerKey,
} from '@/contexts/CommandCenterContext'
import { DataLayersPanel } from '@/components/ops/DataLayersPanel'
import { EntityDetailPanel } from '@/components/ops/EntityDetailPanel'
import { StatusBar } from '@/components/ops/StatusBar'
import { FindingsSummaryChart } from '@/components/ops/FindingsSummaryChart'
import { useFindings } from '@/hooks/useFindings'
import { useAttackPaths, useAttackPathStats } from '@/hooks/useAttackPaths'
import { useRemediations } from '@/hooks/useRemediations'
import { Badge } from '@/components/ui/badge'
import { SEVERITY_COLORS_BORDERED as SEVERITY_COLORS } from '@/lib/severity'
import { ProviderBadge } from '@/components/ui/ProviderBadge'
import {
  ArrowLeft,
  Layers,
  Shield,
  Sparkles,
} from 'lucide-react'
import type { AttackPath } from '@/types/attack-path'
import type { Finding } from '@/types/compliance'

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const NODE_BORDER: Record<string, string> = {
  CRITICAL: '#ef4444',
  HIGH: '#f97316',
  MEDIUM: '#eab308',
  LOW: '#3b82f6',
}

// ---------------------------------------------------------------------------
// Attack path → ReactFlow conversion
// ---------------------------------------------------------------------------

function pathToFlow(path: AttackPath): { nodes: Node[]; edges: Edge[] } {
  const nodes: Node[] = path.nodes.map((n, i) => ({
    id: n.id,
    position: { x: i * 340, y: 0 },
    data: {
      label: (
        <div className="text-left px-2 py-1">
          <div className="flex items-center gap-1 mb-0.5">
            <span className={`text-[8px] font-bold px-1 py-0 ${SEVERITY_COLORS[n.severity] ?? ''}`}>
              {n.severity}
            </span>
            <span className="text-[8px] text-gray-500">{n.category}</span>
          </div>
          <div className="text-[11px] font-medium text-gray-200 truncate max-w-[180px]">
            {n.resource_name}
          </div>
          <div className="text-[9px] text-gray-500">{n.resource_type} · {n.region}</div>
        </div>
      ),
      severity: n.severity,
      findingId: n.finding_id,
    },
    sourcePosition: Position.Right,
    targetPosition: Position.Left,
    style: {
      border: `2px solid ${NODE_BORDER[n.severity] ?? '#4b5563'}`,
      borderRadius: '0px',
      background: '#111318',
      padding: '4px',
      width: 220,
      cursor: 'pointer',
    },
  }))

  const edges: Edge[] = path.edges.map(e => ({
    id: e.id,
    source: e.source,
    target: e.target,
    label: e.label,
    type: 'default',
    markerEnd: { type: MarkerType.ArrowClosed, width: 14, height: 14 },
    style: { strokeWidth: 2, stroke: '#374151' },
    labelStyle: { fontSize: 9, fill: '#6b7280' },
    labelBgStyle: { fill: '#0a0a0f', fillOpacity: 0.9 },
    labelBgPadding: [3, 5] as [number, number],
  }))

  return { nodes, edges }
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
      onClick={onClick}
      className="w-full text-left border border-[#1e2330] bg-[#0d0d14] p-3 hover:bg-[#161b22]/60 transition-colors"
    >
      <div className="flex items-center gap-2 mb-1.5 flex-wrap">
        <Badge variant="outline" className={`text-[9px] px-1.5 py-0 ${SEVERITY_COLORS[path.severity] ?? ''}`}>
          {path.severity}
        </Badge>
        <span className="text-[10px] text-gray-500 font-mono">
          {path.hop_count} hop{path.hop_count !== 1 ? 's' : ''} · {path.score.toFixed(0)}
        </span>
        {path.nodes.length > 0 && <ProviderBadge provider={path.nodes[0].provider} />}
        {path.ai_enriched && (
          <Sparkles className="h-3 w-3 text-violet-400" />
        )}
      </div>
      <div className="text-xs text-gray-200 font-medium truncate">{path.title}</div>
      <div className="text-[10px] text-gray-500 mt-0.5 line-clamp-1">
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
  stats,
}: {
  attackPaths: AttackPath[]
  allFindings: Finding[]
  filteredFindings: Finding[]
  stats?: { total_paths: number; critical_paths: number }
}) {
  const { state, dispatch } = useCommandCenter()
  const { selectedPathId } = state

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

  return (
    <div className="flex flex-col h-full bg-[#0a0a0f]">
      {/* Context bar */}
      <div className="flex items-center gap-3 px-4 h-9 border-b border-[#1e2330] shrink-0">
        {selectedPath ? (
          <>
            <button
              onClick={goBack}
              className="flex items-center gap-1 text-[10px] text-gray-400 hover:text-gray-200 transition-colors"
            >
              <ArrowLeft className="h-3 w-3" /> All Paths
            </button>
            <Badge variant="outline" className={`text-[9px] px-1.5 py-0 ${SEVERITY_COLORS[selectedPath.severity] ?? ''}`}>
              {selectedPath.severity}
            </Badge>
            <span className="text-[11px] text-gray-300 truncate">{selectedPath.title}</span>
          </>
        ) : (
          <>
            <Shield className="h-3.5 w-3.5 text-gray-500" />
            <span className="text-[10px] font-semibold uppercase tracking-widest text-gray-500">
              Attack Paths
            </span>
            <span className="text-[10px] text-gray-600 font-mono">
              {attackPaths.length} paths
              {attackPaths.length > 0 && stats?.critical_paths != null ? ` · ${stats.critical_paths} critical` : ''}
            </span>
          </>
        )}
      </div>

      {/* Main area */}
      <div className="flex-1 overflow-hidden">
        {selectedPath ? (
          /* Graph view */
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
              nodeColor={(n) => NODE_BORDER[(n.data?.severity as string) ?? ''] ?? '#4b5563'}
              style={{ background: '#0d1117' }}
              maskColor="rgba(0,0,0,0.6)"
            />
          </ReactFlow>
        ) : attackPaths.length > 0 ? (
          /* Card grid with findings summary */
          <div className="overflow-y-auto h-full">
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
          <div className="overflow-y-auto h-full">
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

  // Data fetching
  const { data: allFindings = [], isLoading: findingsLoading } = useFindings()
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

  // Filter findings by active layers (severity AND provider AND environment)
  const filteredFindings = useMemo(() => {
    const sevs = enabledByGroup.severity
    const provs = enabledByGroup.provider
    const envs = enabledByGroup.environment
    return allFindings.filter(f =>
      (!sevs || sevs.size === 0 || sevs.has(f.severity)) &&
      (!provs || provs.size === 0 || provs.has(f.cloud_provider)) &&
      (!envs || envs.size === 0 || envs.has(f.environment_type)),
    )
  }, [allFindings, enabledByGroup])

  const toxicComboCount = useMemo(
    () => filteredFindings.filter(f => f.toxic_combo_details).length,
    [filteredFindings],
  )

  // Keyboard: Escape deselects
  useEffect(() => {
    function onKeyDown(e: KeyboardEvent) {
      if (e.key === 'Escape') {
        dispatch({ type: 'SELECT_PATH', payload: null })
        dispatch({ type: 'SELECT_ENTITY', payload: null })
      }
      if (e.key === 'l' || e.key === 'L') {
        if (e.target instanceof HTMLInputElement || e.target instanceof HTMLTextAreaElement) return
        dispatch({ type: 'TOGGLE_LEFT_PANEL' })
      }
    }
    window.addEventListener('keydown', onKeyDown)
    return () => window.removeEventListener('keydown', onKeyDown)
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
      {/* Three-column layout — PaneLayout pattern */}
      <div className="flex flex-1 overflow-hidden">
        {/* Left panel — data layers */}
        <aside
          className="shrink-0 overflow-y-auto border-r border-[#1e2330] transition-all duration-200"
          style={{ width: state.leftPanelOpen ? 240 : 0 }}
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
              onClick={() => dispatch({ type: 'TOGGLE_LEFT_PANEL' })}
              className="absolute z-10 left-1 top-1 p-1.5 bg-[#0d0d14] border border-[#1e2330] text-gray-400 hover:text-gray-200 transition-colors"
              aria-label="Show data layers"
              title="Show layers (L)"
            >
              <Layers className="h-3.5 w-3.5" />
            </button>
          )}
          <CenterPane
            attackPaths={attackPaths}
            allFindings={allFindings}
            filteredFindings={filteredFindings}
            stats={stats ?? undefined}
          />
        </div>

        {/* Right panel — entity detail (slides in on selection) */}
        <aside
          className="shrink-0 overflow-y-auto border-l border-[#1e2330] transition-all duration-200"
          style={{ width: showDetailPanel ? 340 : 0 }}
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
        totalFindings={allFindings.length}
        attackPathCount={attackPaths.length}
        toxicComboCount={toxicComboCount}
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
