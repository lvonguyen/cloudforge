import { useState, useMemo, useCallback } from 'react'
import { useSearchParams } from 'react-router-dom'
import { type Node, type Edge, Position, MarkerType } from '@xyflow/react'
import '@xyflow/react/dist/style.css'
import { BaseGraphView } from '@/components/ops/BaseGraphView'
import { useFindings } from '@/hooks/useFindings'
import { useGraphNeighborhood, useGraphStats } from '@/hooks/useGraphQuery'
import { Badge } from '@/components/ui/badge'
import { Network, Search, X, Shield, Eye, EyeOff, Activity } from 'lucide-react'
import { ProviderBadge } from '@/components/ui/ProviderBadge'
import { SEVERITY_COLORS_BORDERED as SEVERITY_COLORS } from '@/lib/severity'
import type { SecurityGraphNode, GraphNode as BackendGraphNode, NodeType } from '@/types/security-graph'

const NODE_TONE: Record<string, { background: string; border: string; accent: string; label: string }> = {
  CRITICAL: { background: '#fff1f2', border: '#f43f5e', accent: '#9f1239', label: 'Critical' },
  HIGH: { background: '#fff7ed', border: '#f97316', accent: '#9a3412', label: 'High' },
  MEDIUM: { background: '#fffbeb', border: '#f59e0b', accent: '#92400e', label: 'Medium' },
  LOW: { background: '#eff6ff', border: '#60a5fa', accent: '#1d4ed8', label: 'Low' },
}

const TYPE_TONE: Partial<Record<NodeType, { background: string; border: string; accent: string }>> = {
  finding: { background: '#fff7ed', border: '#fb923c', accent: '#9a3412' },
  resource: { background: '#f8fafc', border: '#94a3b8', accent: '#0f172a' },
  control: { background: '#eff6ff', border: '#60a5fa', accent: '#1d4ed8' },
  issue: { background: '#fff1f2', border: '#fb7185', accent: '#be123c' },
  account: { background: '#f8fafc', border: '#64748b', accent: '#334155' },
  compliance_framework: { background: '#ecfdf5', border: '#34d399', accent: '#047857' },
}

// Edge type styles
const EDGE_STYLES: Record<string, { stroke: string; dash?: string }> = {
  affects: { stroke: '#ef4444' },
  violates: { stroke: '#f59e0b', dash: '5 3' },
  maps_to: { stroke: '#22c55e', dash: '4 4' },
  belongs_to: { stroke: '#64748b' },
  same_region: { stroke: '#3b82f6' },
  same_account: { stroke: '#475569' },
  evaluated_by: { stroke: '#8b5cf6', dash: '3 3' },
  materializes_to: { stroke: '#ef4444', dash: '6 3' },
}

const ANALYST_LANES = {
  evidence: -180,
  controls: 80,
  risk: 360,
  access: 660,
  impact: 960,
} as const

const RESOURCE_LANES: Record<string, number> = {
  storage: ANALYST_LANES.impact,
  bucket: ANALYST_LANES.impact,
  blob: ANALYST_LANES.impact,
  database: ANALYST_LANES.impact,
  rds: ANALYST_LANES.impact,
  sql: ANALYST_LANES.impact,
  dynamodb: ANALYST_LANES.impact,
  cosmos: ANALYST_LANES.impact,
  compute: ANALYST_LANES.risk,
  instance: ANALYST_LANES.risk,
  vm: ANALYST_LANES.risk,
  ec2: ANALYST_LANES.risk,
  lambda: ANALYST_LANES.risk,
  function: ANALYST_LANES.risk,
  container: ANALYST_LANES.risk,
  eks: ANALYST_LANES.risk,
  ecs: ANALYST_LANES.risk,
  kubernetes: ANALYST_LANES.risk,
  pod: ANALYST_LANES.risk,
  network: ANALYST_LANES.access,
  vpc: ANALYST_LANES.access,
  subnet: ANALYST_LANES.access,
  security_group: ANALYST_LANES.access,
  nsg: ANALYST_LANES.access,
  firewall: ANALYST_LANES.access,
  iam: ANALYST_LANES.access,
  role: ANALYST_LANES.access,
  user: ANALYST_LANES.access,
  identity: ANALYST_LANES.access,
  policy: ANALYST_LANES.access,
}

function getLaneForResourceType(rt: string): number {
  const lower = rt.toLowerCase()
  for (const [key, x] of Object.entries(RESOURCE_LANES)) {
    if (lower.includes(key)) return x
  }
  return ANALYST_LANES.risk
}

function getLaneForBackendNode(n: BackendGraphNode): number {
  if (n.type === 'account' || n.type === 'compliance_framework') return ANALYST_LANES.evidence
  if (n.type === 'control') return ANALYST_LANES.controls
  if (n.type === 'issue' || n.type === 'finding') return ANALYST_LANES.risk
  if (n.type === 'resource') return getLaneForResourceType(n.props?.detail ?? n.type)
  return ANALYST_LANES.risk
}

function resourceTypeLabel(resourceType: string): string {
  const lower = resourceType.toLowerCase()
  if (lower.includes('iam') || lower.includes('role') || lower.includes('identity') || lower.includes('user')) return 'Identity / Access'
  if (lower.includes('vpc') || lower.includes('subnet') || lower.includes('security_group') || lower.includes('firewall') || lower.includes('network')) return 'Network Exposure'
  if (lower.includes('bucket') || lower.includes('storage') || lower.includes('blob') || lower.includes('database') || lower.includes('rds') || lower.includes('sql') || lower.includes('dynamodb') || lower.includes('cosmos')) return 'Data / Crown Jewel'
  if (lower.includes('container') || lower.includes('eks') || lower.includes('ecs') || lower.includes('kubernetes') || lower.includes('pod')) return 'Runtime / Workload'
  return 'Compute / Workload'
}

function laneLabelForNodeType(type: NodeType, detail?: string): string {
  switch (type) {
    case 'account':
      return 'Tenant / Account'
    case 'compliance_framework':
      return 'Framework Context'
    case 'control':
      return 'Control Logic'
    case 'issue':
      return 'Materialized Issue'
    case 'finding':
      return 'Finding Evidence'
    case 'resource':
      return resourceTypeLabel(detail ?? type)
    default:
      return 'Risk Context'
  }
}

function laneHeaderForX(x: number): string {
  if (x === ANALYST_LANES.evidence) return 'Tenant / Framework'
  if (x === ANALYST_LANES.controls) return 'Controls'
  if (x === ANALYST_LANES.risk) return 'Findings / Issues'
  if (x === ANALYST_LANES.access) return 'Access / Exposure'
  if (x === ANALYST_LANES.impact) return 'Impact / Crown Jewels'
  return 'Analyst View'
}

function laneSummaryForX(x: number): string {
  if (x === ANALYST_LANES.evidence) return 'Accounts, frameworks, and scope anchors'
  if (x === ANALYST_LANES.controls) return 'Graph rules and evaluation logic'
  if (x === ANALYST_LANES.risk) return 'Primary issue and finding evidence'
  if (x === ANALYST_LANES.access) return 'Identity or network pivots'
  if (x === ANALYST_LANES.impact) return 'Likely blast radius or data impact'
  return 'Security graph context'
}

const MAX_BFS_NODES = 500

function bfsNeighborhood(seedId: string, adjacency: Map<string, Set<string>>, maxHops: number): Set<string> {
  const visited = new Set<string>([seedId])
  let frontier = [seedId]
  for (let hop = 0; hop < maxHops && frontier.length > 0; hop++) {
    const next: string[] = []
    for (const nodeId of frontier) {
      for (const neighbor of adjacency.get(nodeId) ?? []) {
        if (!visited.has(neighbor)) {
          visited.add(neighbor)
          next.push(neighbor)
          if (visited.size >= MAX_BFS_NODES) return visited
        }
      }
    }
    frontier = next
  }
  return visited
}

/** Convert a backend GraphNode to a ReactFlow Node with visual styling. */
function backendNodeToReactFlow(
  n: BackendGraphNode,
  laneIndex: number,
  focusId: string | null,
): Node {
  const x = getLaneForBackendNode(n)
  const isFocused = n.id === focusId
  const tone = TYPE_TONE[n.type] ?? TYPE_TONE.resource!
  const severityTone = n.props?.detail ? NODE_TONE[n.props.detail] : null

  return {
    id: n.id,
    position: { x, y: laneIndex * 112 + 70 },
    sourcePosition: Position.Right,
    targetPosition: Position.Left,
    data: {
      label: (
        <div className="min-w-[170px] rounded-xl border px-3 py-2 text-left shadow-sm" style={{
          background: severityTone?.background ?? tone.background,
          borderColor: isFocused ? '#2563eb' : (severityTone?.border ?? tone.border),
          borderWidth: isFocused ? 2.5 : 1.5,
        }}>
          <div className="flex items-center justify-between gap-2">
            <span className="text-[10px] font-semibold uppercase tracking-[0.16em]" style={{ color: severityTone?.accent ?? tone.accent }}>
              {severityTone?.label ?? laneLabelForNodeType(n.type, n.props?.detail)}
            </span>
            <span className="rounded-full px-2 py-0.5 text-[9px] font-medium" style={{ color: tone.accent, background: 'rgba(255,255,255,0.72)' }}>
              {n.type}
            </span>
          </div>
          <div className="mt-1 text-[11px] font-semibold text-slate-900 truncate">{n.label}</div>
          <div className="mt-1 text-[10px] text-slate-500">
            {laneHeaderForX(x)}
          </div>
        </div>
      ),
    },
    style: { padding: 0, borderRadius: 0, background: 'transparent', border: 'none' },
  }
}

export default function SecurityGraph() {
  const { data: findings = [], isLoading: findingsLoading } = useFindings()
  const [searchParams] = useSearchParams()
  const rawFocus = searchParams.get('focus')
  const focusResourceId = rawFocus && rawFocus.length <= 256 ? rawFocus : null
  const [selectedNode, setSelectedNode] = useState<SecurityGraphNode | null>(null)
  const [filter, setFilter] = useState('')
  const [showAll, setShowAll] = useState(false)

  // Pick a seed node for backend graph query: focused resource, or the first
  // CRITICAL/HIGH finding's resource as a meaningful default entry point.
  const defaultSeed = useMemo(() => {
    if (focusResourceId) return { type: 'resource' as const, id: focusResourceId }
    const critical = findings.find(f => f.severity === 'CRITICAL' || f.severity === 'HIGH')
    if (critical?.resource_id) return { type: 'resource' as const, id: critical.resource_id }
    return null
  }, [focusResourceId, findings])

  // Backend graph neighborhood query — always attempts when a seed exists
  const { data: backendGraph } = useGraphNeighborhood(
    defaultSeed?.type ?? null,
    defaultSeed?.id ?? null,
    2,
    150,
  )

  // Backend graph stats
  const { data: graphStats } = useGraphStats()

  // Convert backend graph data to ReactFlow nodes/edges when available
  const backendView = useMemo(() => {
    if (!backendGraph?.nodes?.length) return null

    const laneCounters = new Map<number, number>()
    const nodes: Node[] = backendGraph.nodes.map((n) => {
      const lane = getLaneForBackendNode(n)
      const laneIndex = laneCounters.get(lane) ?? 0
      laneCounters.set(lane, laneIndex + 1)
      return backendNodeToReactFlow(n, laneIndex, focusResourceId)
    })

    const edges: Edge[] = (backendGraph.edges ?? []).map((e, i) => {
      const style = EDGE_STYLES[e.type] ?? { stroke: '#475569' }
      return {
        id: `be-${i}`,
        source: e.source,
        target: e.target,
        animated: e.type === 'affects' || e.type === 'violates',
        style: { stroke: style.stroke, strokeWidth: 2, ...(style.dash ? { strokeDasharray: style.dash } : {}) },
        markerEnd: { type: MarkerType.ArrowClosed, color: style.stroke, width: 10, height: 10 },
        label: e.type.replace(/_/g, ' '),
        labelStyle: { fontSize: 10, fill: '#64748b' },
      }
    })

    return { nodes, edges, laneCounts: laneCounters }
  }, [backendGraph, focusResourceId])

  // Client-side fallback: build graph from flat findings (existing logic)
  const clientView = useMemo(() => {
    const nMap = new Map<string, SecurityGraphNode>()

    for (const f of findings) {
      const existing = nMap.get(f.resource_id)
      if (existing) {
        existing.finding_count++
        const sevOrder = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']
        if (sevOrder.indexOf(f.severity) < sevOrder.indexOf(existing.max_severity)) {
          existing.max_severity = f.severity
        }
      } else {
        nMap.set(f.resource_id, {
          id: f.resource_id,
          resource_id: f.resource_id,
          resource_name: f.resource_name,
          resource_type: f.resource_type,
          provider: f.cloud_provider,
          region: f.region,
          finding_count: 1,
          max_severity: f.severity,
        })
      }
    }

    const edgeSet = new Set<string>()
    const edges: Edge[] = []
    const adjacency = new Map<string, Set<string>>()

    const addAdjacency = (a: string, b: string) => {
      if (!adjacency.has(a)) adjacency.set(a, new Set())
      if (!adjacency.has(b)) adjacency.set(b, new Set())
      adjacency.get(a)!.add(b)
      adjacency.get(b)!.add(a)
    }

    for (const f of findings) {
      if (f.impacted_resources) {
        for (const ir of f.impacted_resources) {
          const target = ir.resource_id
          if (!target || target === f.resource_id) continue
          const key = `${f.resource_id}->${target}`
          if (edgeSet.has(key)) continue
          edgeSet.add(key)
          if (nMap.has(target)) {
            edges.push({
              id: key,
              source: f.resource_id,
              target,
              animated: true,
              style: { stroke: '#3b82f6', strokeWidth: 1 },
              markerEnd: { type: MarkerType.ArrowClosed, color: '#3b82f6', width: 12, height: 12 },
            })
            addAdjacency(f.resource_id, target)
          }
        }
      }

      if (f.toxic_combo_details?.related_findings) {
        for (const rf of f.toxic_combo_details.related_findings) {
          const relFinding = findings.find(ff => ff.id === rf)
          if (!relFinding || relFinding.resource_id === f.resource_id) continue
          const key = [f.resource_id, relFinding.resource_id].sort().join('<->')
          if (edgeSet.has(key)) continue
          edgeSet.add(key)
          edges.push({
            id: key,
            source: f.resource_id,
            target: relFinding.resource_id,
            animated: true,
            style: { stroke: '#ef4444', strokeWidth: 2, strokeDasharray: '5 5' },
          })
          addAdjacency(f.resource_id, relFinding.resource_id)
        }
      }
    }

    const connectedIds = new Set<string>()
    for (const [id, neighbors] of adjacency) {
      if (neighbors.size > 0) {
        connectedIds.add(id)
        for (const n of neighbors) connectedIds.add(n)
      }
    }

    let visibleIds: Set<string>
    if (focusResourceId && nMap.has(focusResourceId)) {
      visibleIds = bfsNeighborhood(focusResourceId, adjacency, 2)
      if (visibleIds.size <= 1) {
        const focusNode = nMap.get(focusResourceId)!
        for (const [nodeId, node] of nMap) {
          if (node.provider === focusNode.provider && node.region === focusNode.region) {
            visibleIds.add(nodeId)
            if (visibleIds.size > 50) break
          }
        }
      }
    } else if (showAll) {
      visibleIds = new Set(nMap.keys())
    } else {
      visibleIds = connectedIds
    }

    const filterLower = filter.toLowerCase()
    const typeCounters = new Map<number, number>()
    const nodes: Node[] = [...nMap.values()]
      .filter(n => visibleIds.has(n.id))
      .filter(n => !filter || n.resource_name.toLowerCase().includes(filterLower) || n.resource_type.toLowerCase().includes(filterLower))
      .map(n => {
        const x = getLaneForResourceType(n.resource_type)
        const count = typeCounters.get(x) ?? 0
        typeCounters.set(x, count + 1)
        const isFocused = n.id === focusResourceId
        const tone = NODE_TONE[n.max_severity] ?? NODE_TONE.LOW
        return {
          id: n.id,
          position: { x, y: count * 112 + 70 },
          sourcePosition: Position.Right,
          targetPosition: Position.Left,
          data: {
            label: (
              <div className="min-w-[178px] rounded-xl border px-3 py-2 text-left shadow-sm" style={{
                background: tone.background,
                borderColor: isFocused ? '#2563eb' : tone.border,
                borderWidth: isFocused ? 2.5 : 1.5,
              }}>
                <div className="flex items-center justify-between gap-2">
                  <span className="text-[10px] font-semibold uppercase tracking-[0.16em]" style={{ color: tone.accent }}>
                    {resourceTypeLabel(n.resource_type)}
                  </span>
                  <span className="rounded-full px-2 py-0.5 text-[9px] font-medium" style={{ color: tone.accent, background: 'rgba(255,255,255,0.72)' }}>
                    {n.max_severity}
                  </span>
                </div>
                <div className="mt-1 text-[11px] font-semibold text-slate-900 truncate">{n.resource_name}</div>
                <div className="mt-1 text-[10px] text-slate-500">{n.resource_type}</div>
                <div className="mt-2 flex items-center justify-between gap-2 text-[10px] text-slate-600">
                  <span>{n.finding_count} finding{n.finding_count !== 1 ? 's' : ''}</span>
                  <span>{laneHeaderForX(x)}</span>
                </div>
              </div>
            ),
          },
          style: { padding: 0, borderRadius: 0, background: 'transparent', border: 'none' },
        }
      })

    const visibleEdges = edges.filter(e => visibleIds.has(e.source as string) && visibleIds.has(e.target as string))

    return { graphNodes: nodes, graphEdges: visibleEdges, nodeMap: nMap, connectedCount: connectedIds.size, totalCount: nMap.size, laneCounts: typeCounters }
  }, [findings, filter, focusResourceId, showAll])

  // Use backend data when available (DB configured + graph populated), otherwise client-side
  const useBackend = !!backendView
  const graphNodes = useBackend ? backendView.nodes : clientView.graphNodes
  const graphEdges = useBackend ? backendView.edges : clientView.graphEdges
  const laneCounts = useBackend ? (backendView?.laneCounts ?? new Map<number, number>()) : clientView.laneCounts

  // Build a lookup map from backend nodes for click handling
  const backendNodeMap = useMemo(() => {
    if (!backendGraph?.nodes) return new Map<string, SecurityGraphNode>()
    const m = new Map<string, SecurityGraphNode>()
    for (const n of backendGraph.nodes) {
      m.set(n.id, {
        id: n.id,
        resource_id: n.id,
        resource_name: n.label,
        resource_type: n.props?.detail ?? n.type,
        provider: n.props?.provider ?? '',
        region: n.props?.region ?? '',
        finding_count: 0,
        max_severity: n.props?.detail ?? 'LOW',
      })
    }
    return m
  }, [backendGraph])

  const handleNodeClick = useCallback((nodeId: string) => {
    const node = useBackend
      ? (backendNodeMap.get(nodeId) ?? clientView.nodeMap.get(nodeId) ?? null)
      : (clientView.nodeMap.get(nodeId) ?? null)
    setSelectedNode(node)
  }, [useBackend, backendNodeMap, clientView.nodeMap])

  if (findingsLoading) return <div className="text-sm text-muted-foreground p-4">Loading security graph...</div>

  return (
    <div className="flex h-full gap-0">
      {/* Left filter panel */}
      <div className="w-72 border-r border-slate-200 bg-white p-4 space-y-4 shrink-0 overflow-y-auto">
        <div className="flex items-center gap-2">
          <Network className="h-4 w-4 text-sky-600" />
          <h2 className="text-sm font-semibold">Security Graph</h2>
        </div>
        <p className="text-[10px] text-slate-500">
          {graphNodes.length} nodes · {graphEdges.length} edges
          {useBackend && <span className="text-sky-600 ml-1">(live)</span>}
          {!useBackend && !showAll && !focusResourceId && clientView.connectedCount < clientView.totalCount && (
            <span> (of {clientView.totalCount} total)</span>
          )}
        </p>

        <div className="rounded-2xl border border-slate-200 bg-slate-50/90 p-3 shadow-sm">
          <div className="text-[10px] font-semibold uppercase tracking-[0.16em] text-slate-500">
            Analyst Flow
          </div>
          <div className="mt-2 space-y-2">
            {[ANALYST_LANES.evidence, ANALYST_LANES.controls, ANALYST_LANES.risk, ANALYST_LANES.access, ANALYST_LANES.impact].map((lane) => (
              <div key={lane} className="rounded-xl border border-slate-200 bg-white px-3 py-2">
                <div className="flex items-center justify-between gap-2 text-[11px] font-semibold text-slate-800">
                  <span>{laneHeaderForX(lane)}</span>
                  <span className="rounded-full bg-slate-100 px-2 py-0.5 text-[10px] font-medium text-slate-600">
                    {laneCounts.get(lane) ?? 0}
                  </span>
                </div>
                <p className="mt-1 text-[10px] text-slate-500">{laneSummaryForX(lane)}</p>
              </div>
            ))}
          </div>
        </div>

        {/* Graph stats from backend */}
        {graphStats && (
          <div className="rounded-2xl border border-slate-200 bg-slate-50/90 p-3 space-y-2 shadow-sm">
            <div className="flex items-center gap-1.5 text-[10px] font-medium uppercase tracking-[0.16em] text-slate-500">
              <Activity className="h-3 w-3" />
              Graph Stats
            </div>
            <div className="grid grid-cols-2 gap-x-2 gap-y-1 text-[10px]">
              {Object.entries(graphStats.vertices).map(([type, count]) => (
                <div key={type} className="flex justify-between gap-2">
                  <span className="text-slate-500">{type}</span>
                  <span className="text-slate-900 font-mono">{count.toLocaleString()}</span>
                </div>
              ))}
            </div>
            <div className="text-[10px] text-slate-500 pt-2 border-t border-slate-200">
              {graphStats.total_vertices.toLocaleString()} vertices · {graphStats.total_edges.toLocaleString()} edges
            </div>
          </div>
        )}

        {focusResourceId && (
          <Badge variant="outline" className="text-[10px]">
            Focused: {clientView.nodeMap.get(focusResourceId)?.resource_name ?? focusResourceId}
          </Badge>
        )}
        <div className="relative">
          <Search className="absolute left-2 top-1/2 -translate-y-1/2 h-3.5 w-3.5 text-muted-foreground" />
          <input
            type="text"
            value={filter}
            onChange={e => setFilter(e.target.value)}
            placeholder="Filter resources..."
            className="w-full rounded-xl border border-slate-200 bg-slate-50 pl-7 pr-2 py-2 text-xs outline-none focus:border-sky-400 focus:bg-white"
          />
          {filter && (
            <button onClick={() => setFilter('')} className="absolute right-2 top-1/2 -translate-y-1/2">
              <X className="h-3 w-3 text-muted-foreground" />
            </button>
          )}
        </div>
        {!focusResourceId && (
          <button
            onClick={() => setShowAll(v => !v)}
            className="flex items-center gap-1.5 text-[10px] text-slate-500 hover:text-slate-900 transition-colors"
          >
            {showAll ? <EyeOff className="h-3 w-3" /> : <Eye className="h-3 w-3" />}
            {showAll ? 'Connected only' : 'Show all resources'}
          </button>
        )}
        <div className="rounded-2xl border border-slate-200 bg-white p-3 text-[10px] text-slate-500 space-y-1.5 shadow-sm">
          <div className="font-semibold uppercase tracking-[0.16em] text-slate-500">Edge Legend</div>
          <div className="flex items-center gap-1.5"><span className="h-2.5 w-2.5 rounded-full" style={{ background: '#ef4444' }} />Affects</div>
          <div className="flex items-center gap-1.5"><span className="h-2.5 w-2.5 rounded-full" style={{ background: '#f59e0b' }} />Violates</div>
          <div className="flex items-center gap-1.5"><span className="h-2.5 w-2.5 rounded-full" style={{ background: '#3b82f6' }} />Same region</div>
          <div className="flex items-center gap-1.5"><span className="h-2.5 w-2.5 rounded-full" style={{ background: '#22c55e' }} />Maps to</div>
          <div className="flex items-center gap-1.5"><span className="h-2.5 w-2.5 rounded-full" style={{ background: '#64748b' }} />Belongs to</div>
        </div>
      </div>

      {/* Graph area */}
      <div className="flex-1 relative bg-slate-100/60">
        <BaseGraphView nodes={graphNodes} edges={graphEdges} onNodeClick={handleNodeClick} height="h-full" tone="light" />
      </div>

      {/* Right detail panel */}
      {selectedNode && (
        <div className="w-80 border-l border-slate-200 bg-white p-4 space-y-3 shrink-0 overflow-y-auto">
          <div className="flex items-center justify-between">
            <h3 className="text-xs font-semibold">Resource Detail</h3>
            <button onClick={() => setSelectedNode(null)} className="rounded-md p-1 hover:bg-slate-100">
              <X className="h-3.5 w-3.5" />
            </button>
          </div>
          <div className="rounded-2xl border border-slate-200 bg-slate-50/80 p-4 space-y-3 text-xs shadow-sm">
            <div>
              <span className="text-slate-500">Name</span>
              <p className="font-medium text-slate-950">{selectedNode.resource_name}</p>
            </div>
            <div>
              <span className="text-slate-500">Type</span>
              <p className="text-slate-800">{selectedNode.resource_type}</p>
            </div>
            <div className="flex items-center gap-2">
              <ProviderBadge provider={selectedNode.provider} />
              <span className="text-slate-500">{selectedNode.region}</span>
            </div>
            <div className="flex items-center gap-2">
              <Shield className="h-3.5 w-3.5 text-slate-500" />
              <Badge variant="outline" className={`text-[10px] ${SEVERITY_COLORS[selectedNode.max_severity] ?? ''}`}>
                {selectedNode.max_severity}
              </Badge>
              <span className="text-slate-500">{selectedNode.finding_count} finding{selectedNode.finding_count !== 1 ? 's' : ''}</span>
            </div>
            <div className="rounded-xl border border-slate-200 bg-white px-3 py-2 text-[11px] text-slate-600">
              This panel is intended to support the analyst story: trace evidence left-to-right from tenant and controls into the issue, then pivot through access exposure toward impacted resources.
            </div>
          </div>
        </div>
      )}
    </div>
  )
}
