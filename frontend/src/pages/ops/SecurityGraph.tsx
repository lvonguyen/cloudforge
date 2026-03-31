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

const NODE_FILL: Record<string, string> = {
  CRITICAL: '#7f1d1d',
  HIGH: '#7c2d12',
  MEDIUM: '#713f12',
  LOW: '#1e3a5f',
}

// Node type colors for graph-native vertex types
const TYPE_FILL: Partial<Record<NodeType, string>> = {
  finding: '#7c2d12',
  resource: '#1e3a5f',
  control: '#1e40af',
  issue: '#7f1d1d',
  account: '#334155',
  compliance_framework: '#065f46',
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

// Type-lane x-positions for clustering
const TYPE_LANES: Record<string, number> = {
  storage: 0, bucket: 0, blob: 0,
  compute: 200, instance: 200, vm: 200, ec2: 200, lambda: 200, function: 200,
  database: 400, rds: 400, sql: 400, dynamodb: 400, cosmos: 400,
  network: 600, vpc: 600, subnet: 600, security_group: 600, nsg: 600, firewall: 600,
  iam: 800, role: 800, user: 800, identity: 800, policy: 800,
  container: 1000, eks: 1000, ecs: 1000, kubernetes: 1000, pod: 1000,
  // Graph-native node types get their own lanes
  control: 1200, issue: 1400, account: -200, compliance_framework: -400,
}

function getXForType(rt: string): number {
  const lower = rt.toLowerCase()
  for (const [key, x] of Object.entries(TYPE_LANES)) {
    if (lower.includes(key)) return x
  }
  let hash = 0
  for (let i = 0; i < lower.length; i++) hash = ((hash << 5) - hash + lower.charCodeAt(i)) | 0
  return (Math.abs(hash) % 6) * 200
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
  index: number,
  focusId: string | null,
): Node {
  const x = getXForType(n.type === 'resource' ? (n.props?.detail ?? n.type) : n.type)
  const idHash = n.id.split('').reduce((h, c) => ((h << 5) - h + c.charCodeAt(0)) | 0, 0)
  const jitter = (Math.abs(idHash) % 60) - 30
  const isFocused = n.id === focusId
  const fill = TYPE_FILL[n.type] ?? '#1e293b'
  const sevFill = n.props?.detail ? (NODE_FILL[n.props.detail] ?? fill) : fill

  return {
    id: n.id,
    position: { x: x + jitter, y: index * 90 + 50 },
    sourcePosition: Position.Right,
    targetPosition: Position.Left,
    data: {
      label: (
        <div className="px-2 py-1.5 text-left min-w-[130px]" style={{
          background: sevFill,
          border: isFocused ? '3px solid #3b82f6' : '1px solid #334155',
          borderRadius: n.type === 'control' || n.type === 'compliance_framework' ? '6px' : '0',
        }}>
          <div className="text-[10px] font-medium text-white truncate">{n.label}</div>
          <div className="text-[9px] text-gray-400">{n.type}</div>
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

    const nodes: Node[] = backendGraph.nodes.map((n, i) =>
      backendNodeToReactFlow(n, i, focusResourceId),
    )

    const edges: Edge[] = (backendGraph.edges ?? []).map((e, i) => {
      const style = EDGE_STYLES[e.type] ?? { stroke: '#475569' }
      return {
        id: `be-${i}`,
        source: e.source,
        target: e.target,
        animated: e.type === 'affects' || e.type === 'violates',
        style: { stroke: style.stroke, strokeWidth: 1.5, ...(style.dash ? { strokeDasharray: style.dash } : {}) },
        markerEnd: { type: MarkerType.ArrowClosed, color: style.stroke, width: 10, height: 10 },
        label: e.type.replace(/_/g, ' '),
        labelStyle: { fontSize: 9, fill: '#94a3b8' },
      }
    })

    return { nodes, edges }
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
        const x = getXForType(n.resource_type)
        const count = typeCounters.get(x) ?? 0
        typeCounters.set(x, count + 1)
        const isFocused = n.id === focusResourceId
        const idHash = n.id.split('').reduce((h, c) => ((h << 5) - h + c.charCodeAt(0)) | 0, 0)
        const jitter = (Math.abs(idHash) % 60) - 30
        return {
          id: n.id,
          position: { x: x + jitter, y: count * 100 + 50 },
          sourcePosition: Position.Right,
          targetPosition: Position.Left,
          data: {
            label: (
              <div className="px-2 py-1.5 text-left min-w-[140px]" style={{
                background: NODE_FILL[n.max_severity] ?? '#1e293b',
                border: isFocused ? '3px solid #3b82f6' : '1px solid #334155',
              }}>
                <div className="text-[10px] font-medium text-white truncate">{n.resource_name}</div>
                <div className="text-[9px] text-gray-400">{n.resource_type}</div>
                <div className="flex items-center gap-1 mt-0.5">
                  <span className="text-[9px] text-gray-500">{n.finding_count} finding{n.finding_count !== 1 ? 's' : ''}</span>
                </div>
              </div>
            ),
          },
          style: { padding: 0, borderRadius: 0, background: 'transparent', border: 'none' },
        }
      })

    const visibleEdges = edges.filter(e => visibleIds.has(e.source as string) && visibleIds.has(e.target as string))

    return { graphNodes: nodes, graphEdges: visibleEdges, nodeMap: nMap, connectedCount: connectedIds.size, totalCount: nMap.size }
  }, [findings, filter, focusResourceId, showAll])

  // Use backend data when available (DB configured + graph populated), otherwise client-side
  const useBackend = !!backendView
  const graphNodes = useBackend ? backendView.nodes : clientView.graphNodes
  const graphEdges = useBackend ? backendView.edges : clientView.graphEdges

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
      <div className="w-64 border-r border-border bg-background p-4 space-y-4 shrink-0 overflow-y-auto">
        <div className="flex items-center gap-2">
          <Network className="h-4 w-4 text-blue-500" />
          <h2 className="text-sm font-semibold">Security Graph</h2>
        </div>
        <p className="text-[10px] text-muted-foreground">
          {graphNodes.length} nodes · {graphEdges.length} edges
          {useBackend && <span className="text-blue-400 ml-1">(live)</span>}
          {!useBackend && !showAll && !focusResourceId && clientView.connectedCount < clientView.totalCount && (
            <span> (of {clientView.totalCount} total)</span>
          )}
        </p>

        {/* Graph stats from backend */}
        {graphStats && (
          <div className="border border-border p-2 space-y-1">
            <div className="flex items-center gap-1.5 text-[10px] font-medium text-muted-foreground">
              <Activity className="h-3 w-3" />
              Graph Stats
            </div>
            <div className="grid grid-cols-2 gap-x-2 gap-y-0.5 text-[9px]">
              {Object.entries(graphStats.vertices).map(([type, count]) => (
                <div key={type} className="flex justify-between">
                  <span className="text-muted-foreground">{type}</span>
                  <span className="text-foreground font-mono">{count.toLocaleString()}</span>
                </div>
              ))}
            </div>
            <div className="text-[9px] text-muted-foreground pt-1 border-t border-border">
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
            className="w-full pl-7 pr-2 py-1.5 text-xs bg-muted/50 border border-border outline-none"
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
            className="flex items-center gap-1.5 text-[10px] text-muted-foreground hover:text-foreground transition-colors"
          >
            {showAll ? <EyeOff className="h-3 w-3" /> : <Eye className="h-3 w-3" />}
            {showAll ? 'Connected only' : 'Show all resources'}
          </button>
        )}
        <div className="text-[10px] text-muted-foreground space-y-1">
          <div className="flex items-center gap-1.5"><span className="h-2 w-2 rounded-sm" style={{ background: '#ef4444' }} />affects</div>
          <div className="flex items-center gap-1.5"><span className="h-2 w-2 rounded-sm" style={{ background: '#f59e0b' }} />violates</div>
          <div className="flex items-center gap-1.5"><span className="h-2 w-2 rounded-sm" style={{ background: '#3b82f6' }} />same region</div>
          <div className="flex items-center gap-1.5"><span className="h-2 w-2 rounded-sm" style={{ background: '#22c55e' }} />maps to</div>
          <div className="flex items-center gap-1.5"><span className="h-2 w-2 rounded-sm" style={{ background: '#64748b' }} />belongs to</div>
        </div>
      </div>

      {/* Graph area */}
      <div className="flex-1 relative">
        <BaseGraphView nodes={graphNodes} edges={graphEdges} onNodeClick={handleNodeClick} height="h-full" />
      </div>

      {/* Right detail panel */}
      {selectedNode && (
        <div className="w-72 border-l border-border bg-background p-4 space-y-3 shrink-0 overflow-y-auto">
          <div className="flex items-center justify-between">
            <h3 className="text-xs font-semibold">Resource Detail</h3>
            <button onClick={() => setSelectedNode(null)} className="p-0.5 hover:bg-muted">
              <X className="h-3.5 w-3.5" />
            </button>
          </div>
          <div className="space-y-2 text-xs">
            <div>
              <span className="text-muted-foreground">Name</span>
              <p className="font-medium">{selectedNode.resource_name}</p>
            </div>
            <div>
              <span className="text-muted-foreground">Type</span>
              <p>{selectedNode.resource_type}</p>
            </div>
            <div className="flex items-center gap-2">
              <ProviderBadge provider={selectedNode.provider} />
              <span className="text-muted-foreground">{selectedNode.region}</span>
            </div>
            <div className="flex items-center gap-2">
              <Shield className="h-3.5 w-3.5" />
              <Badge variant="outline" className={`text-[10px] ${SEVERITY_COLORS[selectedNode.max_severity] ?? ''}`}>
                {selectedNode.max_severity}
              </Badge>
              <span className="text-muted-foreground">{selectedNode.finding_count} finding{selectedNode.finding_count !== 1 ? 's' : ''}</span>
            </div>
          </div>
        </div>
      )}
    </div>
  )
}
