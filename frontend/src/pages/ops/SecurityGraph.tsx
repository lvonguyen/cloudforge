import { useState, useMemo, useCallback } from 'react'
import { useSearchParams } from 'react-router-dom'
import { type Node, type Edge, Position, MarkerType } from '@xyflow/react'
import '@xyflow/react/dist/style.css'
import { BaseGraphView } from '@/components/ops/BaseGraphView'
import { useFindings } from '@/hooks/useFindings'
import { Badge } from '@/components/ui/badge'
import { Network, Search, X, Shield, Eye, EyeOff } from 'lucide-react'
import { ProviderBadge } from '@/components/ui/ProviderBadge'
import { SEVERITY_COLORS_BORDERED as SEVERITY_COLORS } from '@/lib/severity'
import type { SecurityGraphNode } from '@/types/security-graph'

const NODE_FILL: Record<string, string> = {
  CRITICAL: '#7f1d1d',
  HIGH: '#7c2d12',
  MEDIUM: '#713f12',
  LOW: '#1e3a5f',
}

// Deterministic x-position based on resource_type string hash for cluster distribution.
const TYPE_LANES: Record<string, number> = {
  storage: 0, bucket: 0, blob: 0,
  compute: 200, instance: 200, vm: 200, ec2: 200, lambda: 200, function: 200,
  database: 400, rds: 400, sql: 400, dynamodb: 400, cosmos: 400,
  network: 600, vpc: 600, subnet: 600, security_group: 600, nsg: 600, firewall: 600,
  iam: 800, role: 800, user: 800, identity: 800, policy: 800,
  container: 1000, eks: 1000, ecs: 1000, kubernetes: 1000, pod: 1000,
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

/** BFS to find all nodes within N hops of a seed node. */
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
        }
      }
    }
    frontier = next
  }
  return visited
}

export default function SecurityGraph() {
  const { data: findings = [], isLoading } = useFindings()
  const [searchParams] = useSearchParams()
  const focusResourceId = searchParams.get('focus')
  const [selectedNode, setSelectedNode] = useState<SecurityGraphNode | null>(null)
  const [filter, setFilter] = useState('')
  const [showAll, setShowAll] = useState(false)

  const { graphNodes, graphEdges, nodeMap, connectedCount, totalCount } = useMemo(() => {
    const nMap = new Map<string, SecurityGraphNode>()

    // Build unique resource nodes from findings
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

    // Build edges from impacted_resources and toxic_combo_details
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

    // Determine which nodes to show
    const connectedIds = new Set<string>()
    for (const [id, neighbors] of adjacency) {
      if (neighbors.size > 0) {
        connectedIds.add(id)
        for (const n of neighbors) connectedIds.add(n)
      }
    }

    let visibleIds: Set<string>
    if (focusResourceId && nMap.has(focusResourceId)) {
      // Focus mode: 2-hop neighborhood around the focused resource
      visibleIds = bfsNeighborhood(focusResourceId, adjacency, 2)
      // If no edges exist for focused resource, show same-account + same-region (1-hop context)
      if (visibleIds.size <= 1) {
        const focusNode = nMap.get(focusResourceId)!
        for (const [nodeId, node] of nMap) {
          if (node.provider === focusNode.provider && node.region === focusNode.region) {
            visibleIds.add(nodeId)
            if (visibleIds.size > 50) break // cap neighborhood
          }
        }
      }
    } else if (showAll) {
      visibleIds = new Set(nMap.keys())
    } else {
      // Default: connected subgraphs only
      visibleIds = connectedIds
    }

    // Apply text filter
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
        return {
          id: n.id,
          position: { x: x + (Math.random() * 60 - 30), y: count * 100 + 50 },
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

    // Filter edges to only include visible nodes
    const visibleEdges = edges.filter(e => visibleIds.has(e.source as string) && visibleIds.has(e.target as string))

    return { graphNodes: nodes, graphEdges: visibleEdges, nodeMap: nMap, connectedCount: connectedIds.size, totalCount: nMap.size }
  }, [findings, filter, focusResourceId, showAll])

  const handleNodeClick = useCallback((nodeId: string) => {
    setSelectedNode(nodeMap.get(nodeId) ?? null)
  }, [nodeMap])

  if (isLoading) return <div className="text-sm text-muted-foreground p-4">Loading security graph...</div>

  return (
    <div className="flex h-full gap-0">
      {/* Left filter panel */}
      <div className="w-64 border-r border-border bg-background p-4 space-y-4 shrink-0 overflow-y-auto">
        <div className="flex items-center gap-2">
          <Network className="h-4 w-4 text-blue-500" />
          <h2 className="text-sm font-semibold">Security Graph</h2>
        </div>
        <p className="text-[10px] text-muted-foreground">
          {graphNodes.length} resources · {graphEdges.length} connections
          {!showAll && !focusResourceId && connectedCount < totalCount && (
            <span> (of {totalCount} total)</span>
          )}
        </p>
        {focusResourceId && (
          <Badge variant="outline" className="text-[10px]">
            Focused: {nodeMap.get(focusResourceId)?.resource_name ?? focusResourceId}
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
          <div className="flex items-center gap-1.5"><span className="h-2 w-2 bg-[#3b82f6]" />Impact edges</div>
          <div className="flex items-center gap-1.5"><span className="h-2 w-2 bg-[#ef4444]" />Toxic combo links</div>
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
