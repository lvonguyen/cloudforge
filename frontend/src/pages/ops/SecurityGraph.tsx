import { useState, useMemo, useCallback } from 'react'
import { type Node, type Edge, Position, MarkerType } from '@xyflow/react'
import '@xyflow/react/dist/style.css'
import { BaseGraphView } from '@/components/ops/BaseGraphView'
import { useFindings } from '@/hooks/useFindings'
import { Badge } from '@/components/ui/badge'
import { Network, Search, X, Shield } from 'lucide-react'
import { ProviderBadge } from '@/components/ui/ProviderBadge'
import { SEVERITY_COLORS_BORDERED as SEVERITY_COLORS } from '@/lib/severity'
import type { SecurityGraphNode } from '@/types/security-graph'

const NODE_FILL: Record<string, string> = {
  CRITICAL: '#7f1d1d',
  HIGH: '#7c2d12',
  MEDIUM: '#713f12',
  LOW: '#1e3a5f',
}

const RESOURCE_TYPE_X: Record<string, number> = {
  's3 bucket': 0, 'storage account': 0, 'cloud storage': 0,
  'ec2 instance': 300, 'vm instance': 300, 'virtual machine': 300,
  'rds instance': 600, 'sql database': 600, 'cloud sql': 600,
  'iam role': 900, 'iam user': 900, 'service account': 900,
}

function getXForType(rt: string): number {
  const lower = rt.toLowerCase()
  for (const [key, x] of Object.entries(RESOURCE_TYPE_X)) {
    if (lower.includes(key)) return x
  }
  return 450 // center for unknown types
}

export default function SecurityGraph() {
  const { data: findings = [], isLoading } = useFindings()
  const [selectedNode, setSelectedNode] = useState<SecurityGraphNode | null>(null)
  const [filter, setFilter] = useState('')

  const { graphNodes, graphEdges, nodeMap } = useMemo(() => {
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

    for (const f of findings) {
      // Impacted resources create edges
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
          }
        }
      }

      // Toxic combo related findings
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
        }
      }
    }

    // Position nodes by resource type clusters
    const typeCounters = new Map<number, number>()
    const nodes: Node[] = [...nMap.values()]
      .filter(n => !filter || n.resource_name.toLowerCase().includes(filter.toLowerCase()) || n.resource_type.toLowerCase().includes(filter.toLowerCase()))
      .map(n => {
        const x = getXForType(n.resource_type)
        const count = typeCounters.get(x) ?? 0
        typeCounters.set(x, count + 1)
        return {
          id: n.id,
          position: { x: x + (Math.random() * 60 - 30), y: count * 100 + 50 },
          sourcePosition: Position.Right,
          targetPosition: Position.Left,
          data: {
            label: (
              <div className="px-2 py-1.5 text-left min-w-[140px]" style={{ background: NODE_FILL[n.max_severity] ?? '#1e293b', border: '1px solid #334155' }}>
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

    return { graphNodes: nodes, graphEdges: edges, nodeMap: nMap }
  }, [findings, filter])

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
        </p>
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
