import {
  type Edge,
  type Node,
  MarkerType,
  Position,
} from '@xyflow/react'
import { SEVERITY_COLORS_BORDERED as SEVERITY_COLORS, SEVERITY_HEX, SEVERITY_NEUTRAL_HEX } from '@/lib/severity'
import type { AttackPath, AttackPathNode } from '@/types/attack-path'

function AttackPathFlowNodeLabel({ node }: { node: AttackPathNode }) {
  return (
    <div className="text-left px-2 py-1">
      <div className="flex items-center gap-1 mb-0.5">
        <span className={`text-[10px] font-bold px-1 py-0 ${SEVERITY_COLORS[node.severity] ?? ''}`}>
          {node.severity}
        </span>
        <span className="text-[10px] text-slate-500">{node.category}</span>
      </div>
      <div className="text-xs font-medium text-slate-950 truncate max-w-[200px]">
        {node.resource_name}
      </div>
      <div className="text-[11px] text-slate-500">{node.resource_type} · {node.region}</div>
    </div>
  )
}

export function pathToFlow(path: AttackPath): { nodes: Node[]; edges: Edge[] } {
  const nodes: Node[] = path.nodes.map((node, index) => ({
    id: node.id,
    position: { x: index * 340, y: 0 },
    data: {
      label: <AttackPathFlowNodeLabel node={node} />,
      severity: node.severity,
      findingId: node.finding_id,
    },
    sourcePosition: Position.Right,
    targetPosition: Position.Left,
    style: {
      border: `2px solid ${SEVERITY_HEX[node.severity] ?? SEVERITY_NEUTRAL_HEX}`,
      borderRadius: '20px',
      background: '#ffffff',
      padding: '4px',
      width: 240,
      cursor: 'pointer',
      boxShadow: '0 14px 32px rgba(15, 23, 42, 0.12)',
    },
  }))

  const edges: Edge[] = path.edges.map(edge => ({
    id: edge.id,
    source: edge.source,
    target: edge.target,
    label: edge.label,
    type: 'default',
    markerEnd: { type: MarkerType.ArrowClosed, width: 16, height: 16 },
    style: { strokeWidth: 2.35, stroke: '#64748b' },
    labelStyle: { fontSize: 9, fill: '#475569', fontWeight: 700 },
    labelBgStyle: { fill: '#ffffff', fillOpacity: 0.96 },
    labelBgPadding: [3, 5] as [number, number],
  }))

  return { nodes, edges }
}
