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
        <span className="text-[10px] text-gray-500">{node.category}</span>
      </div>
      <div className="text-xs font-medium text-gray-200 truncate max-w-[180px]">
        {node.resource_name}
      </div>
      <div className="text-[11px] text-gray-500">{node.resource_type} · {node.region}</div>
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
      borderRadius: '0px',
      background: '#111318',
      padding: '4px',
      width: 220,
      cursor: 'pointer',
    },
  }))

  const edges: Edge[] = path.edges.map(edge => ({
    id: edge.id,
    source: edge.source,
    target: edge.target,
    label: edge.label,
    type: 'default',
    markerEnd: { type: MarkerType.ArrowClosed, width: 14, height: 14 },
    style: { strokeWidth: 2, stroke: '#374151' },
    labelStyle: { fontSize: 9, fill: '#6b7280' },
    labelBgStyle: { fill: '#0a0a0f', fillOpacity: 0.9 },
    labelBgPadding: [3, 5] as [number, number],
  }))

  return { nodes, edges }
}
