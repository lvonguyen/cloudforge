import { useCallback } from 'react'
import {
  ReactFlow,
  Background,
  Controls,
  type Node,
  type Edge,
  type OnNodesChange,
  type OnEdgesChange,
  useNodesState,
  useEdgesState,
} from '@xyflow/react'
import '@xyflow/react/dist/style.css'

interface BaseGraphViewProps {
  nodes: Node[]
  edges: Edge[]
  onNodeClick?: (nodeId: string) => void
  height?: string
}

export function BaseGraphView({ nodes: initialNodes, edges: initialEdges, onNodeClick, height = 'h-[600px]' }: BaseGraphViewProps) {
  const [nodes, , onNodesChange] = useNodesState(initialNodes)
  const [edges, , onEdgesChange] = useEdgesState(initialEdges)

  const handleNodeClick = useCallback((_: React.MouseEvent, node: Node) => {
    onNodeClick?.(node.id)
  }, [onNodeClick])

  return (
    <div className={height}>
      <ReactFlow
        nodes={nodes}
        edges={edges}
        onNodesChange={onNodesChange}
        onEdgesChange={onEdgesChange}
        onNodeClick={handleNodeClick}
        fitView
        minZoom={0.3}
        maxZoom={2}
        proOptions={{ hideAttribution: true }}
        style={{ background: '#0a0a0f' }}
      >
        <Background color="#1e2330" gap={20} size={1} />
        <Controls
          showInteractive={false}
          className="[&_button]:rounded-none [&_button]:border-[#1e2330] [&_button]:bg-[#12121a] [&_button]:text-gray-400"
        />
      </ReactFlow>
    </div>
  )
}
