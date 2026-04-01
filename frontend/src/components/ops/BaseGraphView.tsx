import { useCallback, useEffect } from 'react'
import {
  ReactFlow,
  Background,
  Controls,
  type Node,
  type Edge,
  useNodesState,
  useEdgesState,
} from '@xyflow/react'
import '@xyflow/react/dist/style.css'

interface BaseGraphViewProps {
  nodes: Node[]
  edges: Edge[]
  onNodeClick?: (nodeId: string) => void
  height?: string
  tone?: 'dark' | 'light'
}

const GRAPH_TONE = {
  dark: {
    background: '#0a0a0f',
    grid: '#1e2330',
    controlsClass: '[&_button]:rounded-none [&_button]:border-[#1e2330] [&_button]:bg-[#12121a] [&_button]:text-gray-400',
  },
  light: {
    background: '#fbfdff',
    grid: '#d7e3f0',
    controlsClass: '[&_button]:rounded-md [&_button]:border-slate-200 [&_button]:bg-white [&_button]:text-slate-600 [&_button]:shadow-sm [&_button:hover]:bg-slate-50',
  },
} as const

export function BaseGraphView({
  nodes: initialNodes,
  edges: initialEdges,
  onNodeClick,
  height = 'h-[600px]',
  tone = 'dark',
}: BaseGraphViewProps) {
  const [nodes, setNodes, onNodesChange] = useNodesState(initialNodes)
  const [edges, setEdges, onEdgesChange] = useEdgesState(initialEdges)
  const palette = GRAPH_TONE[tone]

  useEffect(() => { setNodes(initialNodes) }, [initialNodes, setNodes])
  useEffect(() => { setEdges(initialEdges) }, [initialEdges, setEdges])

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
        fitViewOptions={{ padding: 0.14 }}
        minZoom={0.35}
        maxZoom={2.2}
        proOptions={{ hideAttribution: true }}
        style={{ background: palette.background }}
      >
        <Background color={palette.grid} gap={20} size={1} />
        <Controls
          showInteractive={false}
          className={palette.controlsClass}
        />
      </ReactFlow>
    </div>
  )
}
