/**
 * Compact attack path graph for embedding in finding detail Investigation tab.
 * Supports expand/collapse, path selector, node click detail, and edge tooltips.
 */
import { useState, useMemo, useCallback } from 'react'
import {
  ReactFlow,
  Background,
  Controls,
  type Node,
  type Edge,
  Position,
  MarkerType,
} from '@xyflow/react'
import '@xyflow/react/dist/style.css'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { ArrowRight, Network, AlertTriangle, Maximize2, Minimize2, X } from 'lucide-react'
import type { AttackPath, AttackPathNode } from '@/types/attack-path'
import { SEVERITY_COLORS_BORDERED as SEVERITY_COLORS } from '@/lib/severity'

const NODE_BORDER_COLORS: Record<string, string> = {
  CRITICAL: '#ef4444',
  HIGH: '#f97316',
  MEDIUM: '#eab308',
  LOW: '#3b82f6',
}

function pathToFlowNodes(path: AttackPath): { nodes: Node[]; edges: Edge[] } {
  const nodes: Node[] = path.nodes.map((n, i) => ({
    id: n.id,
    position: { x: i * 280, y: 0 },
    data: {
      label: (
        <div className="text-left px-2 py-1">
          <div className="flex items-center gap-1 mb-1">
            <span className={`text-[9px] font-bold px-1.5 py-0 rounded ${SEVERITY_COLORS[n.severity] ?? ''}`}>
              {n.severity}
            </span>
            <span className="text-[9px] text-muted-foreground">{n.category}</span>
          </div>
          <div className="text-xs font-medium truncate max-w-[180px]">{n.resource_name}</div>
          <div className="text-[10px] text-muted-foreground">{n.resource_type}</div>
        </div>
      ),
    },
    sourcePosition: Position.Right,
    targetPosition: Position.Left,
    style: {
      border: `2px solid ${NODE_BORDER_COLORS[n.severity] ?? '#6b7280'}`,
      borderRadius: '0px',
      background: 'var(--color-card)',
      padding: '4px',
      width: 200,
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
    style: { strokeWidth: 2, cursor: 'pointer' },
    labelStyle: { fontSize: 10, fill: 'var(--color-muted-foreground)', cursor: 'pointer' },
    labelBgStyle: { fill: 'var(--color-background)', fillOpacity: 0.95 },
    labelBgPadding: [4, 6] as [number, number],
  }))

  return { nodes, edges }
}

interface AttackPathMiniGraphProps {
  paths: AttackPath[]
  resourceId?: string
}

export function AttackPathMiniGraph({ paths, resourceId }: AttackPathMiniGraphProps) {
  const [expanded, setExpanded] = useState(false)
  const [selectedPathIndex, setSelectedPathIndex] = useState(0)
  const [nodeDetail, setNodeDetail] = useState<AttackPathNode | null>(null)

  const primaryPath = paths[selectedPathIndex] ?? paths[0]

  const { nodes, edges } = useMemo(
    () => (primaryPath ? pathToFlowNodes(primaryPath) : { nodes: [], edges: [] }),
    [primaryPath],
  )

  const onNodeClick = useCallback((_: React.MouseEvent, node: Node) => {
    const pathNode = primaryPath?.nodes.find(n => n.id === node.id)
    if (pathNode) setNodeDetail(pathNode)
  }, [primaryPath])

  if (!primaryPath) return null

  const blastRadius = primaryPath.nodes.length

  return (
    <Card>
      <CardHeader className="pb-2">
        <div className="flex items-center justify-between">
          <CardTitle className="text-xs font-medium uppercase tracking-wide text-muted-foreground">
            <div className="flex items-center gap-1.5"><Network className="h-3.5 w-3.5" />Attack Path</div>
          </CardTitle>
          <div className="flex items-center gap-2">
            <Badge variant="outline" className={SEVERITY_COLORS[primaryPath.severity] ?? ''}>
              {primaryPath.severity}
            </Badge>
            {paths.length > 1 && (
              <select
                value={selectedPathIndex}
                onChange={(e) => { setSelectedPathIndex(Number(e.target.value)); setNodeDetail(null) }}
                className="text-[10px] bg-transparent border border-border rounded px-1 py-0.5 text-muted-foreground"
              >
                {paths.map((p, i) => (
                  <option key={p.id} value={i}>
                    {p.severity} — {p.title.slice(0, 40)}{p.title.length > 40 ? '\u2026' : ''}
                  </option>
                ))}
              </select>
            )}
            <Button variant="ghost" size="sm" className="h-6 w-6 p-0" onClick={() => setExpanded(!expanded)}>
              {expanded ? <Minimize2 className="h-3 w-3" /> : <Maximize2 className="h-3 w-3" />}
            </Button>
          </div>
        </div>
      </CardHeader>
      <CardContent className="space-y-3">
        {/* Path summary */}
        <div className="flex items-center gap-2 text-xs">
          <span className="font-medium">{primaryPath.entry_point.resource_name}</span>
          <ArrowRight className="h-3 w-3 text-muted-foreground" />
          {primaryPath.hop_count > 2 && (
            <>
              <span className="text-muted-foreground">{primaryPath.hop_count - 2} hop{primaryPath.hop_count > 3 ? 's' : ''}</span>
              <ArrowRight className="h-3 w-3 text-muted-foreground" />
            </>
          )}
          <span className="font-medium">{primaryPath.target.resource_name}</span>
        </div>

        {/* Mini badges */}
        <div className="flex items-center gap-2 flex-wrap">
          <Badge variant="secondary" className="text-[10px]">
            {blastRadius} resource{blastRadius !== 1 ? 's' : ''} in blast radius
          </Badge>
          <Badge variant="secondary" className="text-[10px]">
            Score: {primaryPath.score}
          </Badge>
          {primaryPath.ai_enriched && (
            <Badge variant="secondary" className="text-[10px] bg-purple-100 text-purple-700 dark:bg-purple-900/30 dark:text-purple-300">
              AI Validated
            </Badge>
          )}
          {primaryPath.low_confidence && (
            <Badge variant="secondary" className="text-[10px] bg-yellow-100 text-yellow-700 dark:bg-yellow-900/30 dark:text-yellow-300">
              <AlertTriangle className="h-3 w-3 mr-1" />Low Confidence
            </Badge>
          )}
        </div>

        {/* AI narrative */}
        {primaryPath.ai_risk_narrative && (
          <p className="text-[11px] text-muted-foreground italic border-l-2 border-purple-400 pl-2">
            {primaryPath.ai_risk_narrative}
          </p>
        )}

        {/* Graph */}
        <div className={`${expanded ? 'h-[400px]' : 'h-48'} border rounded-md overflow-hidden relative transition-all duration-200`}>
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
            panOnDrag={expanded}
            zoomOnScroll={expanded}
            minZoom={0.3}
            maxZoom={expanded ? 2 : 1}
          >
            <Background gap={16} size={1} />
            <Controls showInteractive={false} showZoom={expanded} />
          </ReactFlow>

          {/* Node detail overlay */}
          {nodeDetail && (
            <div className="absolute z-20 top-2 right-2 bg-card border border-border rounded-md shadow-lg p-3 max-w-[220px]">
              <button onClick={() => setNodeDetail(null)} className="absolute top-1 right-1 text-muted-foreground hover:text-foreground">
                <X className="h-3 w-3" />
              </button>
              <div className="space-y-1.5">
                <Badge variant="outline" className={`text-[9px] ${SEVERITY_COLORS[nodeDetail.severity] ?? ''}`}>
                  {nodeDetail.severity}
                </Badge>
                <p className="text-xs font-medium">{nodeDetail.resource_name}</p>
                <p className="text-[10px] text-muted-foreground">{nodeDetail.resource_type}</p>
                <p className="text-[10px] text-muted-foreground">{nodeDetail.region}</p>
                {nodeDetail.finding_id && (
                  <p className="text-[10px] font-mono text-muted-foreground truncate">{nodeDetail.finding_id}</p>
                )}
              </div>
            </div>
          )}
        </div>

        {/* Link to security graph (attack-paths route removed in Sprint G) */}
        {resourceId && (
          <div className="flex justify-end">
            <Button variant="ghost" size="sm" className="text-xs gap-1 text-muted-foreground">
              Resource: {resourceId.length > 30 ? resourceId.slice(0, 30) + '\u2026' : resourceId}
            </Button>
          </div>
        )}
      </CardContent>
    </Card>
  )
}
