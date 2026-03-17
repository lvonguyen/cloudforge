/**
 * Compact attack path graph for embedding in finding detail Investigation tab.
 * Reuses the same node/edge styling as the full AttackPaths page.
 */
import { useMemo } from 'react'
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
import { ArrowRight, Network, AlertTriangle, ExternalLink } from 'lucide-react'
import { Link } from 'react-router-dom'
import type { AttackPath } from '@/types/attack-path'
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
    },
  }))

  const edges: Edge[] = path.edges.map(e => ({
    id: e.id,
    source: e.source,
    target: e.target,
    label: e.label,
    type: 'default',
    markerEnd: { type: MarkerType.ArrowClosed, width: 14, height: 14 },
    style: { strokeWidth: 2 },
    labelStyle: { fontSize: 9, fill: 'var(--color-muted-foreground)' },
    labelBgStyle: { fill: 'var(--color-background)', fillOpacity: 0.9 },
    labelBgPadding: [3, 5] as [number, number],
  }))

  return { nodes, edges }
}

interface AttackPathMiniGraphProps {
  paths: AttackPath[]
  resourceId?: string
}

export function AttackPathMiniGraph({ paths, resourceId }: AttackPathMiniGraphProps) {
  // Show the first (highest-severity) path
  const primaryPath = paths[0]
  if (!primaryPath) return null

  const { nodes, edges } = useMemo(() => pathToFlowNodes(primaryPath), [primaryPath])

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
              <span className="text-[10px] text-muted-foreground">+{paths.length - 1} more</span>
            )}
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
        <div className="h-48 border rounded-md overflow-hidden">
          <ReactFlow
            nodes={nodes}
            edges={edges}
            fitView
            fitViewOptions={{ padding: 0.3 }}
            proOptions={{ hideAttribution: true }}
            nodesDraggable={false}
            nodesConnectable={false}
            elementsSelectable={false}
            panOnDrag={false}
            zoomOnScroll={false}
            minZoom={0.3}
            maxZoom={1}
          >
            <Background gap={16} size={1} />
            <Controls showInteractive={false} showZoom={false} />
          </ReactFlow>
        </div>

        {/* Link to full graph */}
        <div className="flex justify-end gap-2">
          <Link to={`/ops/attack-paths`}>
            <Button variant="ghost" size="sm" className="text-xs gap-1">
              All Attack Paths <ExternalLink className="h-3 w-3" />
            </Button>
          </Link>
          {resourceId && (
            <Link to={`/ops/graph?focus=${encodeURIComponent(resourceId)}`}>
              <Button variant="ghost" size="sm" className="text-xs gap-1">
                View on Security Graph <ExternalLink className="h-3 w-3" />
              </Button>
            </Link>
          )}
        </div>
      </CardContent>
    </Card>
  )
}
