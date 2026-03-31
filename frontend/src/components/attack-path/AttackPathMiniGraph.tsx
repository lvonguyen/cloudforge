/**
 * Compact attack path graph for embedding in finding detail Investigation tab.
 * Supports expand/collapse, path selector, node click detail, and edge tooltips.
 */
import { useState, useMemo, useCallback, useEffect } from 'react'
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
import { ProviderIcon } from '@/components/ui/ProviderIcon'
import { SEVERITY_COLORS_BORDERED as SEVERITY_COLORS, SEVERITY_HEX, SEVERITY_NEUTRAL_HEX } from '@/lib/severity'
import {
  formatResourceTypeLabel,
  getAttackPathEdgeMeta,
  getAttackPathResourceIcon,
  getCrownJewelLabel,
  getCrownJewelIcon,
  isCrownJewelNode,
} from '@/components/attack-path/visuals'

type ResolvedCanvasTone = 'light' | 'dark'

const MINI_CANVAS_THEME: Record<ResolvedCanvasTone, {
  frameClass: string
  graphBackground: string
  gridColor: string
  nodeBackground: string
  nodeShadow: string
  nodeTextClass: string
  mutedTextClass: string
  chipClass: string
  iconWrapClass: string
  controlClass: string
  edgeColor: string
  edgeLabelColor: string
  edgeLabelBackground: string
}> = {
  light: {
    frameClass: 'border-slate-200 bg-[radial-gradient(circle_at_top,_rgba(255,255,255,0.98),_rgba(241,245,249,0.95))]',
    graphBackground: '#f8fafc',
    gridColor: '#cbd5e1',
    nodeBackground: '#ffffff',
    nodeShadow: '0 14px 32px rgba(15, 23, 42, 0.12)',
    nodeTextClass: 'text-slate-950',
    mutedTextClass: 'text-slate-500',
    chipClass: 'border border-slate-200 bg-slate-50 text-slate-700',
    iconWrapClass: 'border border-slate-200 bg-slate-50 text-slate-700',
    controlClass: '[&_button]:rounded-xl [&_button]:border-slate-200 [&_button]:bg-white [&_button]:text-slate-500 [&_button:hover]:bg-slate-50 [&_button:hover]:text-slate-900',
    edgeColor: '#64748b',
    edgeLabelColor: '#475569',
    edgeLabelBackground: '#ffffff',
  },
  dark: {
    frameClass: 'border-slate-800 bg-[radial-gradient(circle_at_top,_rgba(30,41,59,0.96),_rgba(2,6,23,0.95))]',
    graphBackground: '#020617',
    gridColor: '#334155',
    nodeBackground: '#0f172a',
    nodeShadow: '0 18px 42px rgba(2, 6, 23, 0.45)',
    nodeTextClass: 'text-slate-50',
    mutedTextClass: 'text-slate-400',
    chipClass: 'border border-slate-700 bg-slate-800 text-slate-200',
    iconWrapClass: 'border border-slate-700 bg-slate-800 text-slate-100',
    controlClass: '[&_button]:rounded-xl [&_button]:border-slate-700 [&_button]:bg-slate-900/90 [&_button]:text-slate-400 [&_button:hover]:bg-slate-800 [&_button:hover]:text-slate-100',
    edgeColor: '#94a3b8',
    edgeLabelColor: '#cbd5e1',
    edgeLabelBackground: '#0f172a',
  },
}

function useDocumentCanvasTone(): ResolvedCanvasTone {
  const [dark, setDark] = useState(() =>
    typeof document !== 'undefined' && document.documentElement.classList.contains('dark'),
  )

  useEffect(() => {
    if (typeof document === 'undefined') return
    const root = document.documentElement
    const sync = () => setDark(root.classList.contains('dark'))
    sync()
    if (typeof MutationObserver === 'undefined') return
    const observer = new MutationObserver(sync)
    observer.observe(root, { attributes: true, attributeFilter: ['class'] })
    return () => observer.disconnect()
  }, [])

  return dark ? 'dark' : 'light'
}

const EDGE_TONE_STYLES = {
  amber: { stroke: '#f59e0b', labelBg: '#fffbeb', labelText: '#b45309' },
  rose: { stroke: '#ef4444', labelBg: '#fff1f2', labelText: '#be123c' },
  sky: { stroke: '#0ea5e9', labelBg: '#f0f9ff', labelText: '#0369a1' },
  violet: { stroke: '#8b5cf6', labelBg: '#f5f3ff', labelText: '#6d28d9' },
  slate: { stroke: '#64748b', labelBg: '#f8fafc', labelText: '#475569' },
} as const

function pathToFlowNodes(path: AttackPath, resolvedTone: ResolvedCanvasTone): { nodes: Node[]; edges: Edge[] } {
  const canvasTheme = MINI_CANVAS_THEME[resolvedTone]
  const nodes: Node[] = path.nodes.map((n, i) => ({
    id: n.id,
    position: { x: i * 280, y: 0 },
    data: {
      label: (
        <div className={`text-left px-3 py-3 ${canvasTheme.nodeTextClass}`}>
          <div className="flex items-start gap-2.5">
            <div className={`relative mt-0.5 flex h-8 w-8 shrink-0 items-center justify-center rounded-2xl ${canvasTheme.iconWrapClass}`}>
              {(() => {
                const ResourceIcon = getAttackPathResourceIcon(n)
                return <ResourceIcon className="h-4 w-4" />
              })()}
              <span className="absolute -bottom-1 -right-1 flex h-4 w-4 items-center justify-center rounded-full border border-white bg-white shadow-sm dark:border-slate-900 dark:bg-slate-900">
                <ProviderIcon provider={n.provider} className="h-2.5 w-2.5" />
              </span>
            </div>
            <div className="min-w-0">
              <div className="mb-1 flex items-center gap-1.5">
                <span className={`rounded-full px-1.5 py-0.5 text-[9px] font-bold ${SEVERITY_COLORS[n.severity] ?? ''}`}>
                  {n.severity}
                </span>
                <span className={`inline-flex items-center rounded-full px-1.5 py-0.5 text-[9px] font-medium ${canvasTheme.chipClass}`}>
                  {i === 0 ? 'Entry' : i === path.nodes.length - 1 ? 'Target' : 'Pivot'}
                </span>
                {isCrownJewelNode(n) && (
                  <span className="inline-flex items-center gap-1 rounded-full border border-amber-200 bg-amber-50 px-1.5 py-0.5 text-[9px] font-semibold text-amber-700 dark:border-amber-500/30 dark:bg-amber-500/10 dark:text-amber-200">
                    {(() => {
                      const CrownIcon = getCrownJewelIcon()
                      return <CrownIcon className="h-2.5 w-2.5" />
                    })()}
                    Crown
                  </span>
                )}
              </div>
              <div className="truncate text-xs font-semibold max-w-[180px]">{n.resource_name}</div>
              <div className={`mt-1 flex items-center gap-1.5 text-[10px] ${canvasTheme.mutedTextClass}`}>
                <span>{formatResourceTypeLabel(n.resource_type)}</span>
                <span>&middot;</span>
                <span>{n.category}</span>
              </div>
            </div>
          </div>
        </div>
      ),
    },
    sourcePosition: Position.Right,
    targetPosition: Position.Left,
    style: {
      border: `2px solid ${SEVERITY_HEX[n.severity] ?? SEVERITY_NEUTRAL_HEX}`,
      borderRadius: '20px',
      background: canvasTheme.nodeBackground,
      padding: '0px',
      width: 220,
      boxShadow: canvasTheme.nodeShadow,
      cursor: 'pointer',
    },
  }))

  const edges: Edge[] = path.edges.map(e => {
    const edgeMeta = getAttackPathEdgeMeta(e)
    const tone = EDGE_TONE_STYLES[edgeMeta.tone]
    return {
      id: e.id,
      source: e.source,
      target: e.target,
      label: edgeMeta.label,
      type: 'smoothstep',
      animated: edgeMeta.emphasize,
      markerEnd: { type: MarkerType.ArrowClosed, width: 14, height: 14 },
      style: {
        strokeWidth: edgeMeta.emphasize ? 2.6 : 2,
        cursor: 'pointer',
        stroke: resolvedTone === 'dark' && edgeMeta.tone === 'slate' ? canvasTheme.edgeColor : tone.stroke,
      },
      labelStyle: {
        fontSize: 10,
        fill: resolvedTone === 'dark' && edgeMeta.tone === 'slate' ? canvasTheme.edgeLabelColor : tone.labelText,
        cursor: 'pointer',
        fontWeight: 700,
      },
      labelBgStyle: {
        fill: resolvedTone === 'dark' && edgeMeta.tone === 'slate' ? canvasTheme.edgeLabelBackground : tone.labelBg,
        fillOpacity: 0.96,
      },
      labelBgPadding: [4, 6] as [number, number],
    }
  })

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
  const resolvedCanvasTone = useDocumentCanvasTone()
  const canvasTheme = MINI_CANVAS_THEME[resolvedCanvasTone]

  const primaryPath = paths[selectedPathIndex] ?? paths[0]
  const privilegeHopCount = primaryPath?.edges.filter(edge => getAttackPathEdgeMeta(edge).label === 'Privilege escalation').length ?? 0
  const crownJewelCount = primaryPath?.nodes.filter(node => isCrownJewelNode(node)).length ?? 0

  const { nodes, edges } = useMemo(
    () => (primaryPath ? pathToFlowNodes(primaryPath, resolvedCanvasTone) : { nodes: [], edges: [] }),
    [primaryPath, resolvedCanvasTone],
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
          {privilegeHopCount > 0 && (
            <Badge variant="secondary" className="text-[10px] bg-amber-100 text-amber-700 dark:bg-amber-900/30 dark:text-amber-300">
              {privilegeHopCount} privilege hop{privilegeHopCount > 1 ? 's' : ''}
            </Badge>
          )}
          {crownJewelCount > 0 && (
            <Badge variant="secondary" className="text-[10px] bg-rose-100 text-rose-700 dark:bg-rose-900/30 dark:text-rose-300">
              {crownJewelCount} crown jewel{crownJewelCount > 1 ? 's' : ''}
            </Badge>
          )}
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
        <div
          data-canvas-tone={resolvedCanvasTone}
          className={`${expanded ? 'h-[400px]' : 'h-48'} relative overflow-hidden rounded-[24px] border transition-all duration-200 ${canvasTheme.frameClass}`}
        >
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
            style={{ background: canvasTheme.graphBackground }}
          >
            <Background gap={16} size={1} color={canvasTheme.gridColor} />
            <Controls showInteractive={false} showZoom={expanded} className={canvasTheme.controlClass} />
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
                {isCrownJewelNode(nodeDetail) && (
                  <Badge variant="outline" className="text-[9px] border-amber-200 bg-amber-50 text-amber-700 dark:border-amber-500/30 dark:bg-amber-500/10 dark:text-amber-200">
                    Crown jewel
                  </Badge>
                )}
                <p className="text-xs font-medium">{nodeDetail.resource_name}</p>
                <p className="text-[10px] text-muted-foreground">{formatResourceTypeLabel(nodeDetail.resource_type)}</p>
                <p className="text-[10px] text-muted-foreground">{nodeDetail.category}</p>
                <p className="text-[10px] text-muted-foreground">{nodeDetail.region}</p>
                {isCrownJewelNode(nodeDetail) && (
                  <p className="text-[10px] text-amber-700 dark:text-amber-200">{getCrownJewelLabel(nodeDetail)}</p>
                )}
                {nodeDetail.finding_id && (
                  <p className="text-[10px] font-mono text-muted-foreground truncate">{nodeDetail.finding_id}</p>
                )}
              </div>
            </div>
          )}
        </div>

        {/* Link to security graph (attack-paths route removed in Sprint G) */}
        {resourceId && (
          <div className="flex items-center justify-between gap-3">
            <div className="flex flex-wrap items-center gap-2 text-[10px] text-muted-foreground">
              <span className="rounded-full border border-border/80 bg-muted/40 px-2 py-1">Privilege escalation hop</span>
              <span className="rounded-full border border-border/80 bg-muted/40 px-2 py-1">Crown jewel</span>
            </div>
            <Button variant="ghost" size="sm" className="text-xs gap-1 text-muted-foreground">
              Resource: {resourceId.length > 30 ? resourceId.slice(0, 30) + '\u2026' : resourceId}
            </Button>
          </div>
        )}
      </CardContent>
    </Card>
  )
}
