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
import { useAttackPaths, useAttackPathStats } from '@/hooks/useAttackPaths'
import { Card, CardContent } from '@/components/ui/card'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { Separator } from '@/components/ui/separator'
import { ArrowLeft, Shield, AlertTriangle, Zap, Target } from 'lucide-react'
import type { AttackPath } from '@/types/attack-path'

const SEVERITY_COLORS: Record<string, string> = {
  CRITICAL: 'bg-red-100 text-red-800 dark:bg-red-900/30 dark:text-red-300 border-red-300 dark:border-red-700',
  HIGH: 'bg-orange-100 text-orange-800 dark:bg-orange-900/30 dark:text-orange-300 border-orange-300 dark:border-orange-700',
  MEDIUM: 'bg-yellow-100 text-yellow-800 dark:bg-yellow-900/30 dark:text-yellow-300 border-yellow-300 dark:border-yellow-700',
  LOW: 'bg-blue-100 text-blue-800 dark:bg-blue-900/30 dark:text-blue-300 border-blue-300 dark:border-blue-700',
}

const NODE_BORDER_COLORS: Record<string, string> = {
  CRITICAL: '#ef4444',
  HIGH: '#f97316',
  MEDIUM: '#eab308',
  LOW: '#3b82f6',
}

const PROVIDER_COLORS: Record<string, string> = {
  aws: 'bg-orange-100 text-orange-700 dark:bg-orange-900/30 dark:text-orange-300',
  azure: 'bg-blue-100 text-blue-700 dark:bg-blue-900/30 dark:text-blue-300',
  gcp: 'bg-green-100 text-green-700 dark:bg-green-900/30 dark:text-green-300',
}

const CATEGORY_ICONS: Record<string, typeof Shield> = {
  NETWORK: Zap,
  VULNERABILITY: AlertTriangle,
  IDENTITY: Shield,
  MISCONFIGURATION: AlertTriangle,
  COMPLIANCE: Shield,
}

function pathToFlow(path: AttackPath): { nodes: Node[]; edges: Edge[] } {
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
          <div className="text-xs font-medium truncate max-w-[200px]">{n.resource_name}</div>
          <div className="text-[10px] text-muted-foreground">{n.resource_type} · {n.region}</div>
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
      width: 240,
    },
  }))

  const edges: Edge[] = path.edges.map(e => ({
    id: e.id,
    source: e.source,
    target: e.target,
    label: e.label,
    type: 'default',
    markerEnd: { type: MarkerType.ArrowClosed, width: 16, height: 16 },
    style: { strokeWidth: 2 },
    labelStyle: { fontSize: 10, fill: 'var(--color-muted-foreground)' },
  }))

  return { nodes, edges }
}

function PathCard({ path, onClick }: { path: AttackPath; onClick: () => void }) {
  const Icon = CATEGORY_ICONS[path.entry_point?.category] ?? AlertTriangle
  return (
    <Card className="cursor-pointer hover:bg-muted/30 transition-colors" onClick={onClick}>
      <CardContent className="p-4">
        <div className="flex items-start gap-3">
          <div className="h-8 w-8 rounded-none bg-muted flex items-center justify-center shrink-0">
            <Icon className="h-4 w-4" />
          </div>
          <div className="flex-1 min-w-0">
            <div className="flex items-center gap-2 flex-wrap mb-1">
              <Badge variant="outline" className={`text-[10px] px-1.5 py-0 rounded-none ${SEVERITY_COLORS[path.severity] ?? ''}`}>
                {path.severity}
              </Badge>
              <span className="text-[10px] text-muted-foreground">{path.hop_count} hop{path.hop_count !== 1 ? 's' : ''}</span>
              <span className="text-[10px] text-muted-foreground">Score: {path.score.toFixed(0)}</span>
              {path.nodes.length > 0 && (
                <Badge variant="secondary" className={`text-[10px] ${PROVIDER_COLORS[path.nodes[0].provider] ?? ''}`}>
                  {path.nodes[0].provider.toUpperCase()}
                </Badge>
              )}
            </div>
            <p className="text-sm font-medium leading-snug">{path.title}</p>
            <p className="text-xs text-muted-foreground mt-0.5 line-clamp-2">{path.description}</p>
            <div className="flex items-center gap-1 mt-2">
              {path.finding_ids.map(fid => (
                <span key={fid} className="text-[9px] font-mono bg-muted px-1 py-0 rounded">{fid}</span>
              ))}
            </div>
          </div>
          <div className="shrink-0">
            <Target className="h-4 w-4 text-muted-foreground" />
          </div>
        </div>
      </CardContent>
    </Card>
  )
}

function PathGraphView({ path, onBack }: { path: AttackPath; onBack: () => void }) {
  const { nodes, edges } = useMemo(() => pathToFlow(path), [path])

  return (
    <div className="space-y-4">
      <div className="flex items-center gap-3">
        <Button variant="ghost" size="sm" className="gap-1.5 -ml-2" onClick={onBack}>
          <ArrowLeft className="h-4 w-4" />All Paths
        </Button>
        <Badge variant="outline" className={`text-[10px] px-1.5 py-0 rounded-none ${SEVERITY_COLORS[path.severity] ?? ''}`}>
          {path.severity}
        </Badge>
        <span className="text-sm font-medium">{path.title}</span>
      </div>
      <p className="text-xs text-muted-foreground">{path.description}</p>

      <div className="h-[320px] border border-border rounded-none bg-background">
        <ReactFlow
          nodes={nodes}
          edges={edges}
          fitView
          fitViewOptions={{ padding: 0.3 }}
          proOptions={{ hideAttribution: true }}
          nodesDraggable={false}
          nodesConnectable={false}
          elementsSelectable={false}
          minZoom={0.5}
          maxZoom={1.5}
        >
          <Background gap={16} size={1} />
          <Controls showInteractive={false} />
        </ReactFlow>
      </div>

      {path.mitre_tactics.length > 0 && (
        <div className="flex items-center gap-2 flex-wrap">
          <span className="text-[10px] font-semibold text-muted-foreground uppercase tracking-wide">MITRE:</span>
          {path.mitre_tactics.map(t => (
            <span key={t} className="text-[10px] font-mono bg-muted px-1.5 py-0.5">{t}</span>
          ))}
        </div>
      )}
    </div>
  )
}

export default function AttackPaths() {
  const { data: paths = [], isLoading } = useAttackPaths()
  const { data: stats } = useAttackPathStats()
  const [selectedId, setSelectedId] = useState<string | null>(null)

  const selectedPath = useMemo(
    () => paths.find(p => p.id === selectedId) ?? null,
    [paths, selectedId]
  )

  const handleBack = useCallback(() => setSelectedId(null), [])

  if (isLoading) {
    return <div className="text-sm text-muted-foreground p-6">Computing attack paths...</div>
  }

  if (selectedPath) {
    return (
      <div className="max-w-5xl p-6">
        <PathGraphView path={selectedPath} onBack={handleBack} />
      </div>
    )
  }

  return (
    <div className="space-y-6 max-w-4xl">
      <div>
        <h1 className="text-xl font-semibold">Attack Paths</h1>
        <p className="text-sm text-muted-foreground mt-0.5">
          {paths.length} paths computed from {stats?.total_findings ?? 0} findings
          {stats ? ` · ${stats.coverage_percent.toFixed(0)}% coverage · ${stats.isolated_findings} isolated` : ''}
        </p>
      </div>

      {/* Stats bar */}
      {stats && (
        <div className="grid grid-cols-2 md:grid-cols-5 gap-3">
          {[
            { label: 'Total Paths', value: stats.total_paths },
            { label: 'Critical', value: stats.critical_paths },
            { label: 'High', value: stats.high_paths },
            { label: 'Medium', value: stats.medium_paths },
            { label: 'Coverage', value: `${stats.coverage_percent.toFixed(0)}%` },
          ].map(({ label, value }) => (
            <div key={label} className="border border-border p-3">
              <p className="text-[10px] text-muted-foreground uppercase tracking-wide">{label}</p>
              <p className="text-lg font-semibold mt-0.5">{value}</p>
            </div>
          ))}
        </div>
      )}

      <Separator />

      {/* Path list */}
      <div className="space-y-3">
        {paths.map(path => (
          <PathCard key={path.id} path={path} onClick={() => setSelectedId(path.id)} />
        ))}
      </div>

      {paths.length === 0 && (
        <div className="text-center py-12 text-muted-foreground">
          <Shield className="h-8 w-8 mx-auto mb-2 opacity-40" />
          <p className="text-sm">No attack paths detected.</p>
        </div>
      )}
    </div>
  )
}
