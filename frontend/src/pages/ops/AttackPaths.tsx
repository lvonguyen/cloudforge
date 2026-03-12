import { useState, useMemo, useCallback } from 'react'
import { Link } from 'react-router-dom'
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
import { Card, CardContent, CardHeader } from '@/components/ui/card'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { Separator } from '@/components/ui/separator'
import { ArrowLeft, Shield, AlertTriangle, Zap, Target, Sparkles, ArrowRight } from 'lucide-react'
import type { AttackPath } from '@/types/attack-path'
import { ProviderIcon } from '@/components/ui/ProviderIcon'
import { ProviderBadge } from '@/components/ui/ProviderBadge'
import { SEVERITY_COLORS_BORDERED as SEVERITY_COLORS } from '@/lib/severity'

const NODE_BORDER_COLORS: Record<string, string> = {
  CRITICAL: '#ef4444',
  HIGH: '#f97316',
  MEDIUM: '#eab308',
  LOW: '#3b82f6',
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
    position: { x: i * 360, y: 0 },
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
    labelBgStyle: { fill: 'var(--color-background)', fillOpacity: 0.9 },
    labelBgPadding: [4, 6] as [number, number],
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
                <ProviderBadge provider={path.nodes[0].provider} />
              )}
              {path.ai_enriched && (
                <Badge variant="outline" className="text-[10px] px-1.5 py-0 rounded-none bg-violet-100 text-violet-700 border-violet-300 dark:bg-violet-900/30 dark:text-violet-300 dark:border-violet-800 gap-0.5">
                  <Sparkles className="h-2.5 w-2.5" />AI
                </Badge>
              )}
              {path.ai_likelihood && (
                <span className={`text-[10px] font-mono ${
                  path.ai_likelihood === 'high' ? 'text-red-600 dark:text-red-400' :
                  path.ai_likelihood === 'medium' ? 'text-orange-600 dark:text-orange-400' :
                  'text-blue-600 dark:text-blue-400'
                }`}>{path.ai_likelihood.toUpperCase()} likelihood</span>
              )}
            </div>
            <p className="text-sm font-medium leading-snug">{path.title}</p>
            <p className="text-xs text-muted-foreground mt-0.5 line-clamp-2">{path.ai_description ?? path.description}</p>
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
      <p className="text-xs text-muted-foreground">{path.ai_description ?? path.description}</p>

      {path.ai_enriched && path.ai_remediation && (
        <div className="border border-violet-200 dark:border-violet-800 bg-violet-50 dark:bg-violet-950/30 p-3 space-y-1">
          <div className="flex items-center gap-1.5">
            <Sparkles className="h-3.5 w-3.5 text-violet-600 dark:text-violet-400" />
            <span className="text-xs font-semibold text-violet-700 dark:text-violet-300 uppercase tracking-wide">AI Remediation</span>
            {path.ai_likelihood && (
              <Badge variant="outline" className={`text-[10px] px-1.5 py-0 rounded-none ml-auto ${
                path.ai_likelihood === 'high' ? 'bg-red-100 text-red-700 border-red-300 dark:bg-red-900/30 dark:text-red-300' :
                path.ai_likelihood === 'medium' ? 'bg-orange-100 text-orange-700 border-orange-300 dark:bg-orange-900/30 dark:text-orange-300' :
                'bg-blue-100 text-blue-700 border-blue-300 dark:bg-blue-900/30 dark:text-blue-300'
              }`}>{path.ai_likelihood} likelihood</Badge>
            )}
          </div>
          <p className="text-xs text-muted-foreground whitespace-pre-line">{path.ai_remediation}</p>
        </div>
      )}

      <div className="h-[400px] border border-border rounded-none bg-background">
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

      {/* Resource Chain */}
      <Card className="rounded-none">
        <CardHeader className="pb-2 pt-3 px-4">
          <span className="text-xs font-semibold uppercase tracking-wide text-muted-foreground">Resource Chain</span>
        </CardHeader>
        <CardContent className="px-4 pb-4">
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-3">
            {path.nodes.map(n => (
              <div key={n.id} className="border border-border p-3 space-y-1">
                <div className="flex items-center gap-2">
                  <ProviderIcon provider={n.provider} className="h-4 w-4 shrink-0" />
                  <span className="text-xs font-semibold truncate">{n.resource_name}</span>
                </div>
                <div className="text-[10px] text-muted-foreground">{n.resource_type} · {n.region}</div>
                <div className="flex items-center gap-2 mt-1">
                  <Badge variant="outline" className={`text-[9px] px-1.5 py-0 rounded-none ${SEVERITY_COLORS[n.severity] ?? ''}`}>
                    {n.severity}
                  </Badge>
                  {n.finding_id && (
                    <Link
                      to={`/ops/findings/${n.finding_id}`}
                      className="text-[9px] font-mono text-muted-foreground hover:text-foreground underline underline-offset-2"
                    >
                      {n.finding_id}
                    </Link>
                  )}
                </div>
              </div>
            ))}
          </div>
        </CardContent>
      </Card>

      {/* Attack Context */}
      <Card className="rounded-none">
        <CardHeader className="pb-2 pt-3 px-4">
          <span className="text-xs font-semibold uppercase tracking-wide text-muted-foreground">Attack Context</span>
        </CardHeader>
        <CardContent className="px-4 pb-4">
          {(() => {
            const uniqueProviders = [...new Set(path.nodes.map(n => n.provider))]
            const uniqueRegions = [...new Set(path.nodes.map(n => n.region))]
            const uniqueAccounts = [...new Set(path.nodes.map(n => n.account_id))]
            const scoreColor = path.severity === 'CRITICAL' ? 'text-red-600 dark:text-red-400'
              : path.severity === 'HIGH' ? 'text-orange-600 dark:text-orange-400'
              : path.severity === 'MEDIUM' ? 'text-yellow-600 dark:text-yellow-400'
              : 'text-blue-600 dark:text-blue-400'
            return (
              <div className="grid grid-cols-1 md:grid-cols-2 gap-x-8 gap-y-2 text-xs">
                <div>
                  <span className="text-muted-foreground">Entry Point: </span>
                  <span className="font-medium">{path.entry_point.resource_name}</span>
                  <span className="text-muted-foreground ml-1">({path.entry_point.category})</span>
                </div>
                <div>
                  <span className="text-muted-foreground">Target: </span>
                  <span className="font-medium">{path.target.resource_name}</span>
                  <span className="text-muted-foreground ml-1">({path.target.resource_type})</span>
                </div>
                <div className="flex items-center gap-2">
                  <span className="text-muted-foreground">Providers: </span>
                  {uniqueProviders.map(p => (
                    <span key={p} className="flex items-center gap-1">
                      <ProviderIcon provider={p} className="h-3.5 w-3.5" />
                      <span className="font-mono uppercase text-[10px]">{p}</span>
                    </span>
                  ))}
                </div>
                <div>
                  <span className="text-muted-foreground">Regions: </span>
                  <span className="font-mono text-[10px]">{uniqueRegions.join(', ')}</span>
                </div>
                <div>
                  <span className="text-muted-foreground">Accounts: </span>
                  <span className="font-mono text-[10px]">{uniqueAccounts.join(', ')}</span>
                </div>
                <div>
                  <span className="text-muted-foreground">Score: </span>
                  <span className={`font-semibold ${scoreColor}`}>{path.score.toFixed(0)}</span>
                  <span className="text-muted-foreground ml-1">({path.severity})</span>
                </div>
              </div>
            )
          })()}
        </CardContent>
      </Card>

      {/* Finding References */}
      {path.finding_ids.length > 0 && (
        <Card className="rounded-none">
          <CardHeader className="pb-2 pt-3 px-4">
            <span className="text-xs font-semibold uppercase tracking-wide text-muted-foreground">Finding References</span>
          </CardHeader>
          <CardContent className="px-4 pb-4">
            <div className="flex flex-wrap gap-2">
              {path.finding_ids.map(fid => (
                <Link
                  key={fid}
                  to={`/ops/findings/${fid}`}
                  className="flex items-center gap-1 text-[10px] font-mono bg-muted px-2 py-1 hover:bg-muted/70 transition-colors"
                >
                  {fid}
                  <ArrowRight className="h-2.5 w-2.5" />
                </Link>
              ))}
            </div>
          </CardContent>
        </Card>
      )}
    </div>
  )
}

export default function AttackPaths() {
  const [page, setPage] = useState(1)
  const { data: response, isLoading } = useAttackPaths(page, 20)
  const { data: stats } = useAttackPathStats()
  const [selectedId, setSelectedId] = useState<string | null>(null)

  const paths = response?.data ?? []
  const totalPages = response?.total_pages ?? 1
  const total = response?.total ?? 0

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
          {total} paths computed from {stats?.total_findings ?? 0} findings
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

      {/* Pagination */}
      {totalPages > 1 && (
        <div className="flex items-center justify-between pt-2">
          <Button
            variant="outline"
            size="sm"
            className="gap-1.5 text-xs"
            disabled={page <= 1}
            onClick={() => setPage(p => p - 1)}
          >
            <ArrowLeft className="h-3 w-3" />Previous
          </Button>
          <span className="text-xs text-muted-foreground">
            Page {page} of {totalPages}
          </span>
          <Button
            variant="outline"
            size="sm"
            className="gap-1.5 text-xs"
            disabled={page >= totalPages}
            onClick={() => setPage(p => p + 1)}
          >
            Next<ArrowRight className="h-3 w-3" />
          </Button>
        </div>
      )}
    </div>
  )
}
