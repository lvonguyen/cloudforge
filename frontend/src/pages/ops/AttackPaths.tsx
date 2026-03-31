import { useState, useMemo, useCallback, useEffect } from 'react'
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
import {
  ArrowLeft,
  Shield,
  AlertTriangle,
  Zap,
  Target,
  Sparkles,
  ArrowRight,
  Monitor,
  MoonStar,
  SunMedium,
  ListChecks,
  Route,
  Radar,
  Clock3,
} from 'lucide-react'
import type { AttackPath } from '@/types/attack-path'
import { ProviderIcon } from '@/components/ui/ProviderIcon'
import { ProviderBadge } from '@/components/ui/ProviderBadge'
import { SEVERITY_COLORS_BORDERED as SEVERITY_COLORS, SEVERITY_HEX, SEVERITY_NEUTRAL_HEX } from '@/lib/severity'

const CATEGORY_ICONS: Record<string, typeof Shield> = {
  NETWORK: Zap,
  VULNERABILITY: AlertTriangle,
  IDENTITY: Shield,
  MISCONFIGURATION: AlertTriangle,
  COMPLIANCE: Shield,
}

const SEVERITY_PRIORITY: Record<string, number> = { CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3 }

type CanvasTone = 'auto' | 'light' | 'dark'
type ResolvedCanvasTone = Exclude<CanvasTone, 'auto'>

const CANVAS_TONE_STORAGE_KEY = 'attack-path-canvas-tone'

function getCanvasToneStorage(): Pick<Storage, 'getItem' | 'setItem'> | null {
  if (typeof window === 'undefined') return null
  const storage = window.localStorage
  if (!storage || typeof storage.getItem !== 'function' || typeof storage.setItem !== 'function') return null
  return storage
}

const CANVAS_THEME: Record<ResolvedCanvasTone, {
  frameClass: string
  graphBackground: string
  gridColor: string
  nodeBackground: string
  nodeShadow: string
  nodeTextClass: string
  mutedTextClass: string
  chipClass: string
  iconWrapClass: string
  roleClass: string
  controlClass: string
  edgeColor: string
  edgeLabelColor: string
  edgeLabelBackground: string
}> = {
  light: {
    frameClass: 'border-slate-200 bg-[radial-gradient(circle_at_top,_rgba(255,255,255,0.98),_rgba(241,245,249,0.95))] shadow-[0_24px_60px_rgba(15,23,42,0.08)]',
    graphBackground: '#f8fafc',
    gridColor: '#cbd5e1',
    nodeBackground: '#ffffff',
    nodeShadow: '0 18px 42px rgba(15, 23, 42, 0.12)',
    nodeTextClass: 'text-slate-950',
    mutedTextClass: 'text-slate-500',
    chipClass: 'border border-slate-200 bg-slate-50 text-slate-700',
    iconWrapClass: 'border border-slate-200 bg-slate-50 text-slate-700',
    roleClass: 'border border-cyan-200 bg-cyan-50 text-cyan-700',
    controlClass: '[&_button]:rounded-xl [&_button]:border-slate-200 [&_button]:bg-white [&_button]:text-slate-500 [&_button:hover]:bg-slate-50 [&_button:hover]:text-slate-900',
    edgeColor: '#64748b',
    edgeLabelColor: '#475569',
    edgeLabelBackground: '#ffffff',
  },
  dark: {
    frameClass: 'border-slate-800 bg-[radial-gradient(circle_at_top,_rgba(30,41,59,0.98),_rgba(2,6,23,0.96))] shadow-[0_26px_60px_rgba(2,6,23,0.45)]',
    graphBackground: '#020617',
    gridColor: '#334155',
    nodeBackground: '#0f172a',
    nodeShadow: '0 24px 56px rgba(2, 6, 23, 0.45)',
    nodeTextClass: 'text-slate-50',
    mutedTextClass: 'text-slate-400',
    chipClass: 'border border-slate-700 bg-slate-800 text-slate-200',
    iconWrapClass: 'border border-slate-700 bg-slate-800 text-slate-100',
    roleClass: 'border border-cyan-500/30 bg-cyan-500/10 text-cyan-100',
    controlClass: '[&_button]:rounded-xl [&_button]:border-slate-700 [&_button]:bg-slate-900/90 [&_button]:text-slate-400 [&_button:hover]:bg-slate-800 [&_button:hover]:text-slate-100',
    edgeColor: '#94a3b8',
    edgeLabelColor: '#cbd5e1',
    edgeLabelBackground: '#0f172a',
  },
}

function getInitialCanvasTone(): CanvasTone {
  const stored = getCanvasToneStorage()?.getItem(CANVAS_TONE_STORAGE_KEY)
  if (stored === 'auto' || stored === 'light' || stored === 'dark') return stored
  return 'auto'
}

function isEditableTarget(target: EventTarget | null): boolean {
  if (!(target instanceof HTMLElement)) return false
  if (target.isContentEditable) return true
  return Boolean(target.closest('input, textarea, select, [role="textbox"]'))
}

function useResolvedCanvasTone(canvasTone: CanvasTone): ResolvedCanvasTone {
  const [documentDark, setDocumentDark] = useState(() =>
    typeof document !== 'undefined' && document.documentElement.classList.contains('dark'),
  )

  useEffect(() => {
    if (typeof document === 'undefined') return
    const root = document.documentElement
    const sync = () => setDocumentDark(root.classList.contains('dark'))
    sync()
    if (typeof MutationObserver === 'undefined') return
    const observer = new MutationObserver(sync)
    observer.observe(root, { attributes: true, attributeFilter: ['class'] })
    return () => observer.disconnect()
  }, [])

  return canvasTone === 'auto' ? (documentDark ? 'dark' : 'light') : canvasTone
}

function nodeRoleLabel(index: number, total: number) {
  if (index === 0) return 'Entry'
  if (index === total - 1) return 'Target'
  return 'Pivot'
}

function extractActionItems(path: AttackPath): string[] {
  const source = path.ai_remediation || path.ai_risk_narrative || path.description
  const actions = source
    .split(/\r?\n|[.;]/)
    .map(part => part.trim())
    .filter(Boolean)
    .slice(0, 3)
  if (actions.length > 0) return actions
  return [
    `Reduce exposure on ${path.entry_point.resource_name}`,
    `Break pivot access across ${Math.max(path.nodes.length - 2, 1)} intermediate step${path.nodes.length - 2 === 1 ? '' : 's'}`,
    `Harden ${path.target.resource_name} and review dependent identities`,
  ]
}

function buildPathStory(path: AttackPath): string {
  return path.nodes.map(node => node.resource_name).join(' -> ')
}

function formatStageSummary(path: AttackPath): string {
  const pivots = Math.max(path.nodes.length - 2, 0)
  if (pivots === 0) return 'Direct path from foothold to target'
  if (pivots === 1) return 'Single pivot before target access'
  return `${pivots} pivot steps before target access`
}

function CanvasToneToggle({
  value,
  resolvedTone,
  onChange,
}: {
  value: CanvasTone
  resolvedTone: ResolvedCanvasTone
  onChange: (value: CanvasTone) => void
}) {
  const options: Array<{ value: CanvasTone; label: string; icon: typeof Monitor }> = [
    { value: 'auto', label: 'Auto', icon: Monitor },
    { value: 'light', label: 'Light', icon: SunMedium },
    { value: 'dark', label: 'Dark', icon: MoonStar },
  ]

  return (
    <div className="flex items-center gap-2" aria-label="Attack path canvas tone">
      <span className="text-[10px] font-semibold uppercase tracking-[0.22em] text-muted-foreground">Canvas</span>
      <div className="inline-flex items-center gap-1 rounded-full border border-border/80 bg-card/80 p-1">
        {options.map(({ value: optionValue, label, icon: Icon }) => {
          const active = value === optionValue
          return (
            <Button
              key={optionValue}
              type="button"
              variant="ghost"
              size="sm"
              aria-pressed={active}
              aria-label={`${label} canvas`}
              onClick={() => onChange(optionValue)}
              className={`h-7 rounded-full px-2.5 text-[11px] ${
                active
                  ? resolvedTone === 'dark'
                    ? 'bg-slate-900 text-slate-50 hover:bg-slate-900'
                    : 'bg-white text-slate-900 shadow-sm hover:bg-white'
                  : 'text-muted-foreground'
              }`}
            >
              <Icon className="mr-1 h-3.5 w-3.5" />
              {label}
            </Button>
          )
        })}
      </div>
    </div>
  )
}

function pathToFlow(
  path: AttackPath,
  resolvedTone: ResolvedCanvasTone,
  chokePointIds?: Set<string>,
): { nodes: Node[]; edges: Edge[] } {
  const canvasTheme = CANVAS_THEME[resolvedTone]
  const nodes: Node[] = path.nodes.map((n, i) => ({
    id: n.id,
    position: { x: i * 360, y: 0 },
    data: {
      label: (
        <div className={`text-left px-3 py-3 ${canvasTheme.nodeTextClass}`}>
          <div className="flex items-start justify-between gap-3">
            <div className="flex min-w-0 items-start gap-2.5">
              <div className={`mt-0.5 flex h-9 w-9 shrink-0 items-center justify-center rounded-2xl ${canvasTheme.iconWrapClass}`}>
                <ProviderIcon provider={n.provider} className="h-4 w-4" />
              </div>
              <div className="min-w-0">
                <div className="mb-1 flex items-center gap-1.5">
                  <span className={`rounded-full px-2 py-0.5 text-[9px] font-semibold uppercase tracking-wide ${canvasTheme.roleClass}`}>
                    {nodeRoleLabel(i, path.nodes.length)}
                  </span>
                  {chokePointIds?.has(n.resource_id) && (
                    <span className="rounded-full border border-amber-300 bg-amber-50 px-2 py-0.5 text-[9px] font-semibold uppercase tracking-wide text-amber-700 dark:border-amber-500/30 dark:bg-amber-500/10 dark:text-amber-200">
                      Choke
                    </span>
                  )}
                </div>
                <div className="truncate text-sm font-semibold">{n.resource_name}</div>
                <div className={`mt-1 flex items-center gap-1.5 text-[10px] font-medium ${canvasTheme.mutedTextClass}`}>
                  <span className={`inline-flex items-center rounded-full px-2 py-0.5 ${canvasTheme.chipClass}`}>
                    {n.resource_type}
                  </span>
                  <span>{n.region}</span>
                </div>
              </div>
            </div>
            <div className="flex shrink-0 flex-col items-end gap-1">
              <span className={`rounded-full px-2 py-0.5 text-[9px] font-bold ${SEVERITY_COLORS[n.severity] ?? ''}`}>
                {n.severity}
              </span>
            </div>
          </div>
          <div className={`mt-2 flex items-center gap-1.5 text-[10px] ${canvasTheme.mutedTextClass}`}>
            <span className={`inline-flex items-center rounded-full px-2 py-0.5 ${canvasTheme.chipClass}`}>
              {n.category}
            </span>
            <span className="font-mono uppercase">{n.provider}</span>
          </div>
          <div className={`mt-2 text-[10px] ${canvasTheme.mutedTextClass}`}>
            {path.nodes.length} resources in path
          </div>
        </div>
      ),
    },
    sourcePosition: Position.Right,
    targetPosition: Position.Left,
    style: {
      border: chokePointIds?.has(n.resource_id)
        ? '3px dashed #f59e0b'
        : `2px solid ${SEVERITY_HEX[n.severity] ?? SEVERITY_NEUTRAL_HEX}`,
      borderRadius: '22px',
      background: canvasTheme.nodeBackground,
      padding: '0px',
      width: 280,
      boxShadow: canvasTheme.nodeShadow,
    },
  }))

  const edges: Edge[] = path.edges.map(e => ({
    id: e.id,
    source: e.source,
    target: e.target,
    label: e.label,
    type: 'smoothstep',
    markerEnd: { type: MarkerType.ArrowClosed, width: 16, height: 16 },
    style: { strokeWidth: 2.25, stroke: canvasTheme.edgeColor },
    labelStyle: { fontSize: 10, fill: canvasTheme.edgeLabelColor, fontWeight: 600 },
    labelBgStyle: { fill: canvasTheme.edgeLabelBackground, fillOpacity: 0.98 },
    labelBgPadding: [4, 6] as [number, number],
  }))

  return { nodes, edges }
}

function PathCard({ path, onClick }: { path: AttackPath; onClick: () => void }) {
  const Icon = CATEGORY_ICONS[path.entry_point?.category] ?? AlertTriangle
  const actionItems = extractActionItems(path)
  return (
    <button type="button" onClick={onClick} className="w-full text-left">
      <Card className="overflow-hidden rounded-[28px] border border-border/80 bg-card/95 shadow-[0_18px_48px_rgba(15,23,42,0.06)] transition-all hover:-translate-y-0.5 hover:border-slate-300 hover:shadow-[0_24px_60px_rgba(15,23,42,0.1)] dark:hover:border-slate-700">
        <CardContent className="p-4">
          <div className="flex items-start gap-3">
            <div className="flex h-10 w-10 shrink-0 items-center justify-center rounded-2xl border border-slate-200 bg-slate-50 text-slate-700 dark:border-slate-700 dark:bg-slate-900 dark:text-slate-100">
              <Icon className="h-4 w-4" />
            </div>
            <div className="flex-1 min-w-0">
              <div className="flex items-center gap-2 flex-wrap mb-1">
                <Badge variant="outline" className={`text-[10px] px-1.5 py-0 rounded-full ${SEVERITY_COLORS[path.severity] ?? ''}`}>
                  {path.severity}
                </Badge>
                <span className="text-[10px] text-muted-foreground">{path.hop_count} hop{path.hop_count !== 1 ? 's' : ''}</span>
                <Badge variant="outline" className={`text-[10px] px-1.5 py-0 rounded-full ${
                  path.nodes.length > 10 ? 'bg-red-100 text-red-700 border-red-300 dark:bg-red-900/30 dark:text-red-300 dark:border-red-800' :
                  path.nodes.length >= 5 ? 'bg-orange-100 text-orange-700 border-orange-300 dark:bg-orange-900/30 dark:text-orange-300 dark:border-orange-800' :
                  'bg-yellow-100 text-yellow-700 border-yellow-300 dark:bg-yellow-900/30 dark:text-yellow-300 dark:border-yellow-800'
                }`}>
                  Blast: {path.nodes.length} resources
                </Badge>
                <span className="text-[10px] text-muted-foreground">Score: {path.score.toFixed(0)}</span>
                {path.nodes.length > 0 && (
                  <ProviderBadge provider={path.nodes[0].provider} />
                )}
                {path.ai_enriched && (
                  <Badge variant="outline" className="text-[10px] px-1.5 py-0 rounded-full bg-violet-100 text-violet-700 border-violet-300 dark:bg-violet-900/30 dark:text-violet-300 dark:border-violet-800 gap-0.5">
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
              <div className="mt-3 rounded-2xl border border-border/70 bg-muted/20 px-3 py-2">
                <div className="flex items-center gap-1.5 text-[10px] font-semibold uppercase tracking-wide text-muted-foreground">
                  <Route className="h-3 w-3" />Path Story
                </div>
                <p className="mt-1 text-xs font-medium">{buildPathStory(path)}</p>
                <p className="mt-1 text-[10px] text-muted-foreground">{formatStageSummary(path)}</p>
              </div>
              <div className="mt-3 flex items-center gap-2 rounded-2xl border border-border/70 bg-muted/40 px-3 py-2">
                <div className="min-w-0 flex-1">
                  <div className="text-[10px] font-semibold uppercase tracking-wide text-muted-foreground">Entry</div>
                  <div className="truncate text-xs font-medium">{path.entry_point.resource_name}</div>
                </div>
                <ArrowRight className="h-3.5 w-3.5 shrink-0 text-muted-foreground" />
                <div className="min-w-0 flex-1 text-right">
                  <div className="text-[10px] font-semibold uppercase tracking-wide text-muted-foreground">Target</div>
                  <div className="truncate text-xs font-medium">{path.target.resource_name}</div>
                </div>
              </div>
              <div className="mt-3 rounded-2xl border border-border/70 bg-background/80 px-3 py-2">
                <div className="flex items-center gap-1.5 text-[10px] font-semibold uppercase tracking-wide text-muted-foreground">
                  <ListChecks className="h-3 w-3" />Immediate Actions
                </div>
                <ul className="mt-1.5 space-y-1">
                  {actionItems.slice(0, 2).map(item => (
                    <li key={item} className="text-[11px] text-muted-foreground">
                      {item}
                    </li>
                  ))}
                </ul>
              </div>
              <div className="flex items-center gap-1 mt-3">
                {path.finding_ids.map(fid => (
                  <span key={fid} className="text-[9px] font-mono bg-muted px-1.5 py-0.5 rounded-full">{fid}</span>
                ))}
              </div>
            </div>
            <div className="shrink-0">
              <Target className="h-4 w-4 text-muted-foreground" />
            </div>
          </div>
        </CardContent>
      </Card>
    </button>
  )
}

function PathGraphView({
  path,
  onBack,
  chokePointIds,
  canvasTone,
  resolvedCanvasTone,
  onCanvasToneChange,
}: {
  path: AttackPath
  onBack: () => void
  chokePointIds?: Set<string>
  canvasTone: CanvasTone
  resolvedCanvasTone: ResolvedCanvasTone
  onCanvasToneChange: (value: CanvasTone) => void
}) {
  const canvasTheme = CANVAS_THEME[resolvedCanvasTone]
  const actionItems = useMemo(() => extractActionItems(path), [path])
  const pathStory = useMemo(() => buildPathStory(path), [path])
  const { nodes, edges } = useMemo(
    () => pathToFlow(path, resolvedCanvasTone, chokePointIds),
    [path, resolvedCanvasTone, chokePointIds],
  )

  return (
    <div className="space-y-4">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <div className="flex items-center gap-3">
          <Button variant="ghost" size="sm" className="gap-1.5 -ml-2" onClick={onBack}>
            <ArrowLeft className="h-4 w-4" />All Paths
          </Button>
          <Badge variant="outline" className={`text-[10px] px-1.5 py-0 rounded-full ${SEVERITY_COLORS[path.severity] ?? ''}`}>
            {path.severity}
          </Badge>
          <span className="text-sm font-medium">{path.title}</span>
        </div>
        <CanvasToneToggle value={canvasTone} resolvedTone={resolvedCanvasTone} onChange={onCanvasToneChange} />
      </div>
      <p className="text-xs text-muted-foreground">{path.ai_description ?? path.description}</p>

      <div className="grid grid-cols-1 gap-3 md:grid-cols-2 xl:grid-cols-4">
        <Card className="rounded-[24px] border border-border/80">
          <CardContent className="p-4">
            <div className="flex items-center gap-2 text-[10px] font-semibold uppercase tracking-wide text-muted-foreground">
              <Radar className="h-3.5 w-3.5" />Entry Signal
            </div>
            <p className="mt-2 text-sm font-semibold">{path.entry_point.resource_name}</p>
            <p className="mt-1 text-xs text-muted-foreground">{path.entry_point.category} on {path.entry_point.resource_type}</p>
          </CardContent>
        </Card>
        <Card className="rounded-[24px] border border-border/80">
          <CardContent className="p-4">
            <div className="flex items-center gap-2 text-[10px] font-semibold uppercase tracking-wide text-muted-foreground">
              <Target className="h-3.5 w-3.5" />Target At Risk
            </div>
            <p className="mt-2 text-sm font-semibold">{path.target.resource_name}</p>
            <p className="mt-1 text-xs text-muted-foreground">{path.target.resource_type} in {path.target.region}</p>
          </CardContent>
        </Card>
        <Card className="rounded-[24px] border border-border/80">
          <CardContent className="p-4">
            <div className="flex items-center gap-2 text-[10px] font-semibold uppercase tracking-wide text-muted-foreground">
              <Route className="h-3.5 w-3.5" />Path Shape
            </div>
            <p className="mt-2 text-sm font-semibold">{path.nodes.length} resources · {path.hop_count} hops</p>
            <p className="mt-1 text-xs text-muted-foreground">{formatStageSummary(path)}</p>
          </CardContent>
        </Card>
        <Card className="rounded-[24px] border border-border/80">
          <CardContent className="p-4">
            <div className="flex items-center gap-2 text-[10px] font-semibold uppercase tracking-wide text-muted-foreground">
              <Clock3 className="h-3.5 w-3.5" />Immediate Action
            </div>
            <p className="mt-2 text-sm font-semibold">{actionItems[0]}</p>
            <p className="mt-1 text-xs text-muted-foreground">Prioritize the first break in the chain before deeper cleanup.</p>
          </CardContent>
        </Card>
      </div>

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

      <div
        data-testid="attack-path-canvas"
        data-canvas-tone={resolvedCanvasTone}
        className={`h-[440px] overflow-hidden rounded-[30px] border ${canvasTheme.frameClass}`}
      >
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
          style={{ background: canvasTheme.graphBackground }}
        >
          <Background gap={18} size={1} color={canvasTheme.gridColor} />
          <Controls showInteractive={false} className={canvasTheme.controlClass} />
        </ReactFlow>
      </div>

      <div className="flex flex-wrap items-center gap-2 text-[10px]">
        {['Entry node', 'Pivot step', 'Target node', 'Choke point = reused across paths'].map(label => (
          <span key={label} className="rounded-full border border-border/80 bg-muted/50 px-2 py-1 text-muted-foreground">
            {label}
          </span>
        ))}
      </div>

      <Card className="rounded-none">
        <CardHeader className="pb-2 pt-3 px-4">
          <span className="text-xs font-semibold uppercase tracking-wide text-muted-foreground">Analyst Narrative</span>
        </CardHeader>
        <CardContent className="px-4 pb-4 space-y-3">
          <p className="text-xs text-muted-foreground">{path.ai_risk_narrative ?? path.description}</p>
          <div className="rounded-none border border-border bg-muted/20 p-3">
            <div className="text-[10px] font-semibold uppercase tracking-wide text-muted-foreground">Sequence</div>
            <p className="mt-1 text-xs font-medium">{pathStory}</p>
          </div>
          <div>
            <div className="text-[10px] font-semibold uppercase tracking-wide text-muted-foreground">Immediate actions</div>
            <ul className="mt-2 space-y-1 text-xs text-muted-foreground">
              {actionItems.map(item => (
                <li key={item}>{item}</li>
              ))}
            </ul>
          </div>
        </CardContent>
      </Card>

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
  const { data: response, isLoading, isError } = useAttackPaths(page, 20)
  const { data: stats } = useAttackPathStats()
  const [selectedId, setSelectedId] = useState<string | null>(null)
  const [canvasTone, setCanvasTone] = useState<CanvasTone>(getInitialCanvasTone)

  const paths = response?.data ?? []
  const totalPages = response?.total_pages ?? 1
  const total = response?.total ?? 0
  const resolvedCanvasTone = useResolvedCanvasTone(canvasTone)

  useEffect(() => {
    getCanvasToneStorage()?.setItem(CANVAS_TONE_STORAGE_KEY, canvasTone)
  }, [canvasTone])

  const selectedPath = useMemo(
    () => paths.find(p => p.id === selectedId) ?? null,
    [paths, selectedId]
  )
  const selectedIndex = useMemo(
    () => paths.findIndex(path => path.id === selectedId),
    [paths, selectedId],
  )

  // Full dataset for choke point analysis
  const { data: fullResponse } = useAttackPaths(1, 100)
  const allPaths = useMemo(() => fullResponse?.data ?? [], [fullResponse])

  const chokePoints = useMemo(() => {
    const resourceMap = new Map<string, { resource_name: string; resource_type: string; provider: string; pathCount: number; severity: string }>()
    for (const p of allPaths) {
      const seen = new Set<string>()
      for (const node of p.nodes) {
        if (seen.has(node.resource_id)) continue
        seen.add(node.resource_id)
        const existing = resourceMap.get(node.resource_id)
        if (existing) {
          existing.pathCount++
          if ((SEVERITY_PRIORITY[node.severity] ?? 9) < (SEVERITY_PRIORITY[existing.severity] ?? 9)) {
            existing.severity = node.severity
          }
        } else {
          resourceMap.set(node.resource_id, {
            resource_name: node.resource_name,
            resource_type: node.resource_type,
            provider: node.provider,
            pathCount: 1,
            severity: node.severity,
          })
        }
      }
    }
    return [...resourceMap.entries()]
      .filter(([, r]) => r.pathCount > 1)
      .sort((a, b) => b[1].pathCount - a[1].pathCount)
      .slice(0, 5)
  }, [allPaths])

  const chokePointIds = useMemo(
    () => new Set(chokePoints.map(([id]) => id)),
    [chokePoints],
  )
  const highestRiskPath = paths[0] ?? null
  const mostSharedResource = chokePoints[0] ?? null

  const handleBack = useCallback(() => setSelectedId(null), [])

  useEffect(() => {
    function handleKeyDown(event: KeyboardEvent) {
      if (isEditableTarget(event.target)) return

      if (event.key === '[') {
        if (page > 1) {
          event.preventDefault()
          setPage(current => Math.max(1, current - 1))
        }
        return
      }

      if (event.key === ']') {
        if (page < totalPages) {
          event.preventDefault()
          setPage(current => Math.min(totalPages, current + 1))
        }
        return
      }

      if (event.key === 'Escape') {
        if (selectedId) {
          event.preventDefault()
          setSelectedId(null)
        }
        return
      }

      const wantsNext = event.key === 'j' || event.key === 'ArrowDown'
      const wantsPrev = event.key === 'k' || event.key === 'ArrowUp'
      if (!wantsNext && !wantsPrev) return
      if (paths.length === 0) return

      event.preventDefault()
      const fallbackIndex = wantsNext ? 0 : paths.length - 1
      const currentIndex = selectedIndex >= 0 ? selectedIndex : fallbackIndex
      const nextIndex = wantsNext
        ? Math.min(paths.length - 1, currentIndex + (selectedIndex >= 0 ? 1 : 0))
        : Math.max(0, currentIndex - (selectedIndex >= 0 ? 1 : 0))
      setSelectedId(paths[nextIndex]?.id ?? null)
    }

    document.addEventListener('keydown', handleKeyDown)
    return () => document.removeEventListener('keydown', handleKeyDown)
  }, [page, paths, selectedId, selectedIndex, totalPages])

  if (isLoading) {
    return <div className="text-sm text-muted-foreground p-6">Computing attack paths...</div>
  }
  if (isError) {
    return <div className="text-sm text-destructive p-6">Failed to load attack paths. Check backend connection.</div>
  }

  if (selectedPath) {
    return (
      <div className="max-w-5xl p-6">
        <PathGraphView
          path={selectedPath}
          onBack={handleBack}
          chokePointIds={chokePointIds}
          canvasTone={canvasTone}
          resolvedCanvasTone={resolvedCanvasTone}
          onCanvasToneChange={setCanvasTone}
        />
      </div>
    )
  }

  return (
    <div className="space-y-6 max-w-4xl">
      <div className="flex flex-wrap items-start justify-between gap-4">
        <div>
          <h1 className="text-xl font-semibold">Attack Paths</h1>
          <p className="text-sm text-muted-foreground mt-0.5">
            {total} paths · {stats?.total_findings ?? 0} findings analyzed
            {stats ? ` · ${stats.coverage_percent.toFixed(0)}% coverage · ${stats.isolated_findings} isolated` : ''}
          </p>
          <p className="mt-1 text-[11px] uppercase tracking-[0.18em] text-muted-foreground/80">
            J/K browse paths · Esc return · [ ] change page
          </p>
        </div>
        <CanvasToneToggle value={canvasTone} resolvedTone={resolvedCanvasTone} onChange={setCanvasTone} />
      </div>

      {(highestRiskPath || mostSharedResource) && (
        <div className="grid grid-cols-1 gap-4 lg:grid-cols-[minmax(0,1.4fr)_minmax(0,1fr)]">
          {highestRiskPath && (
            <Card className="rounded-[30px] border border-border/80 bg-card/95">
              <CardContent className="p-5 space-y-3">
                <div className="flex items-center gap-2">
                  <Badge variant="outline" className={`text-[10px] px-1.5 py-0 rounded-full ${SEVERITY_COLORS[highestRiskPath.severity] ?? ''}`}>
                    Highest risk
                  </Badge>
                  <span className="text-[10px] font-mono text-muted-foreground">Score {highestRiskPath.score.toFixed(0)}</span>
                </div>
                <div>
                  <p className="text-lg font-semibold leading-tight">{highestRiskPath.title}</p>
                  <p className="mt-1 text-sm text-muted-foreground">{highestRiskPath.ai_description ?? highestRiskPath.description}</p>
                </div>
                <div className="grid grid-cols-1 gap-3 md:grid-cols-3">
                  <div className="rounded-2xl border border-border/70 bg-muted/20 px-3 py-2">
                    <div className="text-[10px] font-semibold uppercase tracking-wide text-muted-foreground">Entry</div>
                    <p className="mt-1 text-sm font-medium">{highestRiskPath.entry_point.resource_name}</p>
                  </div>
                  <div className="rounded-2xl border border-border/70 bg-muted/20 px-3 py-2">
                    <div className="text-[10px] font-semibold uppercase tracking-wide text-muted-foreground">Target</div>
                    <p className="mt-1 text-sm font-medium">{highestRiskPath.target.resource_name}</p>
                  </div>
                  <div className="rounded-2xl border border-border/70 bg-muted/20 px-3 py-2">
                    <div className="text-[10px] font-semibold uppercase tracking-wide text-muted-foreground">Shape</div>
                    <p className="mt-1 text-sm font-medium">{highestRiskPath.nodes.length} resources · {highestRiskPath.hop_count} hops</p>
                  </div>
                </div>
              </CardContent>
            </Card>
          )}
          {mostSharedResource && (
            <Card className="rounded-[30px] border border-amber-200 bg-amber-50/60 dark:border-amber-900/40 dark:bg-amber-950/10">
              <CardContent className="p-5 space-y-3">
                <div className="flex items-center gap-2 text-amber-700 dark:text-amber-300">
                  <Target className="h-4 w-4" />
                  <span className="text-xs font-semibold uppercase tracking-wide">Analyst Focus</span>
                </div>
                <div>
                  <p className="text-lg font-semibold">{mostSharedResource[1].resource_name}</p>
                  <p className="mt-1 text-sm text-muted-foreground">This resource appears across {mostSharedResource[1].pathCount} attack paths and is likely the best choke point to break first.</p>
                </div>
                <div className="flex flex-wrap items-center gap-2">
                  <ProviderBadge provider={mostSharedResource[1].provider} />
                  <Badge variant="outline" className={`text-[10px] px-1.5 py-0 rounded-full ${SEVERITY_COLORS[mostSharedResource[1].severity] ?? ''}`}>
                    {mostSharedResource[1].severity}
                  </Badge>
                  <span className="text-[10px] font-mono text-muted-foreground">{mostSharedResource[1].resource_type}</span>
                </div>
              </CardContent>
            </Card>
          )}
        </div>
      )}

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

      {/* Choke Points */}
      {chokePoints.length > 0 && (
        <Card className="rounded-none border-amber-200 dark:border-amber-900/40">
          <CardHeader className="pb-2 pt-3 px-4">
            <span className="text-xs font-semibold uppercase tracking-wide text-amber-600 dark:text-amber-400 flex items-center gap-1.5">
              <Target className="h-3.5 w-3.5" />Choke Points
            </span>
            <span className="text-[10px] text-muted-foreground">Resources appearing in multiple attack paths</span>
          </CardHeader>
          <CardContent className="px-4 pb-3">
            <div className="space-y-1.5">
              {chokePoints.map(([id, cp]) => (
                <div key={id} className="flex items-center gap-2 text-xs">
                  <span className="h-2 w-2 shrink-0" style={{ backgroundColor: SEVERITY_HEX[cp.severity] ?? SEVERITY_NEUTRAL_HEX }} />
                  <ProviderIcon provider={cp.provider} className="h-3.5 w-3.5 shrink-0" />
                  <span className="flex-1 truncate font-medium">{cp.resource_name}</span>
                  <span className="text-[10px] text-muted-foreground">{cp.resource_type}</span>
                  <Badge variant="outline" className={`text-[10px] px-1.5 py-0 rounded-none ${SEVERITY_COLORS[cp.severity] ?? ''}`}>
                    in {cp.pathCount} paths
                  </Badge>
                </div>
              ))}
            </div>
          </CardContent>
        </Card>
      )}

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
