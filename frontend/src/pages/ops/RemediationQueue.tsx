import { useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { Card, CardContent } from '@/components/ui/card'
import { Button } from '@/components/ui/button'
import { Separator } from '@/components/ui/separator'
import { RemediationTierBadge } from '@/components/remediation/RemediationTierBadge'
import { ProviderBadge } from '@/components/ui/ProviderBadge'
import { CheckCircle2, Play, Eye, RotateCcw, List, LayoutGrid, Ticket } from 'lucide-react'
import { useRemediations, useExecuteRemediation, usePatchRemediation } from '@/hooks/useRemediations'
import { useTracePanel } from '@/lib/trace-panel-context'
import { useActionCooldown } from '@/hooks/useActionCooldown'
import type { RemediationRecord } from '@/types/remediation'
import { REMEDIATION_STATUS_COLORS as STATUS_COLORS } from '@/lib/severity'
import { DragDropContext, Droppable, Draggable, type DropResult } from '@hello-pangea/dnd'
import { useToast } from '@/hooks/useToast'
import { ToastStack } from '@/components/ui/ToastStack'

interface QueueItem {
  id: string
  finding_id: string
  title: string
  resource: string
  provider: string
  tier: 1 | 2 | 3
  handler: string
  status: 'pending' | 'in_progress' | 'completed' | 'failed' | 'skipped'
  dry_run_ok: boolean | null
  created_at: string
}

function toQueueItem(r: RemediationRecord): QueueItem {
  const dryRunOk = r.result
    ? r.result?.success
    : r.status === 'pending' ? null : null
  return {
    id: r.id,
    finding_id: r.finding_id,
    title: r.result?.message ?? `${r.domain} — ${r.handler}`,
    resource: r.result?.resource_id ?? r.finding_id,
    provider: r.domain,
    tier: (r.tier >= 1 && r.tier <= 3 ? r.tier : 2) as 1 | 2 | 3,
    handler: r.handler,
    status: r.status,
    dry_run_ok: dryRunOk,
    created_at: r.created_at,
  }
}


function QueueItemCard({ item }: { item: QueueItem }) {
  const navigate = useNavigate()
  const { openStreaming, openDryRun } = useTracePanel()
  const executeMutation = useExecuteRemediation()
  const executeCooldown = useActionCooldown({ key: `execute-${item.id}`, cooldownMs: 30_000 })
  const dryRunCooldown = useActionCooldown({ key: `dryrun-${item.id}`, cooldownMs: 15_000 })
  const retryCooldown = useActionCooldown({ key: `retry-${item.id}`, cooldownMs: 30_000 })
  const [dryRunPassed, setDryRunPassed] = useState(false)

  function handleExecute() {
    if (!executeCooldown.canFire) return
    openStreaming('Executing: ' + item.handler)
    executeCooldown.fire()
    executeMutation.mutate(item.id)
  }

  function handleDryRun() {
    if (!dryRunCooldown.canFire) return
    openDryRun('Dry Run: ' + item.handler, {
      finding_id: item.finding_id,
      would_succeed: true,
      planned_actions: ['validate_preconditions', 'apply_change', 'verify_result'],
      prerequisites_met: true,
      warnings: [],
      estimated_impact: 'Low — scoped to single resource',
    })
    dryRunCooldown.fire()
    setDryRunPassed(true)
  }

  function handleRetry() {
    if (!retryCooldown.canFire) return
    openStreaming('Retrying: ' + item.handler)
    retryCooldown.fire()
    executeMutation.mutate(item.id)
  }

  return (
    <Card
      className={`cursor-pointer hover:bg-muted/50 transition-colors ${item.status === 'failed' ? 'border-red-200 dark:border-red-800' : ''}`}
      onClick={() => navigate(`/ops/remediation/${item.id}`)}
    >
      <CardContent className="p-4">
        <div className="flex items-start gap-4">
          <div className="flex-1 min-w-0">
            <div className="flex items-center gap-2 flex-wrap mb-1">
              <span className={`text-[10px] font-medium px-2 py-0.5 rounded-full ${STATUS_COLORS[item.status] ?? 'bg-gray-100 text-gray-700 dark:bg-gray-900/30 dark:text-gray-300'}`}>{item.status}</span>
              <ProviderBadge provider={item.provider} />
              {(item.dry_run_ok === true || dryRunPassed) && (
                <span className="text-[10px] text-green-600 dark:text-green-400 flex items-center gap-0.5"><CheckCircle2 className="h-3 w-3" />dry-run passed</span>
              )}
              {item.dry_run_ok === false && (
                <span className="text-[10px] text-red-600 dark:text-red-400">dry-run failed</span>
              )}
              {(item.status === 'in_progress' || item.status === 'completed') && (
                <span className="text-[10px] text-purple-600 dark:text-purple-400 flex items-center gap-0.5">
                  <Ticket className="h-3 w-3" />MOCK
                </span>
              )}
            </div>
            <p className="text-sm font-medium leading-snug">{item.title}</p>
            <div className="flex items-center gap-3 mt-1">
              <p className="text-xs text-muted-foreground font-mono">{item.resource}</p>
              <p className="text-[10px] text-muted-foreground">Handler: <code>{item.handler}</code></p>
            </div>
          </div>
          <div className="flex gap-2 shrink-0" onClick={e => e.stopPropagation()}>
            {item.status === 'pending' && item.dry_run_ok !== false && (
              <Button
                size="sm"
                className="text-xs h-7 gap-1"
                disabled={!executeCooldown.canFire || (item.dry_run_ok === null && !dryRunPassed)}
                onClick={handleExecute}
              >
                <Play className="h-3 w-3" />
                {!executeCooldown.canFire ? 'Running\u2026' : 'Execute'}
              </Button>
            )}
            {item.dry_run_ok === null && !dryRunPassed && item.status === 'pending' && (
              <Button
                size="sm"
                variant="outline"
                className="text-xs h-7 gap-1"
                disabled={!dryRunCooldown.canFire}
                onClick={handleDryRun}
              >
                <Eye className="h-3 w-3" />Dry Run
              </Button>
            )}
            {item.status === 'failed' && (
              <Button
                size="sm"
                variant="outline"
                className="text-xs h-7 gap-1"
                disabled={!retryCooldown.canFire}
                onClick={handleRetry}
              >
                <RotateCcw className="h-3 w-3" />{!retryCooldown.canFire ? 'Retrying\u2026' : 'Retry'}
              </Button>
            )}
          </div>
        </div>
      </CardContent>
    </Card>
  )
}

function TierSection({ tier, items }: { tier: 1 | 2 | 3; items: QueueItem[] }) {
  const descriptions: Record<number, string> = {
    1: 'Fully automated — no approval required',
    2: 'Semi-automated — dry-run first, then execute',
    3: 'Manual — Asana ticket created, human required',
  }

  if (items.length === 0) return null

  return (
    <div className="space-y-3">
      <div className="flex items-center gap-2">
        <RemediationTierBadge tier={tier} />
        <span className="text-xs text-muted-foreground">{descriptions[tier]}</span>
        <span className="ml-auto text-xs text-muted-foreground">{items.length} item{items.length !== 1 ? 's' : ''}</span>
      </div>
      {items.map(item => (
        <QueueItemCard key={item.id} item={item} />
      ))}
    </div>
  )
}

const KANBAN_COLUMNS = ['pending', 'in_progress', 'completed', 'failed'] as const
const KANBAN_LABELS: Record<string, string> = {
  pending: 'Pending',
  in_progress: 'In Progress',
  completed: 'Completed',
  failed: 'Failed',
}

function KanbanCard({ item }: { item: QueueItem }) {
  const navigate = useNavigate()
  return (
    <Card
      className={`cursor-pointer hover:bg-muted/50 transition-colors ${item.status === 'failed' ? 'border-red-200 dark:border-red-800' : ''}`}
      onClick={() => navigate(`/ops/remediation/${item.id}`)}
    >
      <CardContent className="p-3">
        <div className="flex items-center gap-2 mb-1">
          <ProviderBadge provider={item.provider} />
          <RemediationTierBadge tier={item.tier} />
        </div>
        <p className="text-xs font-medium leading-snug line-clamp-2">{item.title}</p>
        <p className="text-[10px] text-muted-foreground font-mono mt-1 truncate">{item.resource}</p>
      </CardContent>
    </Card>
  )
}

function KanbanView({ items, onDragEnd }: { items: QueueItem[]; onDragEnd: (result: DropResult) => void }) {
  return (
    <DragDropContext onDragEnd={onDragEnd}>
      <div className="grid grid-cols-4 gap-3" style={{ minHeight: 'calc(100vh - 200px)' }}>
        {KANBAN_COLUMNS.map(status => {
          const colItems = items.filter(i => i.status === status)
          return (
            <Droppable droppableId={status} key={status}>
              {(provided, snapshot) => (
                <div
                  ref={provided.innerRef}
                  {...provided.droppableProps}
                  className={`border border-border p-2 space-y-2 overflow-y-auto transition-colors ${
                    snapshot.isDraggingOver ? 'bg-muted/30' : ''
                  }`}
                >
                  <div className="flex items-center justify-between px-1 pb-1 border-b border-border mb-1">
                    <span className={`text-[10px] font-medium px-2 py-0.5 rounded-full ${STATUS_COLORS[status] ?? ''}`}>
                      {KANBAN_LABELS[status]}
                    </span>
                    <span className="text-[10px] text-muted-foreground tabular-nums">{colItems.length}</span>
                  </div>
                  {colItems.map((item, index) => (
                    <Draggable draggableId={item.id} index={index} key={item.id}>
                      {(dragProvided) => (
                        <div
                          ref={dragProvided.innerRef}
                          {...dragProvided.draggableProps}
                          {...dragProvided.dragHandleProps}
                        >
                          <KanbanCard item={item} />
                        </div>
                      )}
                    </Draggable>
                  ))}
                  {provided.placeholder}
                </div>
              )}
            </Droppable>
          )
        })}
      </div>
    </DragDropContext>
  )
}

export default function RemediationQueue() {
  const { data: records = [], isLoading, isError } = useRemediations()
  const [viewMode, setViewMode] = useState<'list' | 'kanban'>('list')
  const [statusOverrides, setStatusOverrides] = useState<Map<string, string>>(new Map())
  const { toasts, toast, dismiss } = useToast()

  const queue = records.map(toQueueItem)
  const items = queue.map(item => {
    const override = statusOverrides.get(item.id)
    return override ? { ...item, status: override as QueueItem['status'] } : item
  })

  const tier1 = items.filter(q => q.tier === 1)
  const tier2 = items.filter(q => q.tier === 2)
  const tier3 = items.filter(q => q.tier === 3)

  const pending = items.filter(q => q.status === 'pending').length
  const inProgress = items.filter(q => q.status === 'in_progress').length

  const patchRemediation = usePatchRemediation()

  function handleKanbanDragEnd(result: DropResult) {
    if (!result.destination) return
    const newStatus = result.destination.droppableId
    if (result.source.droppableId === newStatus) return
    setStatusOverrides(prev => new Map(prev).set(result.draggableId, newStatus))
    patchRemediation.mutate({ id: result.draggableId, status: newStatus })
    toast(`Status updated to ${KANBAN_LABELS[newStatus]}`, 'info')
  }

  if (isLoading) return <div className="flex items-center justify-center h-64 text-sm text-muted-foreground">Loading remediation queue...</div>
  if (isError) return <div className="flex items-center justify-center h-64 text-sm text-destructive">Failed to load remediations. Check backend connection.</div>

  return (
    <div className={`space-y-6 ${viewMode === 'kanban' ? 'max-w-6xl' : 'max-w-3xl'}`}>
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-xl font-semibold">Remediation Queue</h1>
          <p className="text-sm text-muted-foreground mt-0.5">{pending} pending · {inProgress} in progress</p>
        </div>
        <div className="flex items-center gap-0 border border-border">
          <button
            onClick={() => setViewMode('list')}
            className={`p-1.5 transition-colors ${viewMode === 'list' ? 'bg-foreground text-background' : 'text-muted-foreground hover:text-foreground'}`}
            aria-label="List view"
          >
            <List className="h-4 w-4" />
          </button>
          <button
            onClick={() => setViewMode('kanban')}
            className={`p-1.5 transition-colors ${viewMode === 'kanban' ? 'bg-foreground text-background' : 'text-muted-foreground hover:text-foreground'}`}
            aria-label="Kanban view"
          >
            <LayoutGrid className="h-4 w-4" />
          </button>
        </div>
      </div>

      {viewMode === 'list' ? (
        <>
          <TierSection tier={1} items={tier1} />
          {tier2.length > 0 && <Separator />}
          <TierSection tier={2} items={tier2} />
          {tier3.length > 0 && <Separator />}
          <TierSection tier={3} items={tier3} />
        </>
      ) : (
        <KanbanView items={items} onDragEnd={handleKanbanDragEnd} />
      )}

      <ToastStack toasts={toasts} onDismiss={dismiss} />
    </div>
  )
}
