import { Card, CardContent } from '@/components/ui/card'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { Separator } from '@/components/ui/separator'
import { RemediationTierBadge } from '@/components/remediation/RemediationTierBadge'
import { CheckCircle2, Play, Eye, RotateCcw } from 'lucide-react'
import { useRemediations } from '@/hooks/useRemediations'
import { useTracePanel } from '@/lib/trace-panel-context'
import { useActionCooldown } from '@/hooks/useActionCooldown'
import type { RemediationRecord } from '@/types/remediation'

interface QueueItem {
  id: string
  finding_id: string
  title: string
  resource: string
  provider: string
  tier: 1 | 2 | 3
  handler: string
  status: 'pending' | 'in_progress' | 'completed' | 'failed'
  dry_run_ok: boolean | null
  created_at: string
}

function toQueueItem(r: RemediationRecord): QueueItem {
  const dryRunOk = r.result
    ? r.result.success
    : r.status === 'pending' ? null : null
  return {
    id: r.id,
    finding_id: r.finding_id,
    title: r.result?.message ?? `${r.domain} — ${r.handler}`,
    resource: r.result?.resource_id ?? r.finding_id,
    provider: r.domain,
    tier: (r.tier >= 1 && r.tier <= 3 ? r.tier : 2) as 1 | 2 | 3,
    handler: r.handler,
    status: r.status === 'skipped' ? 'failed' : r.status,
    dry_run_ok: dryRunOk,
    created_at: r.created_at,
  }
}

const STATUS_COLORS: Record<string, string> = {
  pending: 'bg-gray-100 text-gray-700 dark:bg-gray-900/30 dark:text-gray-300',
  in_progress: 'bg-blue-100 text-blue-700 dark:bg-blue-900/30 dark:text-blue-300',
  completed: 'bg-green-100 text-green-700 dark:bg-green-900/30 dark:text-green-300',
  failed: 'bg-red-100 text-red-700 dark:bg-red-900/30 dark:text-red-300',
}

const PROVIDER_COLORS: Record<string, string> = {
  aws: 'bg-orange-100 text-orange-700 dark:bg-orange-900/30 dark:text-orange-300',
  gcp: 'bg-green-100 text-green-700 dark:bg-green-900/30 dark:text-green-300',
  azure: 'bg-blue-100 text-blue-700 dark:bg-blue-900/30 dark:text-blue-300',
}

function QueueItemCard({ item }: { item: QueueItem }) {
  const { openStreaming, openDryRun } = useTracePanel()
  const executeCooldown = useActionCooldown({ key: `execute-${item.id}`, cooldownMs: 30_000 })
  const dryRunCooldown = useActionCooldown({ key: `dryrun-${item.id}`, cooldownMs: 15_000 })

  function handleExecute() {
    if (!executeCooldown.canFire) return
    openStreaming('Executing: ' + item.handler)
    executeCooldown.fire()
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
  }

  return (
    <Card className={item.status === 'failed' ? 'border-red-200 dark:border-red-800' : ''}>
      <CardContent className="p-4">
        <div className="flex items-start gap-4">
          <div className="flex-1 min-w-0">
            <div className="flex items-center gap-2 flex-wrap mb-1">
              <span className={`text-[10px] font-medium px-2 py-0.5 rounded-full ${STATUS_COLORS[item.status] ?? 'bg-gray-100 text-gray-700 dark:bg-gray-900/30 dark:text-gray-300'}`}>{item.status}</span>
              <Badge variant="secondary" className={`text-[10px] ${PROVIDER_COLORS[item.provider] ?? ''}`}>{item.provider.toUpperCase()}</Badge>
              {item.dry_run_ok === true && (
                <span className="text-[10px] text-green-600 dark:text-green-400 flex items-center gap-0.5"><CheckCircle2 className="h-3 w-3" />dry-run passed</span>
              )}
              {item.dry_run_ok === false && (
                <span className="text-[10px] text-red-600 dark:text-red-400">dry-run failed</span>
              )}
            </div>
            <p className="text-sm font-medium leading-snug">{item.title}</p>
            <div className="flex items-center gap-3 mt-1">
              <p className="text-xs text-muted-foreground font-mono">{item.resource}</p>
              <p className="text-[10px] text-muted-foreground">Handler: <code>{item.handler}</code></p>
            </div>
          </div>
          <div className="flex gap-2 shrink-0">
            {item.status === 'pending' && item.dry_run_ok !== false && (
              <Button
                size="sm"
                className="text-xs h-7 gap-1"
                disabled={!executeCooldown.canFire || item.dry_run_ok === null}
                onClick={handleExecute}
              >
                <Play className="h-3 w-3" />
                {!executeCooldown.canFire ? 'Running\u2026' : 'Execute'}
              </Button>
            )}
            {item.dry_run_ok === null && item.status === 'pending' && (
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
              <Button size="sm" variant="outline" className="text-xs h-7 gap-1">
                <RotateCcw className="h-3 w-3" />Retry
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

export default function RemediationQueue() {
  const { data: records = [] } = useRemediations()
  const queue = records.map(toQueueItem)

  const tier1 = queue.filter(q => q.tier === 1)
  const tier2 = queue.filter(q => q.tier === 2)
  const tier3 = queue.filter(q => q.tier === 3)

  const pending = queue.filter(q => q.status === 'pending').length
  const inProgress = queue.filter(q => q.status === 'in_progress').length

  return (
    <div className="space-y-6 max-w-3xl">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-xl font-semibold">Remediation Queue</h1>
          <p className="text-sm text-muted-foreground mt-0.5">{pending} pending · {inProgress} in progress</p>
        </div>
      </div>

      <TierSection tier={1} items={tier1} />
      {tier2.length > 0 && <Separator />}
      <TierSection tier={2} items={tier2} />
      {tier3.length > 0 && <Separator />}
      <TierSection tier={3} items={tier3} />
    </div>
  )
}
