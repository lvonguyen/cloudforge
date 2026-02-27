import { useState } from 'react'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { Separator } from '@/components/ui/separator'
import { RemediationTierBadge } from '@/components/remediation/RemediationTierBadge'
import { CheckCircle2, Play, Eye, RotateCcw } from 'lucide-react'

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

const QUEUE: QueueItem[] = [
  { id: 'rem-001', finding_id: 'FIND-0421', title: 'Public S3 bucket — block public access', resource: 's3://data-pipeline-raw', provider: 'aws', tier: 1, handler: 'aws.s3.block_public', status: 'pending', dry_run_ok: true, created_at: '2026-02-26 08:30' },
  { id: 'rem-002', finding_id: 'FIND-0380', title: 'Security group allows 0.0.0.0/0 port 22', resource: 'sg-0abc1234', provider: 'aws', tier: 1, handler: 'aws.ec2.restrict_sg', status: 'pending', dry_run_ok: true, created_at: '2026-02-26 07:45' },
  { id: 'rem-003', finding_id: 'FIND-0315', title: 'RDS instance not encrypted', resource: 'payments-db-prod', provider: 'aws', tier: 2, handler: 'aws.rds.enable_encryption', status: 'pending', dry_run_ok: false, created_at: '2026-02-25 22:10' },
  { id: 'rem-004', finding_id: 'FIND-0290', title: 'GKE node pool using deprecated image', resource: 'gke-prod-pool-1', provider: 'gcp', tier: 2, handler: 'gcp.gke.upgrade_node_image', status: 'in_progress', dry_run_ok: true, created_at: '2026-02-25 18:00' },
  { id: 'rem-005', finding_id: 'FIND-0201', title: 'AKS cluster RBAC misconfiguration', resource: 'aks-prod-eastus', provider: 'azure', tier: 3, handler: 'azure.aks.fix_rbac', status: 'failed', dry_run_ok: null, created_at: '2026-02-25 14:20' },
]

const STATUS_COLORS: Record<string, string> = {
  pending: 'bg-gray-100 text-gray-700',
  in_progress: 'bg-blue-100 text-blue-700',
  completed: 'bg-green-100 text-green-700',
  failed: 'bg-red-100 text-red-700',
}

const PROVIDER_COLORS: Record<string, string> = {
  aws: 'bg-orange-100 text-orange-700',
  gcp: 'bg-green-100 text-green-700',
  azure: 'bg-blue-100 text-blue-700',
}

function TierSection({ tier, items }: { tier: 1 | 2 | 3; items: QueueItem[] }) {
  const descriptions: Record<number, string> = {
    1: 'Fully automated — no approval required',
    2: 'Semi-automated — dry-run first, then execute',
    3: 'Manual — Asana ticket created, human required',
  }
  const [executing, setExecuting] = useState<string | null>(null)

  function handleExecute(id: string) {
    setExecuting(id)
    setTimeout(() => setExecuting(null), 2000)
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
        <Card key={item.id} className={item.status === 'failed' ? 'border-red-200' : ''}>
          <CardContent className="p-4">
            <div className="flex items-start gap-4">
              <div className="flex-1 min-w-0">
                <div className="flex items-center gap-2 flex-wrap mb-1">
                  <span className={`text-[10px] font-medium px-2 py-0.5 rounded-full ${STATUS_COLORS[item.status] ?? 'bg-gray-100 text-gray-700'}`}>{item.status}</span>
                  <Badge variant="secondary" className={`text-[10px] ${PROVIDER_COLORS[item.provider] ?? ''}`}>{item.provider.toUpperCase()}</Badge>
                  {item.dry_run_ok === true && (
                    <span className="text-[10px] text-green-600 flex items-center gap-0.5"><CheckCircle2 className="h-3 w-3" />dry-run passed</span>
                  )}
                  {item.dry_run_ok === false && (
                    <span className="text-[10px] text-red-600">dry-run failed</span>
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
                    disabled={executing === item.id || item.dry_run_ok === null}
                    onClick={() => handleExecute(item.id)}
                  >
                    <Play className="h-3 w-3" />
                    {executing === item.id ? 'Running…' : 'Execute'}
                  </Button>
                )}
                {item.dry_run_ok === null && item.status === 'pending' && (
                  <Button size="sm" variant="outline" className="text-xs h-7 gap-1">
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
      ))}
    </div>
  )
}

export default function RemediationQueue() {
  const tier1 = QUEUE.filter(q => q.tier === 1)
  const tier2 = QUEUE.filter(q => q.tier === 2)
  const tier3 = QUEUE.filter(q => q.tier === 3)

  const pending = QUEUE.filter(q => q.status === 'pending').length
  const inProgress = QUEUE.filter(q => q.status === 'in_progress').length

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
