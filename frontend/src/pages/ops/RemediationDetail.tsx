import { useParams, useNavigate, Link } from 'react-router-dom'
import { useRemediation } from '@/hooks/useRemediations'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { Separator } from '@/components/ui/separator'
import { RemediationTierBadge } from '@/components/remediation/RemediationTierBadge'
import { ArrowLeft, CheckCircle2, ExternalLink, AlertTriangle, Clock } from 'lucide-react'

const STATUS_COLORS: Record<string, string> = {
  pending: 'bg-gray-100 text-gray-700 dark:bg-gray-900/30 dark:text-gray-300',
  in_progress: 'bg-blue-100 text-blue-700 dark:bg-blue-900/30 dark:text-blue-300',
  completed: 'bg-green-100 text-green-700 dark:bg-green-900/30 dark:text-green-300',
  failed: 'bg-red-100 text-red-700 dark:bg-red-900/30 dark:text-red-300',
  skipped: 'bg-yellow-100 text-yellow-700 dark:bg-yellow-900/30 dark:text-yellow-300',
}

const TIER_DESCRIPTIONS: Record<number, string> = {
  1: 'Fully automated — no approval required',
  2: 'Semi-automated — dry-run first, then execute',
  3: 'Manual — Asana ticket created, human required',
}

function formatTimestamp(ts: string | undefined): string {
  if (!ts) return '--'
  return new Date(ts).toLocaleString()
}

function computeDuration(startedAt: string | undefined, completedAt: string | undefined): string {
  if (!startedAt || !completedAt) return '--'
  const ms = new Date(completedAt).getTime() - new Date(startedAt).getTime()
  if (ms < 0) return '--'
  if (ms < 60_000) return `${Math.round(ms / 1000)}s`
  return `${Math.round(ms / 60_000)}m ${Math.round((ms % 60_000) / 1000)}s`
}

export default function RemediationDetail() {
  const { id } = useParams<{ id: string }>()
  const navigate = useNavigate()
  const { data: rem, isLoading } = useRemediation(id ?? '')

  if (isLoading) {
    return <div className="text-sm text-muted-foreground p-6">Loading remediation…</div>
  }
  if (!rem) {
    return (
      <div className="space-y-4 max-w-4xl">
        <Button variant="ghost" size="sm" className="gap-1.5 -ml-2" onClick={() => navigate('/ops/remediation')}>
          <ArrowLeft className="h-4 w-4" />Remediation Queue
        </Button>
        <div className="text-sm text-muted-foreground">Remediation not found.</div>
      </div>
    )
  }

  const title = rem.result?.message ?? `${rem.domain} — ${rem.handler}`

  return (
    <div className="space-y-6 max-w-4xl pb-10">
      <Button variant="ghost" size="sm" className="gap-1.5 -ml-2" onClick={() => navigate('/ops/remediation')}>
        <ArrowLeft className="h-4 w-4" />Remediation Queue
      </Button>

      {/* Header */}
      <div className="flex items-start gap-4">
        <div className="flex-1 min-w-0">
          <div className="flex items-center gap-2 flex-wrap mb-2">
            <span className={`text-[10px] font-medium px-2 py-0.5 rounded-full ${STATUS_COLORS[rem.status] ?? STATUS_COLORS.pending}`}>
              {rem.status}
            </span>
            <RemediationTierBadge tier={rem.tier} />
            <Badge variant="outline" className="text-[10px]">{rem.domain}</Badge>
          </div>
          <h1 className="text-xl font-semibold leading-snug">{title}</h1>
          <p className="text-sm text-muted-foreground mt-1 font-mono">{rem.handler}</p>
        </div>
      </div>

      <Separator />

      {/* Impacted Resource */}
      <Card>
        <CardHeader className="pb-2">
          <CardTitle className="text-xs font-medium uppercase tracking-wide text-muted-foreground">
            Impacted Resource
          </CardTitle>
        </CardHeader>
        <CardContent className="space-y-3">
          <div className="grid grid-cols-2 md:grid-cols-3 gap-4">
            <div>
              <p className="text-[10px] text-muted-foreground uppercase tracking-wide">Resource ID</p>
              <code className="text-sm font-mono mt-0.5 block truncate">{rem.result?.resource_id ?? '--'}</code>
            </div>
            <div>
              <p className="text-[10px] text-muted-foreground uppercase tracking-wide">Domain</p>
              <p className="text-sm font-medium mt-0.5">{rem.domain}</p>
            </div>
            <div>
              <p className="text-[10px] text-muted-foreground uppercase tracking-wide">Finding</p>
              <Link
                to={`/ops/findings/${rem.finding_id}`}
                className="text-sm font-mono text-blue-600 dark:text-blue-400 hover:underline mt-0.5 block truncate"
              >
                {rem.finding_id}
              </Link>
            </div>
          </div>
          <div>
            <p className="text-[10px] text-muted-foreground uppercase tracking-wide">Tier</p>
            <div className="flex items-center gap-2 mt-0.5">
              <RemediationTierBadge tier={rem.tier} />
              <span className="text-xs text-muted-foreground">{TIER_DESCRIPTIONS[rem.tier] ?? ''}</span>
            </div>
          </div>
        </CardContent>
      </Card>

      {/* Execution Timeline */}
      <Card>
        <CardHeader className="pb-2">
          <CardTitle className="text-xs font-medium uppercase tracking-wide text-muted-foreground">
            <div className="flex items-center gap-1.5"><Clock className="h-3.5 w-3.5" />Execution Timeline</div>
          </CardTitle>
        </CardHeader>
        <CardContent>
          <div className="relative ml-3 border-l-2 border-muted pl-4 space-y-4">
            {[
              { label: 'Created', ts: rem.created_at },
              { label: 'Started', ts: rem.result?.started_at },
              { label: 'Completed', ts: rem.result?.completed_at },
              { label: 'Validated', ts: rem.validation?.validated_at },
            ].map(({ label, ts }) => (
              <div key={label} className="relative">
                <div className="absolute -left-[21px] h-3 w-3 rounded-full bg-muted border-2 border-border" />
                <p className="text-[10px] text-muted-foreground uppercase tracking-wide">{label}</p>
                <p className="text-sm font-medium">{formatTimestamp(ts)}</p>
              </div>
            ))}
          </div>
          {rem.result?.started_at && rem.result?.completed_at && (
            <p className="text-xs text-muted-foreground mt-4">
              Duration: <strong>{computeDuration(rem.result.started_at, rem.result.completed_at)}</strong>
              {rem.result.duration && rem.result.duration !== computeDuration(rem.result.started_at, rem.result.completed_at) && (
                <span className="ml-1">({rem.result.duration})</span>
              )}
            </p>
          )}
        </CardContent>
      </Card>

      {/* Actions Performed */}
      {rem.result?.actions && rem.result.actions.length > 0 && (
        <Card>
          <CardHeader className="pb-2">
            <CardTitle className="text-xs font-medium uppercase tracking-wide text-muted-foreground">
              Actions Performed
            </CardTitle>
          </CardHeader>
          <CardContent>
            <ol className="space-y-2">
              {rem.result.actions.map((action, i) => (
                <li key={action} className="flex items-center gap-2 text-sm">
                  <CheckCircle2 className="h-3.5 w-3.5 text-green-500 shrink-0" />
                  <span className="text-xs text-muted-foreground font-mono tabular-nums w-5 shrink-0">{i + 1}.</span>
                  <code className="font-mono text-xs">{action}</code>
                </li>
              ))}
            </ol>
          </CardContent>
        </Card>
      )}

      {/* Validation */}
      {rem.validation && (
        <Card>
          <CardHeader className="pb-2">
            <CardTitle className="text-xs font-medium uppercase tracking-wide text-muted-foreground">
              Validation
            </CardTitle>
          </CardHeader>
          <CardContent className="space-y-3">
            <div className="flex items-center gap-2">
              <Badge
                variant="outline"
                className={
                  rem.validation.is_compliant
                    ? 'bg-green-100 text-green-800 border-green-300 dark:bg-green-900/30 dark:text-green-300 dark:border-green-800'
                    : 'bg-red-100 text-red-800 border-red-300 dark:bg-red-900/30 dark:text-red-300 dark:border-red-800'
                }
              >
                {rem.validation.is_compliant ? 'Compliant' : 'Non-Compliant'}
              </Badge>
            </div>
            <p className="text-sm">{rem.validation.message}</p>
            {rem.validation.evidence && rem.validation.evidence.length > 0 && (
              <ul className="space-y-1">
                {rem.validation.evidence.map(e => (
                  <li key={e} className="flex items-center gap-1.5 text-xs text-muted-foreground">
                    <span className="text-muted-foreground">-</span>
                    <code className="font-mono">{e}</code>
                  </li>
                ))}
              </ul>
            )}
            {rem.validation.recheck_after && (
              <p className="text-xs text-muted-foreground">
                Recheck after: <strong>{formatTimestamp(rem.validation.recheck_after)}</strong>
              </p>
            )}
          </CardContent>
        </Card>
      )}

      {/* Error callout (failed status only) */}
      {rem.status === 'failed' && rem.result?.error && (
        <Card className="border-red-200 dark:border-red-800">
          <CardContent className="p-4 flex items-start gap-3">
            <AlertTriangle className="h-4 w-4 text-red-500 shrink-0 mt-0.5" />
            <div className="flex-1 min-w-0 space-y-2">
              <p className="text-sm font-medium text-red-700 dark:text-red-400">Execution Failed</p>
              <code className="text-xs font-mono block text-red-600 dark:text-red-300">{rem.result.error}</code>
              <Button size="sm" variant="outline" className="text-xs h-7 border-red-300 dark:border-red-700">
                Retry
              </Button>
            </div>
          </CardContent>
        </Card>
      )}

      {/* Links */}
      <div className="flex items-center gap-3 flex-wrap">
        <Button variant="outline" size="sm" className="text-xs gap-1.5" asChild>
          <Link to={`/ops/findings/${rem.finding_id}`}>
            <ExternalLink className="h-3.5 w-3.5" />View Finding
          </Link>
        </Button>
        {rem.tier === 3 && rem.asana_task_url && (
          <Button variant="outline" size="sm" className="text-xs gap-1.5" asChild>
            <a href={rem.asana_task_url} target="_blank" rel="noreferrer">
              <ExternalLink className="h-3.5 w-3.5" />Open Asana Task
            </a>
          </Button>
        )}
      </div>
    </div>
  )
}
