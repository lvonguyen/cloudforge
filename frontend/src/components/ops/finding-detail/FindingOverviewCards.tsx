import type { ReactNode } from 'react'
import { Crosshair, ShieldAlert, Ticket, UserRoundCheck, Wrench } from 'lucide-react'
import { Badge } from '@/components/ui/badge'
import { Card, CardContent } from '@/components/ui/card'
import type { Finding } from '@/types/compliance'
import type { AttackPath } from '@/types/attack-path'
import type { RemediationRecord } from '@/types/remediation'
import type { FindingGraphEvidence } from '@/lib/finding-graph-evidence'
import { formatDate, formatWorkflowStatus, getFindingSlaState } from './helpers'

function MetricCard({
  icon: Icon,
  label,
  value,
  detail,
  accentClass = 'text-foreground',
  badge,
}: {
  icon: typeof Crosshair
  label: string
  value: string
  detail: string
  accentClass?: string
  badge?: ReactNode
}) {
  return (
    <Card className="border-border/80 bg-card/95">
      <CardContent className="flex items-start gap-3 p-4">
        <div className="flex h-10 w-10 shrink-0 items-center justify-center rounded-2xl border border-border bg-muted/40">
          <Icon className={`h-4 w-4 ${accentClass}`} />
        </div>
        <div className="min-w-0 space-y-1">
          <div className="flex items-center gap-2">
            <p className="text-[10px] font-semibold uppercase tracking-[0.22em] text-muted-foreground">{label}</p>
            {badge}
          </div>
          <p className={`text-sm font-semibold ${accentClass}`}>{value}</p>
          <p className="text-xs text-muted-foreground">{detail}</p>
        </div>
      </CardContent>
    </Card>
  )
}

export function FindingOverviewCards({
  finding,
  relatedPaths,
  remediation,
  hasTicket,
  graphEvidence,
}: {
  finding: Finding
  relatedPaths: AttackPath[]
  remediation?: RemediationRecord
  hasTicket: boolean
  graphEvidence?: FindingGraphEvidence
}) {
  const sla = getFindingSlaState(finding)
  const hasNearbyGraphEvidence = relatedPaths.length === 0 && (graphEvidence?.nearbyNodeCount ?? 0) > 0
  const remediationSummary = finding.remediation_steps?.length
    ? `${finding.remediation_steps.length} ordered step${finding.remediation_steps.length === 1 ? '' : 's'}`
    : finding.auto_remediatable
      ? 'Auto-remediation available'
      : 'Manual playbook required'

  return (
    <div className="grid grid-cols-1 gap-4 md:grid-cols-2 xl:grid-cols-4">
      <MetricCard
        icon={Crosshair}
        label="Attack Paths"
        value={relatedPaths.length > 0
          ? `${relatedPaths.length} linked path${relatedPaths.length === 1 ? '' : 's'}`
          : hasNearbyGraphEvidence ? graphEvidence!.label : 'No linked paths'}
        detail={relatedPaths.length > 0
          ? 'This finding participates in the current blast-radius view.'
          : hasNearbyGraphEvidence ? graphEvidence!.detail : 'No attack-path evidence currently maps to this resource.'}
        accentClass={relatedPaths.length > 0 || hasNearbyGraphEvidence ? 'text-amber-600 dark:text-amber-400' : 'text-muted-foreground'}
      />
      <MetricCard
        icon={ShieldAlert}
        label="SLA"
        value={sla.label}
        detail={`${sla.detail} · due ${formatDate(finding.due_date)}`}
        accentClass={sla.textClass}
        badge={<Badge variant="outline" className={`text-[10px] ${sla.badgeClass}`}>{sla.label}</Badge>}
      />
      <MetricCard
        icon={UserRoundCheck}
        label="Ownership"
        value={finding.assignee?.user_name ?? 'Unassigned'}
        detail={finding.assignee ? `${finding.assignee.team} · ${formatWorkflowStatus(finding.workflow_status)}` : 'Awaiting triage ownership assignment'}
        accentClass={finding.assignee ? 'text-slate-900 dark:text-slate-100' : 'text-muted-foreground'}
      />
      <MetricCard
        icon={hasTicket ? Ticket : Wrench}
        label="Remediation"
        value={hasTicket ? 'External ticket linked' : remediation ? formatWorkflowStatus(remediation.status) : remediationSummary}
        detail={hasTicket ? 'Follow the linked ticket for execution details.' : remediation ? `${remediation.handler} · Tier ${remediation.tier}` : remediationSummary}
        accentClass={hasTicket ? 'text-blue-600 dark:text-blue-400' : finding.auto_remediatable ? 'text-emerald-600 dark:text-emerald-400' : 'text-slate-900 dark:text-slate-100'}
      />
    </div>
  )
}
