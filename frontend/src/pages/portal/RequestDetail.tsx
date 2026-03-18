import { brandEmail } from '@/lib/mock-data-utils'
import { useState } from 'react'
import { useParams, useNavigate } from 'react-router-dom'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { Separator } from '@/components/ui/separator'
import { ArrowLeft, CheckCircle2, XCircle, Clock, Loader2 } from 'lucide-react'
import { ProviderBadge } from '@/components/ui/ProviderBadge'
import { useToast } from '@/hooks/useToast'
import { ToastStack } from '@/components/ui/ToastStack'
import { useException } from '@/hooks/useExceptions'

interface ExceptionLifecycle {
  id: string
  resource: string
  type: string
  provider: string
  region: string
  app_id: string
  requestor: string
  team: string
  business_case: string
  status: 'PENDING' | 'APPROVED' | 'REJECTED' | 'EXPIRED'
  created: string
  updated: string
  expiry?: string
  approver_chain: Array<{ role: string; email: string; decision: string; decided_at?: string; comments?: string }>
  timeline: Array<{ event: string; actor: string; timestamp: string; note?: string }>
  compensating_controls: string[]
}

// Inline mock keyed by ID
const MOCK_DETAILS: Record<string, ExceptionLifecycle> = {
  'EXC-002': {
    id: 'EXC-002', resource: 'EC2 m5.24xlarge in us-east-1', type: 'OVERSIZED_INSTANCE', provider: 'aws', region: 'us-east-1',
    app_id: 'data-pipeline', requestor: brandEmail('user1'), team: 'Data Platform',
    business_case: 'ML training job requires high-memory instance for quarterly model refresh. Estimated 72h runtime. Cannot be split across smaller instances due to memory requirements.',
    status: 'PENDING', created: '2026-02-24 10:30', updated: '2026-02-24 10:30', expiry: undefined,
    approver_chain: [
      { role: 'operator', email: brandEmail('operator1'), decision: 'PENDING' },
      { role: 'admin', email: brandEmail('admin1'), decision: 'PENDING' },
    ],
    timeline: [
      { event: 'Request created', actor: brandEmail('user1'), timestamp: '2026-02-24 10:30', note: 'Policy check: OVERSIZED_INSTANCE' },
      { event: 'Notified approvers', actor: 'system', timestamp: '2026-02-24 10:31', note: 'Email sent to operator queue' },
    ],
    compensating_controls: ['Instance auto-terminates after 72h via Lambda', 'No PHI/PCI data processed', 'CloudTrail logging enabled'],
  },
  'EXC-006': {
    id: 'EXC-006', resource: 'S3 bucket in ap-southeast-1', type: 'UNAPPROVED_REGION', provider: 'aws', region: 'ap-southeast-1',
    app_id: 'customer-backups', requestor: brandEmail('user1'), team: 'Data Platform',
    business_case: 'Singapore customer data residency requirement — data must reside in ap-southeast-1 per DPA agreement signed 2025-12-15.',
    status: 'APPROVED', created: '2026-02-18 09:00', updated: '2026-02-19 11:42', expiry: '2026-05-19',
    approver_chain: [
      { role: 'operator', email: brandEmail('operator1'), decision: 'APPROVED', decided_at: '2026-02-18 14:00', comments: 'Confirmed DPA on file.' },
      { role: 'admin', email: brandEmail('admin1'), decision: 'APPROVED', decided_at: '2026-02-19 11:42', comments: 'Approved. Review at expiry.' },
    ],
    timeline: [
      { event: 'Request created', actor: brandEmail('user1'), timestamp: '2026-02-18 09:00' },
      { event: 'Approved by operator', actor: brandEmail('operator1'), timestamp: '2026-02-18 14:00', note: 'Confirmed DPA on file.' },
      { event: 'Approved by admin', actor: brandEmail('admin1'), timestamp: '2026-02-19 11:42', note: 'Approved. Review at expiry.' },
    ],
    compensating_controls: ['Encryption at rest with KMS', 'Bucket policy restricts to VPC endpoint', 'Versioning enabled', '90-day access review'],
  },
  'EXC-007': {
    id: 'EXC-007', resource: 'RDS db.r5.2xlarge prod', type: 'OVERSIZED_INSTANCE', provider: 'aws', region: 'us-east-1',
    app_id: 'analytics-platform', requestor: brandEmail('user2'), team: 'Analytics',
    business_case: 'Production analytics database requires db.r5.2xlarge to handle peak query load during end-of-quarter reporting. Downsize to db.r5.large caused query timeouts affecting SLA.',
    status: 'REJECTED', created: '2026-02-10 08:45', updated: '2026-02-11 14:20', expiry: undefined,
    approver_chain: [
      { role: 'operator', email: brandEmail('operator1'), decision: 'REJECTED', decided_at: '2026-02-11 14:20', comments: 'Rightsizing analysis shows db.r5.large sufficient outside peak windows. Use Aurora Auto Scaling instead.' },
    ],
    timeline: [
      { event: 'Request created', actor: brandEmail('user2'), timestamp: '2026-02-10 08:45', note: 'Policy check: OVERSIZED_INSTANCE' },
      { event: 'Notified approvers', actor: 'system', timestamp: '2026-02-10 08:46', note: 'Email sent to operator queue' },
      { event: 'Rejected by operator', actor: brandEmail('operator1'), timestamp: '2026-02-11 14:20', note: 'Rightsizing analysis shows db.r5.large sufficient outside peak windows.' },
    ],
    compensating_controls: ['CloudWatch alarms on CPU/connections', 'Read replica for reporting queries'],
  },
  'EXC-009': {
    id: 'EXC-009', resource: 'AKS private cluster eastus', type: 'RESTRICTED_SERVICE', provider: 'azure', region: 'eastus',
    app_id: 'k8s-platform', requestor: brandEmail('operator1'), team: 'Platform Engineering',
    business_case: 'Private AKS cluster required for PCI-DSS workload isolation. Public AKS endpoint cannot be used for cardholder data environment per compliance mandate.',
    status: 'APPROVED', created: '2026-01-15 11:00', updated: '2026-01-17 09:30', expiry: '2026-04-15',
    approver_chain: [
      { role: 'operator', email: brandEmail('operator2'), decision: 'APPROVED', decided_at: '2026-01-16 10:00', comments: 'PCI scope confirmed. Private cluster architecture reviewed.' },
      { role: 'admin', email: brandEmail('admin1'), decision: 'APPROVED', decided_at: '2026-01-17 09:30', comments: 'Approved for 90 days. Re-evaluate at expiry for permanent policy exception.' },
    ],
    timeline: [
      { event: 'Request created', actor: brandEmail('operator1'), timestamp: '2026-01-15 11:00', note: 'Policy check: RESTRICTED_SERVICE' },
      { event: 'Notified approvers', actor: 'system', timestamp: '2026-01-15 11:01', note: 'Email sent to operator queue' },
      { event: 'Approved by operator', actor: brandEmail('operator2'), timestamp: '2026-01-16 10:00', note: 'PCI scope confirmed. Private cluster architecture reviewed.' },
      { event: 'Approved by admin', actor: brandEmail('admin1'), timestamp: '2026-01-17 09:30', note: 'Approved for 90 days.' },
    ],
    compensating_controls: ['Private endpoint with no public API server', 'Azure Policy enforcing node pool taints', 'Network policy (Calico) between namespaces', 'Defender for Containers enabled'],
  },
  'EXC-011': {
    id: 'EXC-011', resource: 'GKE node pool us-central1-a', type: 'OVERSIZED_INSTANCE', provider: 'gcp', region: 'us-central1',
    app_id: 'ml-training', requestor: brandEmail('user1'), team: 'ML Platform',
    business_case: 'GPU node pool (n1-standard-96) required for distributed ML training. Exception granted for model training sprint Nov–Dec 2025.',
    status: 'EXPIRED', created: '2025-11-01 09:00', updated: '2026-01-01 00:00', expiry: '2026-01-01',
    approver_chain: [
      { role: 'operator', email: brandEmail('operator1'), decision: 'APPROVED', decided_at: '2025-11-02 10:15', comments: 'Approved for 60-day training sprint.' },
      { role: 'admin', email: brandEmail('admin1'), decision: 'APPROVED', decided_at: '2025-11-03 08:00', comments: 'Approved. Node pool must be deleted at expiry.' },
    ],
    timeline: [
      { event: 'Request created', actor: brandEmail('user1'), timestamp: '2025-11-01 09:00', note: 'Policy check: OVERSIZED_INSTANCE' },
      { event: 'Approved by operator', actor: brandEmail('operator1'), timestamp: '2025-11-02 10:15', note: 'Approved for 60-day training sprint.' },
      { event: 'Approved by admin', actor: brandEmail('admin1'), timestamp: '2025-11-03 08:00', note: 'Node pool must be deleted at expiry.' },
      { event: 'Exception expired', actor: 'system', timestamp: '2026-01-01 00:00', note: 'Automatic expiry — node pool decommissioned.' },
    ],
    compensating_controls: ['Node pool auto-deleted via Terraform TTL', 'No persistent storage attached', 'Workload Identity for GCS access only'],
  },
}

const DECISION_ICON: Record<string, typeof CheckCircle2> = {
  APPROVED: CheckCircle2,
  REJECTED: XCircle,
  PENDING: Clock,
}
const DECISION_COLOR: Record<string, string> = {
  APPROVED: 'text-green-600 dark:text-green-400',
  REJECTED: 'text-red-600 dark:text-red-400',
  PENDING: 'text-yellow-600 dark:text-yellow-400',
}
const STATUS_BADGE: Record<string, string> = {
  PENDING: 'bg-yellow-100 text-yellow-800 dark:bg-yellow-900/30 dark:text-yellow-300',
  APPROVED: 'bg-green-100 text-green-800 dark:bg-green-900/30 dark:text-green-300',
  REJECTED: 'bg-red-100 text-red-800 dark:bg-red-900/30 dark:text-red-300',
  EXPIRED: 'bg-gray-100 text-gray-600 dark:bg-gray-900/30 dark:text-gray-400',
}

export default function RequestDetail() {
  const { id } = useParams<{ id: string }>()
  const navigate = useNavigate()
  const { toasts, toast, dismiss } = useToast()
  const [withdrawn, setWithdrawn] = useState(false)
  const [withdrawing, setWithdrawing] = useState(false)
  const { data: apiException, isLoading } = useException(id ?? '')

  // Try API data first; fall back to inline mock for dev/offline
  const apiMapped = apiException ? {
    id: apiException.id,
    resource: apiException.resource_requested,
    type: apiException.request_type,
    provider: (apiException.metadata?.provider ?? 'aws'),
    region: (apiException.metadata?.region ?? ''),
    app_id: apiException.application_id,
    requestor: apiException.requestor_email,
    team: (apiException.metadata?.team ?? ''),
    business_case: apiException.business_case,
    status: apiException.status as ExceptionLifecycle['status'],
    created: apiException.created_at,
    updated: apiException.updated_at,
    expiry: apiException.expiration_date,
    approver_chain: (apiException.approver_chain ?? []).map(a => ({
      role: a.role, email: a.email, decision: a.decision,
      decided_at: a.decided_at, comments: a.comments,
    })),
    timeline: ((apiException as unknown as Record<string, unknown>).timeline as ExceptionLifecycle['timeline']) ?? [],
    compensating_controls: apiException.compensating_controls ?? [],
  } satisfies ExceptionLifecycle : undefined
  const exc = apiMapped ?? (id ? MOCK_DETAILS[id] : undefined)

  if (isLoading) {
    return (
      <div className="flex items-center gap-2 text-sm text-muted-foreground p-4">
        <Loader2 className="h-4 w-4 animate-spin" />Loading request…
      </div>
    )
  }

  if (!exc) {
    return (
      <div className="space-y-4 max-w-3xl">
        <Button variant="ghost" size="sm" className="gap-1.5 -ml-2" onClick={() => navigate('/portal/requests')}>
          <ArrowLeft className="h-4 w-4" />My Requests
        </Button>
        <div className="text-sm text-muted-foreground">Request not found. <Button variant="link" className="text-xs p-0 h-auto" onClick={() => navigate('/portal/requests')}>Back to list</Button></div>
      </div>
    )
  }

  return (
    <div className="space-y-6 max-w-3xl pb-10">
      <Button variant="ghost" size="sm" className="gap-1.5 -ml-2" onClick={() => navigate('/portal/requests')}>
        <ArrowLeft className="h-4 w-4" />My Requests
      </Button>

      {/* Header */}
      <div className="flex items-start justify-between gap-4">
        <div>
          <div className="flex items-center gap-2 mb-1">
            <h1 className="text-xl font-semibold">{exc.id}</h1>
            <span className={`text-[10px] font-medium px-2 py-0.5 rounded-full ${STATUS_BADGE[exc.status] ?? 'bg-gray-100 text-gray-600 dark:bg-gray-900/30 dark:text-gray-400'}`}>{exc.status}</span>
            <Badge variant="outline" className="text-[10px]">{exc.type}</Badge>
          </div>
          <p className="text-sm text-muted-foreground">{exc.resource}</p>
        </div>
        {exc.status === 'PENDING' && !withdrawn && (
          <Button
            size="sm"
            variant="outline"
            className="text-xs shrink-0"
            disabled={withdrawing}
            onClick={() => {
              setWithdrawing(true)
              setTimeout(() => {
                setWithdrawing(false)
                setWithdrawn(true)
                toast('Request withdrawn')
                setTimeout(() => navigate('/portal/requests'), 1500)
              }, 800)
            }}
          >
            {withdrawing ? 'Withdrawing\u2026' : 'Withdraw'}
          </Button>
        )}
      </div>

      <Separator />

      {/* Request details */}
      <Card>
        <CardHeader className="pb-2">
          <CardTitle className="text-xs font-medium uppercase tracking-wide text-muted-foreground">Request Details</CardTitle>
        </CardHeader>
        <CardContent className="grid grid-cols-2 gap-x-6 gap-y-3 text-sm">
          <div><p className="text-[10px] text-muted-foreground uppercase tracking-wide">Application</p><p className="text-sm font-medium mt-0.5">{exc.app_id}</p></div>
          <div><p className="text-[10px] text-muted-foreground uppercase tracking-wide">Team</p><p className="text-sm font-medium mt-0.5">{exc.team}</p></div>
          <div><p className="text-[10px] text-muted-foreground uppercase tracking-wide">Provider / Region</p><div className="flex items-center gap-1.5 mt-0.5"><ProviderBadge provider={exc.provider} /><span className="text-sm font-medium">· {exc.region}</span></div></div>
          <div><p className="text-[10px] text-muted-foreground uppercase tracking-wide">Requestor</p><p className="text-sm font-medium mt-0.5">{exc.requestor}</p></div>
          <div className="col-span-2">
            <p className="text-[10px] text-muted-foreground uppercase tracking-wide">Business Case</p>
            <p className="text-sm mt-0.5 leading-relaxed">{exc.business_case}</p>
          </div>
          {exc.expiry && (
            <div><p className="text-[10px] text-muted-foreground uppercase tracking-wide">Expiry</p><p className="text-sm font-medium mt-0.5">{exc.expiry}</p></div>
          )}
        </CardContent>
      </Card>

      {/* Compensating controls */}
      {exc.compensating_controls.length > 0 && (
        <Card>
          <CardHeader className="pb-2">
            <CardTitle className="text-xs font-medium uppercase tracking-wide text-muted-foreground">Compensating Controls</CardTitle>
          </CardHeader>
          <CardContent>
            <ul className="space-y-1.5">
              {exc.compensating_controls.map((ctrl, i) => (
                <li key={i} className="flex items-start gap-2 text-xs">
                  <CheckCircle2 className="h-3.5 w-3.5 text-green-600 dark:text-green-400 mt-0.5 shrink-0" />
                  <span>{ctrl}</span>
                </li>
              ))}
            </ul>
          </CardContent>
        </Card>
      )}

      {/* Approver chain */}
      <Card>
        <CardHeader className="pb-2">
          <CardTitle className="text-xs font-medium uppercase tracking-wide text-muted-foreground">Approval Chain</CardTitle>
        </CardHeader>
        <CardContent className="space-y-3">
          {exc.approver_chain.map((appr, i) => {
            const Icon = DECISION_ICON[appr.decision] ?? Clock
            return (
              <div key={i} className="flex items-start gap-3">
                <Icon className={`h-4 w-4 mt-0.5 shrink-0 ${DECISION_COLOR[appr.decision] ?? 'text-muted-foreground'}`} />
                <div>
                  <p className="text-xs font-medium">{appr.email} <span className="text-muted-foreground font-normal">({appr.role})</span></p>
                  <p className="text-[10px] text-muted-foreground">{appr.decision}{appr.decided_at ? ` · ${appr.decided_at}` : ''}</p>
                  {appr.comments && <p className="text-xs mt-0.5 italic text-muted-foreground">"{appr.comments}"</p>}
                </div>
              </div>
            )
          })}
        </CardContent>
      </Card>

      {/* Timeline */}
      {exc.timeline.length > 0 && (
      <Card>
        <CardHeader className="pb-2">
          <CardTitle className="text-xs font-medium uppercase tracking-wide text-muted-foreground">Timeline</CardTitle>
        </CardHeader>
        <CardContent className="space-y-4">
          {exc.timeline.map((evt, i) => (
            <div key={i} className="flex items-start gap-3">
              <div className="relative">
                <div className="h-2 w-2 rounded-full bg-muted-foreground mt-1.5" />
                {i < exc.timeline.length - 1 && <div className="absolute left-0.5 top-3 h-full w-px bg-border" />}
              </div>
              <div className="pb-2">
                <p className="text-xs font-medium">{evt.event}</p>
                <p className="text-[10px] text-muted-foreground">{evt.actor} · {evt.timestamp}</p>
                {evt.note && <p className="text-[10px] text-muted-foreground italic mt-0.5">{evt.note}</p>}
              </div>
            </div>
          ))}
        </CardContent>
      </Card>
      )}

      <ToastStack toasts={toasts} onDismiss={dismiss} />
    </div>
  )
}
