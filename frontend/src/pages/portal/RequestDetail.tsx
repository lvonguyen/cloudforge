import { useParams, useNavigate } from 'react-router-dom'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { Separator } from '@/components/ui/separator'
import { ArrowLeft, CheckCircle2, XCircle, Clock } from 'lucide-react'

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
    app_id: 'data-pipeline', requestor: 'falhassan@cloudforge.dev', team: 'Data Platform',
    business_case: 'ML training job requires high-memory instance for quarterly model refresh. Estimated 72h runtime. Cannot be split across smaller instances due to memory requirements.',
    status: 'PENDING', created: '2026-02-24 10:30', updated: '2026-02-24 10:30', expiry: undefined,
    approver_chain: [
      { role: 'operator', email: 'priya@cloudforge.dev', decision: 'PENDING' },
      { role: 'admin', email: 'liem@cloudforge.dev', decision: 'PENDING' },
    ],
    timeline: [
      { event: 'Request created', actor: 'falhassan@cloudforge.dev', timestamp: '2026-02-24 10:30', note: 'Policy check: OVERSIZED_INSTANCE' },
      { event: 'Notified approvers', actor: 'system', timestamp: '2026-02-24 10:31', note: 'Email sent to operator queue' },
    ],
    compensating_controls: ['Instance auto-terminates after 72h via Lambda', 'No PHI/PCI data processed', 'CloudTrail logging enabled'],
  },
  'EXC-006': {
    id: 'EXC-006', resource: 'S3 bucket in ap-southeast-1', type: 'UNAPPROVED_REGION', provider: 'aws', region: 'ap-southeast-1',
    app_id: 'customer-backups', requestor: 'falhassan@cloudforge.dev', team: 'Data Platform',
    business_case: 'Singapore customer data residency requirement — data must reside in ap-southeast-1 per DPA agreement signed 2025-12-15.',
    status: 'APPROVED', created: '2026-02-18 09:00', updated: '2026-02-19 11:42', expiry: '2026-05-19',
    approver_chain: [
      { role: 'operator', email: 'priya@cloudforge.dev', decision: 'APPROVED', decided_at: '2026-02-18 14:00', comments: 'Confirmed DPA on file.' },
      { role: 'admin', email: 'liem@cloudforge.dev', decision: 'APPROVED', decided_at: '2026-02-19 11:42', comments: 'Approved. Review at expiry.' },
    ],
    timeline: [
      { event: 'Request created', actor: 'falhassan@cloudforge.dev', timestamp: '2026-02-18 09:00' },
      { event: 'Approved by operator', actor: 'priya@cloudforge.dev', timestamp: '2026-02-18 14:00', note: 'Confirmed DPA on file.' },
      { event: 'Approved by admin', actor: 'liem@cloudforge.dev', timestamp: '2026-02-19 11:42', note: 'Approved. Review at expiry.' },
    ],
    compensating_controls: ['Encryption at rest with KMS', 'Bucket policy restricts to VPC endpoint', 'Versioning enabled', '90-day access review'],
  },
}

const DECISION_ICON: Record<string, typeof CheckCircle2> = {
  APPROVED: CheckCircle2,
  REJECTED: XCircle,
  PENDING: Clock,
}
const DECISION_COLOR: Record<string, string> = {
  APPROVED: 'text-green-600',
  REJECTED: 'text-red-600',
  PENDING: 'text-yellow-600',
}
const STATUS_BADGE: Record<string, string> = {
  PENDING: 'bg-yellow-100 text-yellow-800',
  APPROVED: 'bg-green-100 text-green-800',
  REJECTED: 'bg-red-100 text-red-800',
  EXPIRED: 'bg-gray-100 text-gray-600',
}

export default function RequestDetail() {
  const { id } = useParams<{ id: string }>()
  const navigate = useNavigate()

  const exc = id ? MOCK_DETAILS[id] : undefined

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
            <span className={`text-[10px] font-medium px-2 py-0.5 rounded-full ${STATUS_BADGE[exc.status] ?? 'bg-gray-100 text-gray-600'}`}>{exc.status}</span>
            <Badge variant="outline" className="text-[10px]">{exc.type}</Badge>
          </div>
          <p className="text-sm text-muted-foreground">{exc.resource}</p>
        </div>
        {exc.status === 'PENDING' && (
          <Button size="sm" variant="outline" className="text-xs shrink-0">Withdraw</Button>
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
          <div><p className="text-[10px] text-muted-foreground uppercase tracking-wide">Provider / Region</p><p className="text-sm font-medium mt-0.5">{exc.provider.toUpperCase()} · {exc.region}</p></div>
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
                  <CheckCircle2 className="h-3.5 w-3.5 text-green-600 mt-0.5 shrink-0" />
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
    </div>
  )
}
