import { useState, useMemo, useEffect } from 'react'
import { useExceptions, useApproveException, useRejectException } from '@/hooks/useExceptions'
import { useToast } from '@/hooks/useToast'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import {
  Table, TableBody, TableCell, TableHead, TableHeader, TableRow,
} from '@/components/ui/table'
import { EXCEPTION_STATUS_COLORS as STATUS_COLORS } from '@/lib/severity'
import { ListChecks, Filter, X, ChevronRight } from 'lucide-react'
import type { ExceptionRequest, Approver } from '@/types/grc'

const STATUS_FILTERS = ['ALL', 'PENDING', 'APPROVED', 'REJECTED', 'EXPIRED'] as const
type StatusFilter = (typeof STATUS_FILTERS)[number]

function approver(email: string): Approver {
  return { email, role: 'team-lead', decision: 'PENDING' }
}

const FALLBACK_EXCEPTIONS: ExceptionRequest[] = [
  { id: 'EXC-001', application_id: 'payments-api', requestor_email: 'alice@contoso.dev', request_type: 'UNAPPROVED_REGION', policy_violated: 'region-restriction', resource_requested: 'RDS in ap-southeast-3', business_case: 'APAC expansion requires local DB replica for <10ms latency', status: 'PENDING', approver_chain: [approver('bob@contoso.dev')], created_at: '2026-02-25T10:30:00Z', updated_at: '2026-02-25T10:30:00Z' },
  { id: 'EXC-002', application_id: 'data-pipeline', requestor_email: 'carol@contoso.dev', request_type: 'OVERSIZED_INSTANCE', policy_violated: 'instance-size-limit', resource_requested: 'EC2 m5.24xlarge', business_case: 'ML training workload requires 384GB RAM for model fitting', status: 'PENDING', approver_chain: [approver('dave@contoso.dev')], created_at: '2026-02-24T14:15:00Z', updated_at: '2026-02-24T14:15:00Z' },
  { id: 'EXC-003', application_id: 'ml-training', requestor_email: 'eve@contoso.dev', request_type: 'RESTRICTED_SERVICE', policy_violated: 'service-allowlist', resource_requested: 'Bedrock us-gov-west-1', business_case: 'FedRAMP compliance testing requires GovCloud inference endpoint', status: 'APPROVED', approver_chain: [approver('frank@contoso.dev')], created_at: '2026-02-23T09:00:00Z', updated_at: '2026-02-24T11:00:00Z' },
  { id: 'EXC-004', application_id: 'auth-service', requestor_email: 'grace@contoso.dev', request_type: 'NETWORK_EXPOSURE', policy_violated: 'no-public-ingress', resource_requested: 'SG sg-0abc1234 port 22', business_case: 'Temporary SSH access for incident response', status: 'PENDING', approver_chain: [approver('heidi@contoso.dev')], created_at: '2026-02-22T16:45:00Z', updated_at: '2026-02-22T16:45:00Z' },
  { id: 'EXC-005', application_id: 'analytics-dash', requestor_email: 'ivan@contoso.dev', request_type: 'DATA_RESIDENCY', policy_violated: 'data-residency-eu', resource_requested: 'S3 bucket in us-east-1', business_case: 'Cross-region replication for DR — EU primary, US failover', status: 'REJECTED', approver_chain: [approver('judy@contoso.dev')], created_at: '2026-02-20T08:30:00Z', updated_at: '2026-02-21T09:00:00Z' },
  { id: 'EXC-006', application_id: 'crm-platform', requestor_email: 'karl@contoso.dev', request_type: 'OTHER', policy_violated: 'encryption-at-rest', resource_requested: 'DynamoDB without KMS', business_case: 'Legacy integration — vendor SDK does not support CMK encryption', status: 'EXPIRED', approver_chain: [approver('liam@contoso.dev')], created_at: '2026-02-15T12:00:00Z', updated_at: '2026-03-01T00:00:00Z' },
]

function formatDate(iso: string): string {
  try {
    return new Date(iso).toLocaleDateString('en-US', { month: 'short', day: 'numeric', year: 'numeric' })
  } catch {
    return iso
  }
}

function ExceptionDetailDrawer({ exc, onClose, onApprove, onReject }: {
  exc: ExceptionRequest
  onClose: () => void
  onApprove: () => void
  onReject: () => void
}) {
  const [apiActionsOpen, setApiActionsOpen] = useState(false)

  useEffect(() => {
    const h = (e: KeyboardEvent) => { if (e.key === 'Escape') onClose() }
    document.addEventListener('keydown', h)
    return () => document.removeEventListener('keydown', h)
  }, [onClose])

  return (
    <div className="fixed inset-0 z-50 flex justify-end" onClick={onClose}>
      <div className="absolute inset-0 bg-black/40 backdrop-blur-sm" />
      <div
        role="dialog"
        aria-modal="true"
        aria-label="Exception details"
        className="relative w-full max-w-md bg-background border-l border-border h-full overflow-y-auto shadow-xl"
        onClick={e => e.stopPropagation()}
      >
        <div className="flex items-center justify-between p-4 border-b border-border">
          <h2 className="text-sm font-semibold">Exception {exc.id}</h2>
          <button onClick={onClose} className="p-1 hover:bg-muted rounded" aria-label="Close">
            <X className="h-4 w-4" />
          </button>
        </div>

        <div className="p-4 space-y-5">
          {/* Key fields */}
          <div className="space-y-3">
            <div>
              <p className="text-[10px] uppercase tracking-wide text-muted-foreground">Application</p>
              <p className="text-sm font-medium">{exc.application_id}</p>
            </div>
            <div>
              <p className="text-[10px] uppercase tracking-wide text-muted-foreground">Type</p>
              <Badge variant="outline" className="text-[10px]">{exc.request_type}</Badge>
            </div>
            <div>
              <p className="text-[10px] uppercase tracking-wide text-muted-foreground">Resource</p>
              <p className="text-sm">{exc.resource_requested}</p>
            </div>
            <div>
              <p className="text-[10px] uppercase tracking-wide text-muted-foreground">Requestor</p>
              <p className="text-sm">{exc.requestor_email}</p>
            </div>
            <div>
              <p className="text-[10px] uppercase tracking-wide text-muted-foreground">Status</p>
              <span className={`text-[10px] font-medium px-2 py-0.5 rounded-none ${STATUS_COLORS[exc.status] ?? 'bg-gray-100 text-gray-700 dark:bg-gray-900/30 dark:text-gray-300'}`}>
                {exc.status}
              </span>
            </div>
            <div className="flex gap-6">
              <div>
                <p className="text-[10px] uppercase tracking-wide text-muted-foreground">Created</p>
                <p className="text-xs">{formatDate(exc.created_at)}</p>
              </div>
              <div>
                <p className="text-[10px] uppercase tracking-wide text-muted-foreground">Updated</p>
                <p className="text-xs">{formatDate(exc.updated_at)}</p>
              </div>
            </div>
          </div>

          {/* Business case */}
          <div>
            <p className="text-[10px] uppercase tracking-wide text-muted-foreground mb-1">Business Case</p>
            <p className="text-sm leading-relaxed bg-muted/30 p-3 border border-border">{exc.business_case}</p>
          </div>

          {/* Approver chain */}
          {(exc.approver_chain?.length ?? 0) > 0 && (
            <div>
              <p className="text-[10px] uppercase tracking-wide text-muted-foreground mb-2">Approver Chain</p>
              <div className="space-y-2">
                {exc.approver_chain.map((a, i) => (
                  <div key={i} className="flex items-center justify-between bg-muted/20 p-2 border border-border">
                    <div>
                      <p className="text-xs font-medium">{a.email}</p>
                      <p className="text-[10px] text-muted-foreground">{a.role}</p>
                    </div>
                    <span className={`text-[10px] font-medium px-2 py-0.5 rounded-none ${STATUS_COLORS[a.decision] ?? 'bg-gray-100 text-gray-700 dark:bg-gray-900/30 dark:text-gray-300'}`}>
                      {a.decision}
                    </span>
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* API Actions (collapsible) */}
          <div className="space-y-2">
            <button
              onClick={() => setApiActionsOpen(!apiActionsOpen)}
              className="flex items-center gap-1.5 w-full text-left"
            >
              <ChevronRight className={`h-3 w-3 transition-transform ${apiActionsOpen ? 'rotate-90' : ''}`} />
              <span className="text-[10px] uppercase tracking-wide text-muted-foreground">API Actions</span>
            </button>

            {apiActionsOpen && (
              <div className="space-y-3">
                {/* Approve */}
                <div className="bg-muted/20 border border-border p-3 space-y-2">
                  <div className="flex items-center gap-2">
                    <span className="text-[9px] font-mono font-bold px-1.5 py-0.5 bg-emerald-900/50 text-emerald-300">POST</span>
                    <span className="text-[10px] font-mono text-muted-foreground">/api/v1/exceptions/{'{'}id{'}'}/approve</span>
                  </div>
                  <div>
                    <p className="text-[9px] uppercase tracking-wide text-muted-foreground mb-1">Request Body</p>
                    <pre className="text-[10px] font-mono text-gray-400 bg-black/20 p-2 border border-border overflow-x-auto">
{JSON.stringify({ approver: "current_user", decision: "APPROVED", comments: "string?" }, null, 2)}
                    </pre>
                  </div>
                  <p className="text-[9px] text-muted-foreground">Response: <span className="text-emerald-400">200</span> → ExceptionRequest</p>
                </div>

                {/* Reject */}
                <div className="bg-muted/20 border border-border p-3 space-y-2">
                  <div className="flex items-center gap-2">
                    <span className="text-[9px] font-mono font-bold px-1.5 py-0.5 bg-emerald-900/50 text-emerald-300">POST</span>
                    <span className="text-[10px] font-mono text-muted-foreground">/api/v1/exceptions/{'{'}id{'}'}/reject</span>
                  </div>
                  <div>
                    <p className="text-[9px] uppercase tracking-wide text-muted-foreground mb-1">Request Body</p>
                    <pre className="text-[10px] font-mono text-gray-400 bg-black/20 p-2 border border-border overflow-x-auto">
{JSON.stringify({ approver: "current_user", decision: "REJECTED", reason: "string", comments: "string?" }, null, 2)}
                    </pre>
                  </div>
                  <p className="text-[9px] text-muted-foreground">Response: <span className="text-emerald-400">200</span> → ExceptionRequest</p>
                </div>

                {/* Provision */}
                <div className="bg-muted/20 border border-border p-3 space-y-2">
                  <div className="flex items-center gap-2">
                    <span className="text-[9px] font-mono font-bold px-1.5 py-0.5 bg-emerald-900/50 text-emerald-300">POST</span>
                    <span className="text-[10px] font-mono text-muted-foreground">/api/v1/exceptions/{'{'}id{'}'}/provision</span>
                  </div>
                  <div>
                    <p className="text-[9px] uppercase tracking-wide text-muted-foreground mb-1">Request Body</p>
                    <pre className="text-[10px] font-mono text-gray-400 bg-black/20 p-2 border border-border overflow-x-auto">
{JSON.stringify({ approved_by: "string", resource_config: {}, ttl_hours: 72, compensating_controls: ["string"] }, null, 2)}
                    </pre>
                  </div>
                  <p className="text-[9px] text-muted-foreground">Response: <span className="text-emerald-400">202</span> → ProvisioningTask</p>
                </div>
              </div>
            )}
          </div>

          {/* Action buttons */}
          {exc.status === 'PENDING' && (
            <div className="flex gap-2 pt-2">
              <Button size="sm" className="flex-1 text-xs" onClick={onApprove}>
                Approve
              </Button>
              <Button size="sm" variant="outline" className="flex-1 text-xs" onClick={onReject}>
                Reject
              </Button>
            </div>
          )}
        </div>
      </div>
    </div>
  )
}

export default function Exceptions() {
  const { data: exceptions } = useExceptions()
  const [statusFilter, setStatusFilter] = useState<StatusFilter>('ALL')
  const [selectedExc, setSelectedExc] = useState<ExceptionRequest | null>(null)
  const approveMutation = useApproveException()
  const rejectMutation = useRejectException()
  const { toasts, toast, dismiss } = useToast()

  const handleApprove = () => {
    if (!selectedExc) return
    approveMutation.mutate(
      { id: selectedExc.id, approver: { email: 'current_user@contoso.dev', role: 'SECURITY_LEAD', decision: 'APPROVED' } },
      {
        onSuccess: () => { toast('Exception approved', 'success'); setSelectedExc(null) },
        onError: () => { toast('Failed to approve exception', 'error') },
      },
    )
  }

  const handleReject = () => {
    if (!selectedExc) return
    rejectMutation.mutate(
      { id: selectedExc.id, approver: { email: 'current_user@contoso.dev', role: 'SECURITY_LEAD', decision: 'REJECTED' } },
      {
        onSuccess: () => { toast('Exception rejected', 'success'); setSelectedExc(null) },
        onError: () => { toast('Failed to reject exception', 'error') },
      },
    )
  }

  const items = exceptions && exceptions.length > 0 ? exceptions : FALLBACK_EXCEPTIONS
  const usingFallback = !exceptions || exceptions.length === 0

  const filtered = useMemo(() => {
    if (statusFilter === 'ALL') return items
    return items.filter(e => e.status === statusFilter)
  }, [items, statusFilter])

  const counts = useMemo(() => ({
    ALL: items.length,
    PENDING: items.filter(e => e.status === 'PENDING').length,
    APPROVED: items.filter(e => e.status === 'APPROVED').length,
    REJECTED: items.filter(e => e.status === 'REJECTED').length,
    EXPIRED: items.filter(e => e.status === 'EXPIRED').length,
  }), [items])

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-xl font-semibold">Exception Requests</h1>
        <p className="text-sm text-muted-foreground mt-0.5">
          Policy exception requests requiring review and approval
          {usingFallback && <span className="text-[10px] ml-2 text-muted-foreground/60">(demo data)</span>}
        </p>
      </div>

      {/* Status filter tabs */}
      <div className="flex items-center gap-1">
        <Filter className="h-3.5 w-3.5 text-muted-foreground mr-1" />
        {STATUS_FILTERS.map(sf => (
          <button
            key={sf}
            onClick={() => setStatusFilter(sf)}
            className={`text-xs px-3 py-1 transition-colors ${
              statusFilter === sf
                ? 'bg-primary text-primary-foreground'
                : 'bg-muted/50 text-muted-foreground hover:bg-muted'
            }`}
          >
            {sf} ({counts[sf]})
          </button>
        ))}
      </div>

      <Card>
        <CardHeader className="pb-2">
          <div className="flex items-center gap-2">
            <ListChecks className="h-4 w-4 text-muted-foreground" />
            <CardTitle className="text-sm font-medium">{filtered.length} exception{filtered.length !== 1 ? 's' : ''}</CardTitle>
          </div>
        </CardHeader>
        <CardContent className="p-0">
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead className="text-xs pl-4">ID</TableHead>
                <TableHead className="text-xs">Application</TableHead>
                <TableHead className="text-xs">Type</TableHead>
                <TableHead className="text-xs">Resource</TableHead>
                <TableHead className="text-xs">Requestor</TableHead>
                <TableHead className="text-xs">Status</TableHead>
                <TableHead className="text-xs">Created</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {filtered.length === 0 ? (
                <TableRow>
                  <TableCell colSpan={7} className="text-center text-xs text-muted-foreground py-8">
                    No exceptions match this filter.
                  </TableCell>
                </TableRow>
              ) : (
                filtered.map(exc => (
                  <TableRow key={exc.id} className="cursor-pointer hover:bg-muted/30" onClick={() => setSelectedExc(exc)}>
                    <TableCell className="text-xs font-mono pl-4">{exc.id}</TableCell>
                    <TableCell className="text-xs font-medium">{exc.application_id}</TableCell>
                    <TableCell><Badge variant="outline" className="text-[10px]">{exc.request_type}</Badge></TableCell>
                    <TableCell className="text-xs text-muted-foreground max-w-[200px] truncate">{exc.resource_requested}</TableCell>
                    <TableCell className="text-xs text-muted-foreground">{exc.requestor_email}</TableCell>
                    <TableCell>
                      <span className={`text-[10px] font-medium px-2 py-0.5 rounded-none ${STATUS_COLORS[exc.status] ?? 'bg-gray-100 text-gray-700 dark:bg-gray-900/30 dark:text-gray-300'}`}>
                        {exc.status}
                      </span>
                    </TableCell>
                    <TableCell className="text-xs text-muted-foreground">{formatDate(exc.created_at)}</TableCell>
                  </TableRow>
                ))
              )}
            </TableBody>
          </Table>
        </CardContent>
      </Card>

      {selectedExc && (
        <ExceptionDetailDrawer
          exc={selectedExc}
          onClose={() => setSelectedExc(null)}
          onApprove={handleApprove}
          onReject={handleReject}
        />
      )}

      {/* Toasts */}
      {toasts.length > 0 && (
        <div className="fixed bottom-4 right-4 z-[60] space-y-2">
          {toasts.map(t => (
            <div
              key={t.id}
              className={`px-4 py-2 text-xs shadow-lg border ${
                t.variant === 'success' ? 'bg-emerald-950 border-emerald-800 text-emerald-200' :
                t.variant === 'error' ? 'bg-red-950 border-red-800 text-red-200' :
                'bg-blue-950 border-blue-800 text-blue-200'
              }`}
              onClick={() => dismiss(t.id)}
            >
              {t.message}
            </div>
          ))}
        </div>
      )}
    </div>
  )
}
