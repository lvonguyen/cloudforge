import { useState, useMemo } from 'react'
import { useExceptions } from '@/hooks/useExceptions'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
import { Badge } from '@/components/ui/badge'
import {
  Table, TableBody, TableCell, TableHead, TableHeader, TableRow,
} from '@/components/ui/table'
import { EXCEPTION_STATUS_COLORS as STATUS_COLORS } from '@/lib/severity'
import { ListChecks, Filter } from 'lucide-react'
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

export default function Exceptions() {
  const { data: exceptions } = useExceptions()
  const [statusFilter, setStatusFilter] = useState<StatusFilter>('ALL')

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
                  <TableRow key={exc.id}>
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
    </div>
  )
}
