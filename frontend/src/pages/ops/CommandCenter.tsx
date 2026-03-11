import { useState } from 'react'
import { Link, useNavigate } from 'react-router-dom'
import { useExceptions, useApproveException } from '@/hooks/useExceptions'
import { useFindings } from '@/hooks/useFindings'
import { useCostAnomalies } from '@/hooks/useCosts'
import { useActionCooldown } from '@/hooks/useActionCooldown'
import { ExceptionCard } from '@/components/grc/ExceptionCard'
import { FindingCard } from '@/components/findings/FindingCard'
import { AnomalyAlertCard } from '@/components/finops/AnomalyAlertCard'
import { Button } from '@/components/ui/button'
import { Badge } from '@/components/ui/badge'
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select'
import { Separator } from '@/components/ui/separator'
import type { Approver, ExceptionRequest } from '@/types/grc'

const MOCK_EXCEPTIONS: ExceptionRequest[] = [
  {
    id: 'EXC-001',
    application_id: 'payments-api',
    requestor_email: 'dev1@contoso.dev',
    request_type: 'UNAPPROVED_REGION',
    policy_violated: 'REGION-001',
    resource_requested: 'RDS in ap-southeast-3',
    business_case: 'APAC latency requirements for payment processing',
    status: 'PENDING',
    approver_chain: [],
    created_at: '2026-02-25T10:00:00Z',
    updated_at: '2026-02-25T10:00:00Z',
  },
  {
    id: 'EXC-002',
    application_id: 'data-pipeline',
    requestor_email: 'dev2@contoso.dev',
    request_type: 'OVERSIZED_INSTANCE',
    policy_violated: 'COST-002',
    resource_requested: 'EC2 m5.24xlarge in us-east-1',
    business_case: 'Large-scale ETL batch processing',
    status: 'PENDING',
    approver_chain: [],
    created_at: '2026-02-24T14:30:00Z',
    updated_at: '2026-02-24T14:30:00Z',
  },
  {
    id: 'EXC-003',
    application_id: 'ml-training',
    requestor_email: 'ml-team@contoso.dev',
    request_type: 'RESTRICTED_SERVICE',
    policy_violated: 'SVC-003',
    resource_requested: 'Bedrock us-gov-west-1',
    business_case: 'FedRAMP-compliant model inference',
    status: 'APPROVED',
    approver_chain: [{ email: 'admin1@contoso.dev', role: 'admin', decision: 'APPROVED', decided_at: '2026-02-23T16:00:00Z' }],
    created_at: '2026-02-23T09:00:00Z',
    updated_at: '2026-02-23T16:00:00Z',
  },
  {
    id: 'EXC-004',
    application_id: 'auth-service',
    requestor_email: 'secops@contoso.dev',
    request_type: 'NETWORK_EXPOSURE',
    policy_violated: 'NET-001',
    resource_requested: 'SG sg-0abc1234 port 22',
    business_case: 'Temporary SSH access for incident response',
    status: 'PENDING',
    approver_chain: [],
    created_at: '2026-02-22T11:00:00Z',
    updated_at: '2026-02-22T11:00:00Z',
  },
]

const SEVERITY_TABS = ['ALL', 'CRITICAL', 'HIGH', 'MEDIUM', 'LOW'] as const
type SeverityTab = (typeof SEVERITY_TABS)[number]

const SEVERITY_COLORS: Record<string, string> = {
  CRITICAL: 'bg-red-100 text-red-800 dark:bg-red-900/30 dark:text-red-300',
  HIGH: 'bg-orange-100 text-orange-800 dark:bg-orange-900/30 dark:text-orange-300',
  MEDIUM: 'bg-yellow-100 text-yellow-800 dark:bg-yellow-900/30 dark:text-yellow-300',
  LOW: 'bg-blue-100 text-blue-800 dark:bg-blue-900/30 dark:text-blue-300',
}

export default function CommandCenter() {
  const navigate = useNavigate()
  const [severityFilter, setSeverityFilter] = useState<SeverityTab>('ALL')
  const [providerFilter, setProviderFilter] = useState<string>('ALL')

  const exceptions = useExceptions()
  const approveException = useApproveException()
  const approveCooldown = useActionCooldown({ key: 'approve-exception', cooldownMs: 3000 })
  const [approvedIds, setApprovedIds] = useState<Set<string>>(new Set())

  const findingFilters = {
    severity: severityFilter !== 'ALL' ? severityFilter : undefined,
    provider: providerFilter !== 'ALL' ? providerFilter.toLowerCase() : undefined,
  }
  const findings = useFindings(findingFilters)
  const anomalies = useCostAnomalies()

  // Count findings per severity from unfiltered data for badge display
  const allFindings = useFindings()
  const severityCounts = (allFindings.data ?? []).reduce<Record<string, number>>((acc, f) => {
    acc[f.severity] = (acc[f.severity] ?? 0) + 1
    return acc
  }, {})

  function handleApprove(id: string) {
    if (!approveCooldown.canFire) return
    const approver: Approver = {
      email: 'operator1@contoso.dev',
      role: 'ops',
      decision: 'APPROVED',
    }
    approveCooldown.fire()
    approveException.mutate({ id, approver }, {
      onSuccess: () => setApprovedIds(prev => new Set(prev).add(id)),
    })
  }

  return (
    <div className="space-y-8 p-6">
      {/* Page heading */}
      <div>
        <h1 className="text-xl font-semibold">Command Center</h1>
        <p className="text-sm text-muted-foreground mt-0.5">Operations overview — Feb 2026</p>
      </div>

      {/* Section 1: Exception Queue */}
      <section>
        <div className="flex items-center justify-between mb-4">
          <h2 className="text-sm font-semibold tracking-widest uppercase text-muted-foreground">
            Exception Queue
          </h2>
          <Link to="/ops/remediation" className="text-xs text-primary hover:underline">
            View All →
          </Link>
        </div>

        {exceptions.isLoading && (
          <p className="text-sm text-muted-foreground">Loading exceptions…</p>
        )}
        {exceptions.data && exceptions.data.length === 0 && !exceptions.isError && (
          <p className="text-sm text-muted-foreground">No pending exceptions.</p>
        )}
        {((exceptions.data && exceptions.data.length > 0) || exceptions.isError) && (
          <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-3 gap-3">
            {(exceptions.data ?? MOCK_EXCEPTIONS).map(exc => (
              <div key={exc.id} className="relative cursor-pointer" onClick={() => navigate(`/portal/requests/${exc.id}`)}>
                <ExceptionCard exception={exc} />
                {exc.status === 'PENDING' && (
                  <div className="px-4 pb-3">
                    {approvedIds.has(exc.id) ? (
                      <Badge variant="outline" className="w-full justify-center text-xs py-1 bg-green-100 text-green-800 border-green-300 dark:bg-green-900/30 dark:text-green-300 dark:border-green-700">
                        Approved
                      </Badge>
                    ) : (
                      <Button
                        size="sm"
                        variant="outline"
                        className="w-full text-xs"
                        disabled={approveException.isPending || !approveCooldown.canFire}
                        onClick={(e) => { e.stopPropagation(); handleApprove(exc.id) }}
                      >
                        {!approveCooldown.canFire
                          ? `Wait ${Math.ceil(approveCooldown.remainingMs / 1000)}s`
                          : 'Approve'}
                      </Button>
                    )}
                  </div>
                )}
              </div>
            ))}
          </div>
        )}
      </section>

      <Separator />

      {/* Section 2: Security Findings */}
      <section>
        <div className="flex flex-wrap items-center justify-between gap-3 mb-4">
          <div className="flex items-center gap-3">
            <h2 className="text-sm font-semibold tracking-widest uppercase text-muted-foreground">
              Findings by Severity
            </h2>
            {(['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'] as const).map(sev => (
              <Badge
                key={sev}
                variant="outline"
                className={`text-[10px] px-1.5 py-0 ${SEVERITY_COLORS[sev] ?? ''}`}
              >
                {sev[0]}{sev.slice(1).toLowerCase()} {severityCounts[sev] ?? 0}
              </Badge>
            ))}
          </div>

          <Select value={providerFilter} onValueChange={setProviderFilter}>
            <SelectTrigger className="h-7 w-28 text-xs">
              <SelectValue placeholder="Provider" />
            </SelectTrigger>
            <SelectContent>
              <SelectItem value="ALL">All Providers</SelectItem>
              <SelectItem value="AWS">AWS</SelectItem>
              <SelectItem value="Azure">Azure</SelectItem>
              <SelectItem value="GCP">GCP</SelectItem>
            </SelectContent>
          </Select>
        </div>

        {/* Severity filter tabs */}
        <div className="flex gap-1 mb-4">
          {SEVERITY_TABS.map(tab => (
            <button
              key={tab}
              onClick={() => setSeverityFilter(tab)}
              className={`px-3 py-1 text-xs rounded-none font-medium transition-colors ${
                severityFilter === tab
                  ? 'bg-foreground text-background'
                  : 'bg-muted text-muted-foreground hover:bg-muted/80'
              }`}
            >
              {tab}
            </button>
          ))}
        </div>

        {findings.isLoading && (
          <p className="text-sm text-muted-foreground">Loading findings…</p>
        )}
        {findings.data && findings.data.length === 0 && (
          <p className="text-sm text-muted-foreground">No findings match the selected filters.</p>
        )}
        {findings.data && findings.data.length > 0 && (
          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-3">
            {findings.data.map(finding => (
              <FindingCard key={finding.id} finding={finding} onClick={() => navigate(`/ops/findings/${finding.id}`)} />
            ))}
          </div>
        )}
      </section>

      <Separator />

      {/* Section 3: Anomaly Alerts */}
      <section>
        <div className="flex items-center gap-2 mb-4">
          <h2 className="text-sm font-semibold tracking-widest uppercase text-muted-foreground">
            Anomaly Alerts
          </h2>
          {anomalies.data && (
            <Badge variant="outline" className="text-[10px] px-1.5 py-0 bg-orange-100 text-orange-800 border-orange-300 dark:bg-orange-900/30 dark:text-orange-300 dark:border-orange-700">
              {anomalies.data.length} active
            </Badge>
          )}
        </div>

        {anomalies.isLoading && (
          <p className="text-sm text-muted-foreground">Loading alerts…</p>
        )}
        {anomalies.data && anomalies.data.length === 0 && (
          <p className="text-sm text-muted-foreground">No active anomalies.</p>
        )}
        {anomalies.data && anomalies.data.length > 0 && (
          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-3">
            {anomalies.data.map(anomaly => (
              <AnomalyAlertCard key={anomaly.id} anomaly={anomaly} />
            ))}
          </div>
        )}
      </section>
    </div>
  )
}
