import { brandEmail } from '@/lib/mock-data-utils'
import { useState, useMemo } from 'react'
import { useAuth } from '@/lib/auth'
import { useParams, useNavigate } from 'react-router-dom'
import { useFinding, useFindingEnrichment } from '@/hooks/useFindings'
import { useAttackPaths } from '@/hooks/useAttackPaths'
import { AttackPathMiniGraph } from '@/components/attack-path/AttackPathMiniGraph'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { Separator } from '@/components/ui/separator'
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs'
import { ArrowLeft, ExternalLink, CheckCircle2, AlertTriangle, Brain, Crosshair, Building2, Zap, Globe, Flame, Server, ChevronRight, Clock, MessageSquare, Search, Wrench, XCircle, Ticket as TicketIcon } from 'lucide-react'
import { SeverityBadge } from '@/components/findings/SeverityBadge'
import { ProviderBadge } from '@/components/ui/ProviderBadge'
import { useTracePanel } from '@/lib/trace-panel-context'
import { useActionCooldown } from '@/hooks/useActionCooldown'
import { useCreateException } from '@/hooks/useExceptions'
import { useComments, useAddComment } from '@/hooks/useComments'
import { useFindingTicket, useRemediateFinding } from '@/hooks/useIntegrations'
import { RemediationSheet } from '@/components/remediation/RemediationSheet'
import { IntegrationViewport } from '@/components/remediation/IntegrationViewport'
import { useToast } from '@/hooks/useToast'
import { ToastStack } from '@/components/ui/ToastStack'
import { FindingOverviewCards } from '@/components/ops/finding-detail/FindingOverviewCards'
import { FindingComplianceList } from '@/components/ops/finding-detail/FindingComplianceList'
import { FindingRemediationPlan } from '@/components/ops/finding-detail/FindingRemediationPlan'
import { FindingAttackPathWorkspace } from '@/components/ops/finding-detail/FindingAttackPathWorkspace'
import { FindingSecurityGraphWorkspace } from '@/components/ops/finding-detail/FindingSecurityGraphWorkspace'
import { formatDate, formatWorkflowStatus } from '@/components/ops/finding-detail/helpers'
import { buildTraceTimeline } from '@/lib/trace-helpers'

interface FindingDetailProps {
  mode?: 'page' | 'inline'
  findingId?: string
  onClose?: () => void
}

export default function FindingDetail({ mode = 'page', findingId: propId, onClose }: FindingDetailProps) {
  const params = useParams<{ id: string }>()
  const navigate = useNavigate()
  const id = mode === 'inline' ? propId : params.id
  const { user } = useAuth()
  const { data: finding, isLoading } = useFinding(id ?? '')
  const { data: enrichment } = useFindingEnrichment(id ?? '')
  const { openTimeline } = useTracePanel()
  const remediateCooldown = useActionCooldown({ key: `remediate-${id ?? ''}`, cooldownMs: 10_000 })
  const suppressCooldown = useActionCooldown({ key: `suppress-${id ?? ''}`, cooldownMs: 15_000 })
  const createException = useCreateException()
  const { toasts, toast, dismiss } = useToast()
  const [suppressed, setSuppressed] = useState(false)
  const [activeTab, setActiveTab] = useState('overview')
  const [investigationView, setInvestigationView] = useState<'attack-path' | 'security-graph'>('attack-path')
  const [commentText, setCommentText] = useState('')
  const { data: comments = [] } = useComments(id ?? '')
  const addComment = useAddComment(id ?? '')
  const { data: ticket } = useFindingTicket(id ?? '')
  const createTicket = useRemediateFinding()
  const [sheetOpen, setSheetOpen] = useState(false)

  // Defer attack path fetch until Investigation tab is active (perf: avoids
  // 50-item fetch on every FindingDetail mount when user only views Overview)
  const [attackPathsRequested, setAttackPathsRequested] = useState(false)
  const attackPathsEnabled = attackPathsRequested || activeTab === 'investigation'
  const { data: attackPathsData } = useAttackPaths(1, 50, { enabled: attackPathsEnabled })
  const relatedPaths = useMemo(() => {
    if (!attackPathsData?.data || !finding) return []
    return attackPathsData.data.filter(p =>
      p.finding_ids.includes(finding.id) ||
      p.nodes.some(n => n.resource_id === finding.resource_id),
    )
  }, [attackPathsData, finding])
  const investigationEnrichment = useMemo(() => {
    if (!enrichment) return undefined
    return {
      root_cause: enrichment.root_cause,
      impact: enrichment.impact,
      remediation: enrichment.remediation,
      related_controls: enrichment.related_controls,
      threat_intel: enrichment.threat_intel,
      enriched_at: enrichment.enriched_at,
    }
  }, [enrichment])
  const openInvestigationTimeline = () => {
    if (!finding) return

    const correlatedTargets = Array.from(
      new Set(
        relatedPaths
          .map((path) => path.target.resource_name)
          .filter(Boolean),
      ),
    ).slice(0, 3)
    const relatedControls = Array.from(
      new Set(investigationEnrichment?.related_controls ?? []),
    ).slice(0, 4)
    const retrievalCount = Math.max(relatedPaths.length, relatedControls.length, 1)
    const topScores = [0.98, 0.94, 0.9].slice(0, Math.min(retrievalCount, 3))

    openTimeline(
      `Timeline: ${finding.title}`,
      buildTraceTimeline([
        {
          id: 'finding-investigator',
          name: `agent:FindingInvestigator:${finding.id}`,
          type: 'agent',
          durationMs: 900,
          attributes: {
            finding_id: finding.id,
            severity: finding.severity,
            workflow_status: finding.workflow_status,
            resource: finding.resource_name,
          },
        },
        {
          id: 'finding-context',
          parentSpanId: 'finding-investigator',
          name: 'retrieval:finding-context',
          type: 'retrieval',
          durationMs: 560,
          attributes: {
            finding_id: finding.id,
            related_path_count: relatedPaths.length,
            related_control_count: relatedControls.length,
          },
          data: {
            retrieval: {
              vector_store: 'security-graph-index',
              query: `${finding.title} ${finding.resource_name}`.trim(),
              num_results: retrievalCount,
              top_scores: topScores,
              filter_applied: true,
            },
          },
        },
        {
          id: 'finding-correlation',
          parentSpanId: 'finding-investigator',
          name: 'chain:graph-correlation',
          type: 'chain',
          durationMs: 640,
          attributes: {
            primary_target: correlatedTargets[0] ?? finding.resource_name,
            correlated_targets: correlatedTargets,
            ticket_linked: Boolean(ticket),
            enrichment_present: Boolean(investigationEnrichment),
          },
        },
        {
          id: 'finding-brief',
          parentSpanId: 'finding-investigator',
          name: 'llm:claude-sonnet-4-6:containment-brief',
          type: 'llm',
          durationMs: 840,
          attributes: {
            model: 'claude-sonnet-4-6',
            purpose: 'containment-brief',
          },
          data: {
            llm: {
              model: 'claude-sonnet-4-6',
              provider: 'anthropic',
              prompt_tokens: 1180,
              completion_tokens: 260,
              total_tokens: 1440,
              temperature: 0.1,
              max_tokens: 1024,
              prompt_hash: `sha256:${finding.id}:containment-brief`,
              finish_reason: 'stop',
            },
          },
        },
        {
          id: 'finding-policy',
          parentSpanId: 'finding-investigator',
          name: 'policy:remediation-readiness',
          type: 'policy',
          durationMs: 420,
          status: finding.auto_remediatable ? 'completed' : 'blocked',
          attributes: {
            auto_remediatable: finding.auto_remediatable,
            related_controls: relatedControls,
            ticket_linked: Boolean(ticket),
          },
          events: [
            {
              timestamp: new Date().toISOString(),
              name: finding.auto_remediatable ? 'policy.allow' : 'policy.review',
              attributes: {
                reason: finding.auto_remediatable
                  ? 'Auto-remediation path available for this finding.'
                  : 'Manual review required before remediation can be executed.',
              },
            },
          ],
        },
      ]),
    )
  }

  const openInvestigationView = (view: 'attack-path' | 'security-graph') => {
    setActiveTab('investigation')
    setInvestigationView(view)
    if (!attackPathsRequested) setAttackPathsRequested(true)
  }

  if (isLoading) {
    return (
      <div className="text-sm text-muted-foreground p-6">
        {mode === 'inline' && onClose && (
          <div className="flex justify-end mb-2">
            <Button variant="ghost" size="icon" className="h-6 w-6" onClick={onClose}>
              <XCircle className="h-4 w-4" />
            </Button>
          </div>
        )}
        Loading finding…
      </div>
    )
  }
  if (!finding) {
    return (
      <div className="space-y-4 max-w-3xl p-4">
        {mode === 'page' && (
          <Button variant="ghost" size="sm" className="gap-1.5 -ml-2" onClick={() => navigate('/ops/findings')}>
            <ArrowLeft className="h-4 w-4" />All Findings
          </Button>
        )}
        {mode === 'inline' && onClose && (
          <div className="flex justify-end">
            <Button variant="ghost" size="icon" className="h-6 w-6" onClick={onClose}>
              <XCircle className="h-4 w-4" />
            </Button>
          </div>
        )}
        <div className="text-sm text-muted-foreground">Finding not found.</div>
      </div>
    )
  }

  const Wrapper = mode === 'inline' ? 'aside' : 'div'
  const wrapperClassName = mode === 'inline'
    ? 'flex flex-col h-full overflow-y-auto p-4 space-y-4'
    : 'space-y-6 max-w-4xl pb-10'

  return (
    <Wrapper className={wrapperClassName}>
      {mode === 'page' && (
        <Button variant="ghost" size="sm" className="gap-1.5 -ml-2" onClick={() => navigate('/ops/findings')}>
          <ArrowLeft className="h-4 w-4" />All Findings
        </Button>
      )}
      {mode === 'inline' && onClose && (
        <div className="flex items-center justify-between">
          <span className="text-xs font-medium text-muted-foreground uppercase tracking-wide">Finding Detail</span>
          <Button variant="ghost" size="icon" className="h-6 w-6" onClick={onClose}>
            <XCircle className="h-4 w-4" />
          </Button>
        </div>
      )}

      {/* Header */}
      <div className="flex items-start gap-4">
        <div className="flex-1 min-w-0">
          <div className="flex items-center gap-2 flex-wrap mb-2">
            <SeverityBadge severity={finding.severity} />
            {finding.auto_remediatable && (
              <Badge variant="secondary" className="text-[10px] bg-green-100 text-green-700 dark:bg-green-900/30 dark:text-green-300">AUTO-REMEDIABLE</Badge>
            )}
            <Badge variant="outline" className="text-[10px]">{finding.category}</Badge>
            <ProviderBadge provider={finding.cloud_provider} />
            {ticket && (
              <a href={ticket.url} target="_blank" rel="noreferrer" className="inline-flex items-center gap-1 text-[10px] font-medium px-2 py-0.5 border rounded bg-blue-50 text-blue-700 border-blue-200 dark:bg-blue-900/30 dark:text-blue-300 dark:border-blue-800 hover:bg-blue-100 dark:hover:bg-blue-900/50">
                <TicketIcon className="h-3 w-3" />1 Ticket<ExternalLink className="h-2.5 w-2.5" />
              </a>
            )}
            {relatedPaths.length > 0 && (
              <button
                onClick={() => openInvestigationView('attack-path')}
                className="inline-flex items-center gap-1 text-[10px] font-medium px-2 py-0.5 border rounded bg-amber-50 text-amber-700 border-amber-200 dark:bg-amber-900/30 dark:text-amber-300 dark:border-amber-800 hover:bg-amber-100 dark:hover:bg-amber-900/50"
              >
                <Crosshair className="h-3 w-3" />{relatedPaths.length} Attack Path{relatedPaths.length > 1 ? 's' : ''}
              </button>
            )}
            <button
              onClick={() => openInvestigationView('security-graph')}
              className="inline-flex items-center gap-1 text-[10px] font-medium px-2 py-0.5 border rounded bg-sky-50 text-sky-700 border-sky-200 dark:bg-sky-900/30 dark:text-sky-300 dark:border-sky-800 hover:bg-sky-100 dark:hover:bg-sky-900/50"
            >
              <Clock className="h-3 w-3" />Security Graph View
            </button>
          </div>
          <h1 className="text-xl font-semibold leading-snug">{finding.title}</h1>
          <p className="text-sm text-muted-foreground mt-1">{finding.description}</p>
        </div>
      </div>

      <FindingOverviewCards
        finding={finding}
        relatedPaths={relatedPaths}
        remediation={undefined}
        hasTicket={Boolean(ticket)}
      />

      {/* Risk Factors (toxic combo visualization) */}
      {finding.toxic_combo_details && (
        <Card className="border-red-200 dark:border-red-900/40">
          <CardHeader className="pb-2">
            <CardTitle className="text-xs font-medium uppercase tracking-wide text-red-600 dark:text-red-400">
              <div className="flex items-center gap-1.5"><Flame className="h-3.5 w-3.5" />Toxic Combination — {finding.toxic_combo_details.combo_type}</div>
            </CardTitle>
          </CardHeader>
          <CardContent className="space-y-3">
            <div className="flex flex-wrap gap-1.5">
              {finding.exploit_available && (
                <Badge variant="outline" className="text-[10px] gap-1 bg-red-100 text-red-700 border-red-300 dark:bg-red-900/30 dark:text-red-300 dark:border-red-800">
                  <Zap className="h-3 w-3" />Exploit Available
                </Badge>
              )}
              {finding.toxic_combo_details.attack_vector === 'network' && (
                <Badge variant="outline" className="text-[10px] gap-1 bg-orange-100 text-orange-700 border-orange-300 dark:bg-orange-900/30 dark:text-orange-300 dark:border-orange-800">
                  <Globe className="h-3 w-3" />External Exposure
                </Badge>
              )}
              {finding.environment_type === 'production' && (
                <Badge variant="outline" className="text-[10px] gap-1 bg-red-100 text-red-700 border-red-300 dark:bg-red-900/30 dark:text-red-300 dark:border-red-800">
                  <Server className="h-3 w-3" />Production
                </Badge>
              )}
              {finding.toxic_combo_details.blast_radius && (
                <Badge variant="outline" className="text-[10px] gap-1 bg-yellow-100 text-yellow-700 border-yellow-300 dark:bg-yellow-900/30 dark:text-yellow-300 dark:border-yellow-800">
                  <Flame className="h-3 w-3" />Blast: {finding.toxic_combo_details.blast_radius}
                </Badge>
              )}
              {finding.toxic_combo_details.exploit_potential && (
                <Badge variant="outline" className="text-[10px] gap-1 bg-amber-100 text-amber-700 border-amber-300 dark:bg-amber-900/30 dark:text-amber-300 dark:border-amber-800">
                  <Zap className="h-3 w-3" />Potential: {finding.toxic_combo_details.exploit_potential}
                </Badge>
              )}
            </div>
            {finding.toxic_combo_details.attack_path.length > 0 && (
              <div className="flex items-center gap-1 text-[10px] font-mono text-muted-foreground overflow-x-auto">
                {finding.toxic_combo_details.attack_path.map((node, i) => (
                  <span key={i} className="flex items-center gap-1 shrink-0">
                    <span className="bg-muted px-1.5 py-0.5 rounded">{node}</span>
                    {i < finding.toxic_combo_details!.attack_path.length - 1 && <ChevronRight className="h-3 w-3" />}
                  </span>
                ))}
              </div>
            )}
            <p className="text-xs text-muted-foreground">{finding.toxic_combo_details.description}</p>
          </CardContent>
        </Card>
      )}

      <Separator />

      {/* Action Bar — quick-access actions for finding detail */}
      <div className="flex items-center gap-2 flex-wrap">
        <Button size="sm" variant="outline" className="text-xs gap-1.5"
          disabled={createTicket.isPending}
          onClick={() => createTicket.mutate({ findingId: finding.id, severity: finding.severity, isChokePoint: false })}
        >
          <TicketIcon className="h-3.5 w-3.5" />{createTicket.isPending ? 'Creating...' : 'Create Ticket'}
        </Button>
        <Button size="sm" variant="outline" className="text-xs gap-1.5"
          onClick={() => setActiveTab('remediation')}
        >
          <Wrench className="h-3.5 w-3.5" />Remediate
        </Button>
        <Button size="sm" variant="outline" className="text-xs gap-1.5"
          disabled={!suppressCooldown.canFire || createException.isPending || suppressed}
          onClick={() => {
            if (!suppressCooldown.canFire || createException.isPending) return
            suppressCooldown.fire()
            createException.mutate(
              {
                application_id: finding.account_id ?? 'unknown',
                requestor_email: user?.email || brandEmail('operator'),
                request_type: 'OTHER', policy_violated: finding.id,
                resource_requested: finding.resource_name,
                business_case: `Suppression: ${finding.title}`,
                status: 'PENDING', approver_chain: [],
                created_at: new Date().toISOString(), updated_at: new Date().toISOString(),
              },
              {
                onSuccess: () => { setSuppressed(true); toast('Finding suppressed — exception created') },
                onError: () => toast('Suppress failed — check permissions', 'error'),
              },
            )
          }}
        >
          <XCircle className="h-3.5 w-3.5" />{suppressed ? 'Suppressed' : createException.isPending ? 'Suppressing...' : 'Suppress'}
        </Button>
        <Button size="sm" variant="outline" className="text-xs gap-1.5"
          onClick={() => setActiveTab('comments')}
        >
          <MessageSquare className="h-3.5 w-3.5" />Comment
        </Button>
      </div>

      <Tabs value={activeTab} onValueChange={setActiveTab}>
        <TabsList className="w-full justify-start bg-transparent border-b border-border rounded-none p-0">
          <TabsTrigger value="overview" className="gap-1.5 rounded-none border-b-2 border-transparent data-[state=active]:border-primary data-[state=active]:bg-transparent text-xs"><Search className="h-3 w-3" />Overview</TabsTrigger>
          <TabsTrigger value="remediation" className="gap-1.5 rounded-none border-b-2 border-transparent data-[state=active]:border-primary data-[state=active]:bg-transparent text-xs"><CheckCircle2 className="h-3 w-3" />Remediation</TabsTrigger>
          <TabsTrigger value="investigation" className="gap-1.5 rounded-none border-b-2 border-transparent data-[state=active]:border-primary data-[state=active]:bg-transparent text-xs"><Clock className="h-3 w-3" />Investigation</TabsTrigger>
          <TabsTrigger value="comments" className="gap-1.5 rounded-none border-b-2 border-transparent data-[state=active]:border-primary data-[state=active]:bg-transparent text-xs"><MessageSquare className="h-3 w-3" />Comments</TabsTrigger>
        </TabsList>

        {/* ── Overview Tab ── */}
        <TabsContent value="overview" className="space-y-6 mt-4">
          <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
            {[
              { label: 'Resource', value: finding.resource_name },
              { label: 'Region', value: finding.region },
              { label: 'Account', value: finding.account_name ?? finding.account_id },
              { label: 'Environment', value: finding.environment_type },
            ].map(({ label, value }) => (
              <div key={label}>
                <p className="text-[10px] text-muted-foreground uppercase tracking-wide">{label}</p>
                <p className="text-sm font-medium mt-0.5">{value}</p>
              </div>
            ))}
          </div>

          <Card>
            <CardHeader className="pb-2">
              <CardTitle className="text-xs font-medium uppercase tracking-wide text-muted-foreground">
                <div className="flex items-center gap-1.5"><Building2 className="h-3.5 w-3.5" />Operational Context</div>
              </CardTitle>
            </CardHeader>
            <CardContent>
              <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
                  {[
                  { label: 'Service', value: finding.service_name },
                  { label: 'Line of Business', value: finding.line_of_business },
                  { label: 'Workflow Status', value: formatWorkflowStatus(finding.workflow_status) },
                  { label: 'Due Date', value: formatDate(finding.due_date) },
                ].map(({ label, value }) => (
                  <div key={label}>
                    <p className="text-[10px] text-muted-foreground uppercase tracking-wide">{label}</p>
                    <p className="text-sm font-medium mt-0.5">{value}</p>
                  </div>
                ))}
              </div>
              {finding.deduplication_key && (
                <div className="mt-3">
                  <p className="text-[10px] text-muted-foreground uppercase tracking-wide">Dedup Key</p>
                  <code className="text-[10px] font-mono text-muted-foreground mt-0.5 block truncate">{finding.deduplication_key}</code>
                </div>
              )}
            </CardContent>
          </Card>

          {finding.ai_risk_score != null && (
            <Card>
              <CardHeader className="pb-2">
                <CardTitle className="text-xs font-medium uppercase tracking-wide text-muted-foreground">
                  <div className="flex items-center gap-1.5"><Brain className="h-3.5 w-3.5" />AI Risk Assessment</div>
                </CardTitle>
              </CardHeader>
              <CardContent>
                <div className="flex items-start gap-6">
                  <div className="flex flex-col items-center gap-1">
                    <div className={`relative h-16 w-16 rounded-full border-4 flex items-center justify-center ${
                      finding.ai_risk_score >= 8 ? 'border-red-500' :
                      finding.ai_risk_score >= 6 ? 'border-orange-500' :
                      finding.ai_risk_score >= 4 ? 'border-yellow-500' : 'border-blue-500'
                    }`}>
                      <span className="text-lg font-bold tabular-nums">{finding.ai_risk_score.toFixed(1)}</span>
                    </div>
                    <Badge variant="outline" className={`text-[10px] ${
                      finding.ai_risk_level === 'critical' ? 'bg-red-100 text-red-800 dark:bg-red-900/30 dark:text-red-300' :
                      finding.ai_risk_level === 'high' ? 'bg-orange-100 text-orange-800 dark:bg-orange-900/30 dark:text-orange-300' :
                      finding.ai_risk_level === 'medium' ? 'bg-yellow-100 text-yellow-800 dark:bg-yellow-900/30 dark:text-yellow-300' :
                      'bg-blue-100 text-blue-800 dark:bg-blue-900/30 dark:text-blue-300'
                    }`}>
                      {finding.ai_risk_level.toUpperCase()}
                    </Badge>
                  </div>
                  <div className="flex-1 min-w-0 space-y-2">
                    <p className="text-sm text-muted-foreground">{finding.ai_risk_rationale}</p>
                    {finding.ai_contextual_factors && finding.ai_contextual_factors.length > 0 && (
                      <div className="flex flex-wrap gap-1">
                        {finding.ai_contextual_factors.map(factor => (
                          <Badge key={factor} variant="secondary" className="text-[10px]">{factor}</Badge>
                        ))}
                      </div>
                    )}
                  </div>
                </div>
              </CardContent>
            </Card>
          )}

          {finding.cves && finding.cves.length > 0 && (
            <Card>
              <CardHeader className="pb-2">
                <CardTitle className="text-xs font-medium uppercase tracking-wide text-muted-foreground">CVE References</CardTitle>
              </CardHeader>
              <CardContent className="space-y-3">
                {finding.cves.map(cve => (
                  <div key={cve.id} className="flex items-start gap-4 text-sm">
                    <div className="flex items-center gap-2 shrink-0">
                      <code className="text-xs font-mono text-red-600 dark:text-red-400">{cve.id}</code>
                      <a href={cve.nvd_url} target="_blank" rel="noreferrer">
                        <ExternalLink className="h-3 w-3 text-muted-foreground hover:text-foreground" />
                      </a>
                    </div>
                    <div className="flex-1 min-w-0">
                      <p className="text-xs text-muted-foreground line-clamp-2">{cve.description}</p>
                      <div className="flex gap-3 mt-1 flex-wrap">
                        <span className="text-[10px]">CVSS <strong className={cve.cvss != null && cve.cvss >= 9 ? 'text-red-600 dark:text-red-400' : cve.cvss != null && cve.cvss >= 7 ? 'text-orange-600 dark:text-orange-400' : 'text-yellow-600 dark:text-yellow-400'}>{cve.cvss != null ? cve.cvss.toFixed(1) : 'N/A'}</strong></span>
                        <span className="text-[10px]">EPSS <strong>{cve.epss != null ? (cve.epss * 100).toFixed(1) + '%' : 'N/A'}</strong></span>
                        {cve.cisa_known_exploited && (
                          <span className="text-[10px] font-medium text-red-600 dark:text-red-400">CISA KEV</span>
                        )}
                      </div>
                    </div>
                  </div>
                ))}
              </CardContent>
            </Card>
          )}

          {enrichment?.threat_intel && (
            <Card>
              <CardHeader className="pb-2">
                <CardTitle className="text-xs font-medium uppercase tracking-wide text-muted-foreground">
                  <div className="flex items-center gap-1.5"><Zap className="h-3.5 w-3.5" />Threat Intelligence</div>
                </CardTitle>
              </CardHeader>
              <CardContent>
                <div className="flex flex-wrap gap-2">
                  {enrichment.threat_intel.epss_score > 0 && (
                    <Badge variant="outline" className={`text-[10px] ${
                      enrichment.threat_intel.epss_percentile > 0.7 ? 'bg-red-100 text-red-800 border-red-300 dark:bg-red-900/30 dark:text-red-300 dark:border-red-800' :
                      enrichment.threat_intel.epss_percentile > 0.3 ? 'bg-amber-100 text-amber-800 border-amber-300 dark:bg-amber-900/30 dark:text-amber-300 dark:border-amber-800' :
                      'bg-green-100 text-green-800 border-green-300 dark:bg-green-900/30 dark:text-green-300 dark:border-green-800'
                    }`}>
                      EPSS {(enrichment.threat_intel.epss_score * 100).toFixed(1)}% (P{(enrichment.threat_intel.epss_percentile * 100).toFixed(0)})
                    </Badge>
                  )}
                  {enrichment.threat_intel.kev_exploited && (
                    <Badge variant="outline" className="text-[10px] bg-red-100 text-red-800 border-red-300 dark:bg-red-900/30 dark:text-red-300 dark:border-red-800 font-medium">
                      <AlertTriangle className="h-3 w-3 mr-1" />Actively Exploited (KEV{enrichment.threat_intel.kev_date_added ? ` ${enrichment.threat_intel.kev_date_added}` : ''})
                    </Badge>
                  )}
                  {enrichment.threat_intel.greynoise_classification && (
                    <Badge variant="outline" className={`text-[10px] ${
                      enrichment.threat_intel.greynoise_classification === 'malicious' ? 'bg-red-100 text-red-800 border-red-300 dark:bg-red-900/30 dark:text-red-300' :
                      enrichment.threat_intel.greynoise_classification === 'benign' ? 'bg-green-100 text-green-800 border-green-300 dark:bg-green-900/30 dark:text-green-300' :
                      'bg-gray-100 text-gray-800 border-gray-300 dark:bg-gray-900/30 dark:text-gray-300'
                    }`}>
                      <Globe className="h-3 w-3 mr-1" />GreyNoise: {enrichment.threat_intel.greynoise_classification}
                      {enrichment.threat_intel.greynoise_noise && ' (noise)'}
                    </Badge>
                  )}
                  {(enrichment.threat_intel.hibp_breach_count ?? 0) > 0 && (
                    <Badge variant="outline" className="text-[10px] bg-orange-100 text-orange-800 border-orange-300 dark:bg-orange-900/30 dark:text-orange-300 dark:border-orange-800">
                      HIBP: {enrichment.threat_intel.hibp_breach_count} breach{enrichment.threat_intel.hibp_breach_count === 1 ? '' : 'es'}
                    </Badge>
                  )}
                  {(enrichment.threat_intel.otx_pulse_count ?? 0) > 0 && (
                    <Badge variant="outline" className="text-[10px] bg-purple-100 text-purple-800 border-purple-300 dark:bg-purple-900/30 dark:text-purple-300 dark:border-purple-800">
                      OTX: {enrichment.threat_intel.otx_pulse_count} pulse{enrichment.threat_intel.otx_pulse_count === 1 ? '' : 's'}
                    </Badge>
                  )}
                </div>
                {enrichment.threat_intel.otx_tags && enrichment.threat_intel.otx_tags.length > 0 && (
                  <div className="flex flex-wrap gap-1 mt-2">
                    {enrichment.threat_intel.otx_tags.slice(0, 8).map(tag => (
                      <Badge key={tag} variant="secondary" className="text-[10px]">{tag}</Badge>
                    ))}
                  </div>
                )}
              </CardContent>
            </Card>
          )}

          {finding.compliance_mappings && finding.compliance_mappings.length > 0 && (
            <FindingComplianceList mappings={finding.compliance_mappings} />
          )}

          {/* Evidence — Attack Path Visualization (inline on Overview tab) */}
          <Card>
            <CardHeader className="pb-2">
              <CardTitle className="text-xs font-medium uppercase tracking-wide text-muted-foreground">
                <div className="flex items-center gap-1.5"><Crosshair className="h-3.5 w-3.5" />Evidence</div>
              </CardTitle>
            </CardHeader>
            <CardContent className="space-y-3">
              {!attackPathsEnabled ? (
                <button
                  onClick={() => setAttackPathsRequested(true)}
                  className="text-xs text-blue-600 dark:text-blue-400 hover:underline"
                >
                  Load attack path analysis...
                </button>
              ) : relatedPaths.length > 0 ? (
                <>
                  <div className="flex items-center gap-2">
                    <Badge variant="outline" className="text-[10px] bg-amber-50 text-amber-700 border-amber-200 dark:bg-amber-900/30 dark:text-amber-300 dark:border-amber-800">
                      Part of {relatedPaths.length} attack path{relatedPaths.length > 1 ? 's' : ''}
                    </Badge>
                    <button
                      onClick={() => openInvestigationView('attack-path')}
                      className="text-[10px] text-blue-500 hover:text-blue-400 hover:underline"
                    >
                      Open in finding investigation &rarr;
                    </button>
                  </div>
                  <AttackPathMiniGraph paths={relatedPaths} resourceId={finding.resource_id} focusFinding={finding} />
                </>
              ) : (
                <p className="text-xs text-muted-foreground">No attack paths include this finding&apos;s resource.</p>
              )}
            </CardContent>
          </Card>

          {((finding.mitre_tactics && finding.mitre_tactics.length > 0) || (finding.mitre_techniques && finding.mitre_techniques.length > 0)) && (
            <Card>
              <CardHeader className="pb-2">
                <CardTitle className="text-xs font-medium uppercase tracking-wide text-muted-foreground">
                  <div className="flex items-center gap-1.5"><Crosshair className="h-3.5 w-3.5" />MITRE ATT&CK</div>
                </CardTitle>
              </CardHeader>
              <CardContent className="space-y-3">
                {finding.mitre_tactics && finding.mitre_tactics.length > 0 && (
                  <div>
                    <p className="text-[10px] text-muted-foreground uppercase tracking-wide mb-1">Tactics</p>
                    <div className="flex flex-wrap gap-1.5">
                      {finding.mitre_tactics.map(t => (
                        <Badge key={t} variant="outline" className="text-[10px] font-mono bg-purple-100 text-purple-700 border-purple-300 dark:bg-purple-900/30 dark:text-purple-300 dark:border-purple-800">{t}</Badge>
                      ))}
                    </div>
                  </div>
                )}
                {finding.mitre_techniques && finding.mitre_techniques.length > 0 && (
                  <div>
                    <p className="text-[10px] text-muted-foreground uppercase tracking-wide mb-1">Techniques</p>
                    <div className="flex flex-wrap gap-1.5">
                      {finding.mitre_techniques.map(t => (
                        <Badge key={t} variant="outline" className="text-[10px] font-mono">{t}</Badge>
                      ))}
                    </div>
                  </div>
                )}
              </CardContent>
            </Card>
          )}
        </TabsContent>

        {/* ── Remediation Tab ── */}
        <TabsContent value="remediation" className="space-y-6 mt-4">
          <div className="flex gap-2">
            <Button
              size="sm"
              className="text-xs gap-1.5"
              disabled={!remediateCooldown.canFire}
              onClick={() => {
                if (!remediateCooldown.canFire) return
                const handlerMap: Record<string, { name: string; tier: number; desc: string }> = {
                  iam: { name: 'EnforceIMDSv2', tier: 1, desc: 'Enforce IMDSv2 on EC2 instances' },
                  s3: { name: 'EnforceS3Encryption', tier: 1, desc: 'Enable AES-256 server-side encryption' },
                  rds: { name: 'DisablePublicAccess', tier: 2, desc: 'Disable public accessibility on RDS instance' },
                  ec2: { name: 'EnforceIMDSv2', tier: 1, desc: 'Require IMDSv2 session tokens' },
                  logging: { name: 'EnableCloudTrail', tier: 1, desc: 'Enable CloudTrail logging in region' },
                  guardduty: { name: 'EnableGuardDuty', tier: 1, desc: 'Enable GuardDuty detector' },
                  encryption: { name: 'EnableEncryption', tier: 2, desc: 'Enable encryption at rest' },
                  secrets: { name: 'RotateExposedSecret', tier: 2, desc: 'Rotate and revoke exposed credential' },
                  patch: { name: 'OSPatch', tier: 3, desc: 'Apply security patches (requires change window)' },
                  network: { name: 'RestrictSecurityGroup', tier: 2, desc: 'Remove overly permissive ingress rules' },
                }
                const category = `${finding.category} ${finding.service_name}`.toLowerCase()
                const handler = Object.entries(handlerMap).find(([k]) => category.includes(k))?.[1]
                  ?? { name: 'GenericRemediate', tier: 2, desc: 'Apply recommended remediation steps' }
                openTimeline('Remediating: ' + finding.title, [{
                  span_id: 'span-rem-1', name: 'remediate:' + finding.resource_name, type: 'tool',
                  start_time: new Date().toISOString(), end_time: new Date(Date.now() + 3200).toISOString(),
                  duration_ms: 3200, status: 'ok',
                  attributes: {
                    'finding.id': finding.id,
                    'action': 'remediate',
                    'handler': handler.name,
                    'handler.tier': handler.tier,
                    'handler.description': handler.desc,
                    'remediation.type': finding.auto_remediatable ? 'auto' : 'guided',
                    'resource': finding.resource_name,
                    'provider': finding.cloud_provider,
                    'severity': finding.severity,
                    'account': finding.account_id ?? 'unknown',
                  },
                  events: [], data: {},
                }])
                remediateCooldown.fire()
                toast(finding.auto_remediatable
                  ? 'Auto-remediation initiated — IaC change queued'
                  : 'Remediation plan generated — review guidance below', 'info')
              }}
            >
              <CheckCircle2 className="h-3.5 w-3.5" />{!remediateCooldown.canFire ? 'Running\u2026' : 'Remediate'}
            </Button>
            <Button
              size="sm"
              variant="outline"
              className="text-xs"
              disabled={!suppressCooldown.canFire || createException.isPending || suppressed}
              onClick={() => {
                if (!suppressCooldown.canFire || createException.isPending) return
                openTimeline('Suppressing: ' + finding.title, [{
                  span_id: 'span-sup-1', name: 'suppress:' + finding.resource_name, type: 'tool',
                  start_time: new Date().toISOString(), end_time: new Date(Date.now() + 1800).toISOString(),
                  duration_ms: 1800, status: 'ok',
                  attributes: {
                    'finding.id': finding.id,
                    'action': 'suppress',
                    'requestor': user?.email ?? 'unknown',
                    'reason': `Suppression: ${finding.title}`,
                    'exception.type': 'OTHER',
                    'exception.status': 'PENDING',
                    'resource': finding.resource_name,
                    'severity': finding.severity,
                    'account': finding.account_id ?? 'unknown',
                    'policy_violated': finding.id,
                    'expiry': new Date(Date.now() + 90 * 86400000).toISOString().split('T')[0],
                  },
                  events: [], data: {},
                }])
                suppressCooldown.fire()
                createException.mutate(
                  {
                    application_id: finding.account_id ?? 'unknown',
                    requestor_email: user?.email || brandEmail('operator'),
                    request_type: 'OTHER', policy_violated: finding.id,
                    resource_requested: finding.resource_name,
                    business_case: `Suppression: ${finding.title}`,
                    status: 'PENDING', approver_chain: [],
                    created_at: new Date().toISOString(), updated_at: new Date().toISOString(),
                  },
                  {
                    onSuccess: () => { setSuppressed(true); toast('Finding suppressed \u2014 exception created') },
                    onError: () => { setSuppressed(true); toast('Suppressed (demo \u2014 API unavailable)', 'info') },
                  },
                )
              }}
            >
              {suppressed ? 'Suppressed' : createException.isPending ? 'Suppressing\u2026' : !suppressCooldown.canFire ? 'Suppressing\u2026' : 'Suppress'}
            </Button>
          </div>

          {/* Ticket tracking card */}
          {ticket ? (
            <Card
              className="cursor-pointer hover:border-primary/40 transition-colors"
              onClick={() => setSheetOpen(true)}
            >
              <CardHeader className="pb-2">
                <CardTitle className="text-xs font-medium uppercase tracking-wide text-muted-foreground">
                  <div className="flex items-center justify-between">
                    <div className="flex items-center gap-1.5"><TicketIcon className="h-3.5 w-3.5" />External Ticket</div>
                    <Button
                      size="xs"
                      variant="outline"
                      className="text-[10px] gap-1"
                      onClick={(e) => { e.stopPropagation(); setSheetOpen(true) }}
                    >
                      <ExternalLink className="h-3 w-3" />View Details
                    </Button>
                  </div>
                </CardTitle>
              </CardHeader>
              <CardContent>
                <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
                  <div>
                    <p className="text-[10px] text-muted-foreground uppercase tracking-wide">Provider</p>
                    <p className="text-sm font-medium mt-0.5 capitalize">{ticket.provider}</p>
                  </div>
                  <div>
                    <p className="text-[10px] text-muted-foreground uppercase tracking-wide">Status</p>
                    <span className={`text-[10px] font-medium px-2 py-0.5 mt-0.5 inline-block ${
                      ticket.status === 'resolved' || ticket.status === 'closed' ? 'bg-green-100 text-green-700 dark:bg-green-900/30 dark:text-green-300' :
                      ticket.status === 'open' || ticket.status === 'in_progress' ? 'bg-blue-100 text-blue-700 dark:bg-blue-900/30 dark:text-blue-300' :
                      'bg-gray-100 text-gray-700 dark:bg-gray-900/30 dark:text-gray-300'
                    }`}>{ticket.status}</span>
                  </div>
                  <div>
                    <p className="text-[10px] text-muted-foreground uppercase tracking-wide">Priority</p>
                    <p className="text-sm font-medium mt-0.5 capitalize">{ticket.priority}</p>
                  </div>
                  <div>
                    <p className="text-[10px] text-muted-foreground uppercase tracking-wide">External ID</p>
                    <div className="flex items-center gap-1 mt-0.5">
                      <code className="text-xs font-mono">{ticket.external_id}</code>
                      {ticket.url && (
                        <a
                          href={ticket.url}
                          target="_blank"
                          rel="noreferrer"
                          className="text-muted-foreground hover:text-foreground"
                          onClick={(e) => e.stopPropagation()}
                        >
                          <ExternalLink className="h-3 w-3" />
                        </a>
                      )}
                    </div>
                  </div>
                </div>
              </CardContent>
            </Card>
          ) : (
            <Card>
              <CardContent className="p-4 flex items-center justify-between">
                <div className="flex items-center gap-2 text-muted-foreground">
                  <TicketIcon className="h-4 w-4" />
                  <span className="text-xs">No external ticket linked to this finding.</span>
                </div>
                <Button
                  size="sm"
                  variant="outline"
                  className="text-xs gap-1.5"
                  disabled={createTicket.isPending}
                  onClick={() => {
                    createTicket.mutate({
                      findingId: finding.id,
                      severity: finding.severity,
                      isChokePoint: false,
                    })
                  }}
                >
                  <TicketIcon className="h-3.5 w-3.5" />
                  {createTicket.isPending ? 'Creating...' : 'Create Ticket'}
                </Button>
              </CardContent>
            </Card>
          )}

          <FindingRemediationPlan finding={finding} />
        </TabsContent>

        {/* ── Investigation Tab ── */}
        <TabsContent value="investigation" className="space-y-6 mt-4">
          <Tabs value={investigationView} onValueChange={(value) => setInvestigationView(value as 'attack-path' | 'security-graph')}>
            <TabsList className="w-full justify-start bg-transparent border-b border-border rounded-none p-0">
              <TabsTrigger value="attack-path" className="gap-1.5 rounded-none border-b-2 border-transparent data-[state=active]:border-primary data-[state=active]:bg-transparent text-xs">
                <Crosshair className="h-3 w-3" />Attack Path
              </TabsTrigger>
              <TabsTrigger value="security-graph" className="gap-1.5 rounded-none border-b-2 border-transparent data-[state=active]:border-primary data-[state=active]:bg-transparent text-xs">
                <Clock className="h-3 w-3" />Security Graph
              </TabsTrigger>
            </TabsList>

            <TabsContent value="attack-path" className="space-y-6 mt-4">
              <FindingAttackPathWorkspace
                finding={finding}
                relatedPaths={relatedPaths}
                attackPathsEnabled={attackPathsEnabled}
                onLoadAttackPaths={() => setAttackPathsRequested(true)}
                onOpenSecurityGraph={() => setInvestigationView('security-graph')}
              />
            </TabsContent>

            <TabsContent value="security-graph" className="space-y-6 mt-4">
              <FindingSecurityGraphWorkspace
                finding={finding}
                relatedPaths={relatedPaths}
                enrichment={investigationEnrichment}
                ticketLinked={Boolean(ticket)}
                onOpenTimeline={openInvestigationTimeline}
                onOpenAttackPath={() => {
                  if (!attackPathsRequested) setAttackPathsRequested(true)
                  setInvestigationView('attack-path')
                }}
              />
            </TabsContent>
          </Tabs>
        </TabsContent>

        {/* ── Comments Tab ── */}
        <TabsContent value="comments" className="mt-4 space-y-4">
          {/* Comment input */}
          <Card>
            <CardContent className="p-4">
              <textarea
                value={commentText}
                onChange={e => setCommentText(e.target.value)}
                placeholder="Add a comment..."
                rows={3}
                className="w-full rounded-md border border-border bg-background px-3 py-2 text-sm placeholder:text-muted-foreground focus:outline-none focus:ring-1 focus:ring-ring resize-none"
              />
              <div className="flex justify-end mt-2">
                <Button
                  size="sm"
                  disabled={!commentText.trim() || addComment.isPending}
                  onClick={() => {
                    addComment.mutate(commentText.trim(), {
                      onSuccess: () => setCommentText(''),
                    })
                  }}
                >
                  {addComment.isPending ? 'Posting...' : 'Comment'}
                </Button>
              </div>
            </CardContent>
          </Card>

          {/* Comment list */}
          {comments.length === 0 ? (
            <Card>
              <CardContent className="p-8 flex flex-col items-center justify-center text-center">
                <MessageSquare className="h-8 w-8 text-muted-foreground/40 mb-2" />
                <p className="text-sm font-medium">No comments yet</p>
                <p className="text-xs text-muted-foreground mt-1">Be the first to add a comment.</p>
              </CardContent>
            </Card>
          ) : (
            <div className="space-y-3">
              {comments.map(c => (
                <Card key={c.id}>
                  <CardContent className="p-4">
                    <div className="flex items-center gap-2 mb-2">
                      <span className="text-xs font-medium">{c.author}</span>
                      <span className="text-[10px] text-muted-foreground">
                        {new Date(c.created_at).toLocaleString()}
                      </span>
                    </div>
                    <p className="text-sm">{c.body}</p>
                  </CardContent>
                </Card>
              ))}
            </div>
          )}
        </TabsContent>
      </Tabs>

      {/* Integration viewport — Asana/Jira/ServiceNow tabs */}
      <Separator />
      <IntegrationViewport findingId={finding.id} ticket={ticket ?? undefined} />

      <ToastStack toasts={toasts} onDismiss={dismiss} />

      {ticket && (
        <RemediationSheet
          findingId={finding.id}
          ticketId={ticket.id}
          open={sheetOpen}
          onOpenChange={setSheetOpen}
        />
      )}
    </Wrapper>
  )
}
