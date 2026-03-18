import { brandEmail } from '@/lib/mock-data-utils'
import { useState, useMemo } from 'react'
import { useAuth } from '@/lib/auth'
import { useParams, useNavigate } from 'react-router-dom'
import { useFinding } from '@/hooks/useFindings'
import { useAttackPaths } from '@/hooks/useAttackPaths'
import { AttackPathMiniGraph } from '@/components/attack-path/AttackPathMiniGraph'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { Separator } from '@/components/ui/separator'
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs'
import { ArrowLeft, ExternalLink, CheckCircle2, Shield, AlertTriangle, Brain, Crosshair, Building2, Zap, Globe, Flame, Server, ChevronRight, Clock, MessageSquare, Search, CircleDot, Wrench, UserCheck, XCircle } from 'lucide-react'
import { SeverityBadge } from '@/components/findings/SeverityBadge'
import { ProviderBadge } from '@/components/ui/ProviderBadge'
import { useTracePanel } from '@/lib/trace-panel-context'
import { useActionCooldown } from '@/hooks/useActionCooldown'
import { useCreateException } from '@/hooks/useExceptions'
import { useComments, useAddComment } from '@/hooks/useComments'
import { useToast } from '@/hooks/useToast'
import { ToastStack } from '@/components/ui/ToastStack'

export default function FindingDetail() {
  const { id } = useParams<{ id: string }>()
  const navigate = useNavigate()
  const { user } = useAuth()
  const { data: finding, isLoading } = useFinding(id ?? '')
  const { openTimeline } = useTracePanel()
  const remediateCooldown = useActionCooldown({ key: `remediate-${id ?? ''}`, cooldownMs: 10_000 })
  const suppressCooldown = useActionCooldown({ key: `suppress-${id ?? ''}`, cooldownMs: 15_000 })
  const createException = useCreateException()
  const { toasts, toast, dismiss } = useToast()
  const [suppressed, setSuppressed] = useState(false)
  const [commentText, setCommentText] = useState('')
  const { data: comments = [] } = useComments(id ?? '')
  const addComment = useAddComment(id ?? '')

  // Fetch attack paths to find any that include this finding
  const { data: attackPathsData } = useAttackPaths(1, 200)
  const relatedPaths = useMemo(() => {
    if (!attackPathsData?.data || !finding) return []
    return attackPathsData.data.filter(p =>
      p.finding_ids.includes(finding.id) ||
      p.nodes.some(n => n.resource_id === finding.resource_id),
    )
  }, [attackPathsData, finding])

  if (isLoading) {
    return <div className="text-sm text-muted-foreground p-6">Loading finding…</div>
  }
  if (!finding) {
    return (
      <div className="space-y-4 max-w-3xl">
        <Button variant="ghost" size="sm" className="gap-1.5 -ml-2" onClick={() => navigate('/ops/findings')}>
          <ArrowLeft className="h-4 w-4" />All Findings
        </Button>
        <div className="text-sm text-muted-foreground">Finding not found.</div>
      </div>
    )
  }

  return (
    <div className="space-y-6 max-w-4xl pb-10">
      <Button variant="ghost" size="sm" className="gap-1.5 -ml-2" onClick={() => navigate('/ops/findings')}>
        <ArrowLeft className="h-4 w-4" />All Findings
      </Button>

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
          </div>
          <h1 className="text-xl font-semibold leading-snug">{finding.title}</h1>
          <p className="text-sm text-muted-foreground mt-1">{finding.description}</p>
        </div>
      </div>

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

      <Tabs defaultValue="overview">
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
                  { label: 'Workflow Status', value: finding.workflow_status.replace(/_/g, ' ').replace(/\b\w/g, c => c.toUpperCase()) },
                  { label: 'Due Date', value: finding.due_date ? new Date(finding.due_date).toLocaleDateString() : 'N/A' },
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

          {finding.compliance_mappings && finding.compliance_mappings.length > 0 && (
            <Card>
              <CardHeader className="pb-2">
                <CardTitle className="text-xs font-medium uppercase tracking-wide text-muted-foreground">
                  <div className="flex items-center gap-1.5"><Shield className="h-3.5 w-3.5" />Compliance Mappings</div>
                </CardTitle>
              </CardHeader>
              <CardContent>
                <div className="flex flex-wrap gap-1.5">
                  {finding.compliance_mappings.map(m => (
                    <div key={`${m.framework_id}-${m.control_id}`} className="text-[10px] font-mono border rounded px-2 py-0.5 bg-muted">
                      {m.framework_name} {m.control_id}
                    </div>
                  ))}
                </div>
              </CardContent>
            </Card>
          )}

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
                openTimeline('Remediating: ' + finding.title, [{
                  span_id: 'span-rem-1', name: 'remediate:' + finding.resource_name, type: 'tool',
                  start_time: new Date().toISOString(), end_time: new Date(Date.now() + 3200).toISOString(),
                  duration_ms: 3200, status: 'ok', attributes: { 'finding.id': finding.id }, events: [], data: {},
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
                  duration_ms: 1800, status: 'ok', attributes: { 'finding.id': finding.id, action: 'suppress' }, events: [], data: {},
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

          {finding.remediation_steps && finding.remediation_steps.length > 0 ? (
            <Card>
              <CardHeader className="pb-2">
                <CardTitle className="text-xs font-medium uppercase tracking-wide text-muted-foreground">
                  <div className="flex items-center gap-1.5"><AlertTriangle className="h-3.5 w-3.5" />Remediation Steps</div>
                </CardTitle>
              </CardHeader>
              <CardContent className="space-y-4">
                {finding.remediation_steps.map(step => (
                  <div key={step.order} className="flex gap-3">
                    <div className="h-5 w-5 rounded-full bg-muted flex items-center justify-center text-[10px] font-bold shrink-0 mt-0.5">
                      {step.order}
                    </div>
                    <div className="flex-1 min-w-0">
                      <p className="text-sm font-medium">{step.title}</p>
                      <p className="text-xs text-muted-foreground mt-0.5">{step.description}</p>
                      {step.command && (
                        <code className="block mt-1.5 text-[10px] font-mono bg-muted rounded px-2 py-1.5">{step.command}</code>
                      )}
                      <div className="flex items-center gap-2 mt-1">
                        {step.automated && <Badge variant="secondary" className="text-[10px] bg-green-100 text-green-700 dark:bg-green-900/30 dark:text-green-300">Automated</Badge>}
                        {step.platform && <span className="text-[10px] text-muted-foreground">{step.platform}</span>}
                      </div>
                    </div>
                  </div>
                ))}
              </CardContent>
            </Card>
          ) : (
            <Card>
              <CardContent className="p-4 space-y-3">
                <p className="text-sm text-muted-foreground">{finding.remediation}</p>
                {(() => {
                  const guidance: Record<string, { title: string; steps: string[] }> = {
                    compute: { title: 'Compute Remediation', steps: ['Review instance security groups and restrict inbound rules', 'Enable IMDSv2 and disable legacy metadata endpoints', 'Apply latest AMI/image patches via deployment pipeline', 'Rotate compromised credentials and revoke unused IAM roles'] },
                    storage: { title: 'Storage Remediation', steps: ['Enable server-side encryption (SSE-S3/SSE-KMS/CMK)', 'Block public access at bucket/account level', 'Enable access logging and versioning', 'Review and tighten bucket policies and ACLs'] },
                    database: { title: 'Database Remediation', steps: ['Enable encryption at rest and in transit (TLS)', 'Restrict network access to private subnets only', 'Enable automated backups and audit logging', 'Rotate master credentials and enforce IAM authentication'] },
                    network: { title: 'Network Remediation', steps: ['Restrict security group/NSG rules to specific CIDR ranges', 'Remove 0.0.0.0/0 inbound rules on sensitive ports', 'Enable VPC Flow Logs / NSG Flow Logs for monitoring', 'Implement network segmentation with private subnets'] },
                    identity: { title: 'Identity & Access Remediation', steps: ['Remove unused IAM users/roles and access keys', 'Enforce MFA on all privileged accounts', 'Apply least-privilege policies and review permissions', 'Enable CloudTrail/Activity Log for authentication events'] },
                    container: { title: 'Container Remediation', steps: ['Scan images for known CVEs and rebuild from patched base', 'Enforce pod security standards (restricted profile)', 'Enable runtime protection and network policies', 'Rotate secrets and use external secret managers'] },
                    serverless: { title: 'Serverless Remediation', steps: ['Restrict function execution role to minimum permissions', 'Enable VPC attachment for functions accessing private resources', 'Review and limit environment variables containing secrets', 'Enable X-Ray/distributed tracing for execution monitoring'] },
                  }
                  const g = guidance[finding.resource_type] ?? guidance.compute
                  return (
                    <div className="mt-3 border-t border-border pt-3">
                      <p className="text-xs font-medium uppercase tracking-wide text-muted-foreground mb-2">{g.title}</p>
                      <ol className="list-decimal list-inside space-y-1.5">
                        {g.steps.map((step, i) => (
                          <li key={i} className="text-xs text-muted-foreground">{step}</li>
                        ))}
                      </ol>
                    </div>
                  )
                })()}
              </CardContent>
            </Card>
          )}
        </TabsContent>

        {/* ── Investigation Tab ── */}
        <TabsContent value="investigation" className="space-y-6 mt-4">
          {/* Attack Path Visualization — Wiz-style finding-scoped graph */}
          {relatedPaths.length > 0 && (
            <AttackPathMiniGraph paths={relatedPaths} resourceId={finding.resource_id} />
          )}

          <Card>
            <CardHeader className="pb-2">
              <CardTitle className="text-xs font-medium uppercase tracking-wide text-muted-foreground">
                <div className="flex items-center gap-1.5"><Clock className="h-3.5 w-3.5" />Finding Lifecycle</div>
              </CardTitle>
            </CardHeader>
            <CardContent>
              <div className="space-y-0">
                {(() => {
                  const events: { label: string; time: string; icon: typeof Clock; iconColor: string; dotColor: string; description: string; actor?: string }[] = [
                    { label: 'First Detected', time: finding.first_found_at, icon: CircleDot, iconColor: 'text-blue-500', dotColor: 'bg-blue-500', description: `Detected by ${finding.source} scanner` },
                    { label: 'Last Seen', time: finding.last_seen_at, icon: Search, iconColor: 'text-indigo-500', dotColor: 'bg-indigo-500', description: 'Latest scan confirmed finding still active' },
                  ]
                  // Synthetic events from workflow status
                  if (finding.workflow_status !== 'new') {
                    events.push({
                      label: 'Triaged',
                      time: finding.first_found_at, // approximate
                      icon: CheckCircle2, iconColor: 'text-yellow-500', dotColor: 'bg-yellow-500',
                      description: 'Finding triaged and severity confirmed',
                    })
                  }
                  if (finding.assignee) {
                    events.push({
                      label: 'Assigned',
                      time: finding.assignee.assigned_at,
                      icon: UserCheck, iconColor: 'text-orange-500', dotColor: 'bg-orange-500',
                      description: `Assigned to ${finding.assignee.team}`,
                      actor: finding.assignee.user_name,
                    })
                  }
                  if (finding.workflow_status === 'in_progress') {
                    events.push({
                      label: 'Remediation Started',
                      time: finding.last_seen_at,
                      icon: Wrench, iconColor: 'text-cyan-500', dotColor: 'bg-cyan-500',
                      description: 'Active remediation in progress',
                    })
                  }
                  if (finding.due_date) {
                    events.push({
                      label: 'SLA Due',
                      time: finding.due_date,
                      icon: Clock, iconColor: 'text-orange-500', dotColor: 'bg-orange-500',
                      description: finding.sla_breach_date ? 'SLA breached — overdue' : 'Remediation deadline',
                    })
                  }
                  if (finding.resolved_at) {
                    events.push({
                      label: 'Resolved',
                      time: finding.resolved_at,
                      icon: CheckCircle2, iconColor: 'text-green-500', dotColor: 'bg-green-500',
                      description: 'Finding resolved and verified',
                    })
                  }
                  if (finding.workflow_status === 'false_positive' || finding.workflow_status === 'risk_accepted') {
                    events.push({
                      label: finding.workflow_status === 'false_positive' ? 'Marked False Positive' : 'Risk Accepted',
                      time: finding.last_seen_at,
                      icon: XCircle, iconColor: 'text-gray-500', dotColor: 'bg-gray-500',
                      description: finding.suppression_reason ?? 'Finding suppressed',
                    })
                  }
                  // Sort by time
                  events.sort((a, b) => new Date(a.time).getTime() - new Date(b.time).getTime())
                  return events.map((event, i, arr) => {
                    const Icon = event.icon
                    return (
                      <div key={event.label} className="flex gap-3 items-start">
                        <div className="flex flex-col items-center">
                          <div className={`h-6 w-6 rounded-full bg-muted flex items-center justify-center shrink-0 mt-0.5`}>
                            <Icon className={`h-3 w-3 ${event.iconColor}`} />
                          </div>
                          {i < arr.length - 1 && <div className="w-px h-8 bg-border" />}
                        </div>
                        <div className="pb-4 flex-1 min-w-0">
                          <div className="flex items-center gap-2">
                            <p className="text-xs font-medium">{event.label}</p>
                            {event.actor && (
                              <span className="text-[10px] text-muted-foreground">by {event.actor}</span>
                            )}
                          </div>
                          <p className="text-[10px] text-muted-foreground">{event.description}</p>
                          <p className="text-[10px] text-muted-foreground/70 mt-0.5">{new Date(event.time).toLocaleString()}</p>
                        </div>
                      </div>
                    )
                  })
                })()}
              </div>
              <Separator className="my-3" />
              <div className="grid grid-cols-2 gap-4">
                <div>
                  <p className="text-[10px] text-muted-foreground uppercase tracking-wide">Current Status</p>
                  <p className="text-xs font-medium mt-0.5">{finding.workflow_status.replace(/_/g, ' ').replace(/\b\w/g, c => c.toUpperCase())}</p>
                </div>
                <div>
                  <p className="text-[10px] text-muted-foreground uppercase tracking-wide">Source</p>
                  <p className="text-xs font-medium mt-0.5">{finding.source} ({finding.source_finding_id})</p>
                </div>
              </div>
            </CardContent>
          </Card>
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

      <ToastStack toasts={toasts} onDismiss={dismiss} />
    </div>
  )
}
