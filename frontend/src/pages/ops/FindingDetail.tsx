import { brandEmail } from '@/lib/mock-data-utils'
import { useState } from 'react'
import { useAuth } from '@/lib/auth'
import { useParams, useNavigate } from 'react-router-dom'
import { useFinding } from '@/hooks/useFindings'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { Separator } from '@/components/ui/separator'
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs'
import { ArrowLeft, ExternalLink, CheckCircle2, Shield, AlertTriangle, Brain, Crosshair, Building2, Zap, Globe, Flame, Server, ChevronRight, Clock, MessageSquare, Search } from 'lucide-react'
import { SeverityBadge } from '@/components/findings/SeverityBadge'
import { ProviderBadge } from '@/components/ui/ProviderBadge'
import { useTracePanel } from '@/lib/trace-panel-context'
import { useActionCooldown } from '@/hooks/useActionCooldown'
import { useCreateException } from '@/hooks/useExceptions'
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
              disabled={!finding.auto_remediatable || !remediateCooldown.canFire}
              onClick={() => {
                if (!remediateCooldown.canFire) return
                openTimeline('Remediating: ' + finding.title, [{
                  span_id: 'span-rem-1', name: 'remediate:' + finding.resource_name, type: 'tool',
                  start_time: new Date().toISOString(), end_time: new Date(Date.now() + 3200).toISOString(),
                  duration_ms: 3200, status: 'ok', attributes: { 'finding.id': finding.id }, events: [], data: {},
                }])
                remediateCooldown.fire()
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
              <CardContent className="p-4">
                <p className="text-sm text-muted-foreground">{finding.remediation}</p>
              </CardContent>
            </Card>
          )}
        </TabsContent>

        {/* ── Investigation Tab ── */}
        <TabsContent value="investigation" className="space-y-6 mt-4">
          <Card>
            <CardHeader className="pb-2">
              <CardTitle className="text-xs font-medium uppercase tracking-wide text-muted-foreground">
                <div className="flex items-center gap-1.5"><Clock className="h-3.5 w-3.5" />Detection Timeline</div>
              </CardTitle>
            </CardHeader>
            <CardContent>
              <div className="space-y-0">
                {[
                  { label: 'First Detected', time: finding.first_found_at, color: 'bg-blue-500' },
                  { label: 'Last Seen', time: finding.last_seen_at, color: 'bg-indigo-500' },
                  ...(finding.due_date ? [{ label: 'SLA Due', time: finding.due_date, color: 'bg-orange-500' }] : []),
                  ...(finding.resolved_at ? [{ label: 'Resolved', time: finding.resolved_at, color: 'bg-green-500' }] : []),
                ].map((event, i, arr) => (
                  <div key={event.label} className="flex gap-3 items-start">
                    <div className="flex flex-col items-center">
                      <div className={`h-2.5 w-2.5 rounded-full ${event.color} shrink-0 mt-1.5`} />
                      {i < arr.length - 1 && <div className="w-px h-8 bg-border" />}
                    </div>
                    <div className="pb-4">
                      <p className="text-xs font-medium">{event.label}</p>
                      <p className="text-[10px] text-muted-foreground">{new Date(event.time).toLocaleString()}</p>
                    </div>
                  </div>
                ))}
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
        <TabsContent value="comments" className="mt-4">
          <Card>
            <CardContent className="p-8 flex flex-col items-center justify-center text-center">
              <MessageSquare className="h-8 w-8 text-muted-foreground/40 mb-2" />
              <p className="text-sm font-medium">Comments</p>
              <p className="text-xs text-muted-foreground mt-1">Coming soon — threaded discussion for findings collaboration.</p>
            </CardContent>
          </Card>
        </TabsContent>
      </Tabs>

      <ToastStack toasts={toasts} onDismiss={dismiss} />
    </div>
  )
}
