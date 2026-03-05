import { useParams, useNavigate } from 'react-router-dom'
import { useFinding } from '@/hooks/useFindings'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { Separator } from '@/components/ui/separator'
import { ArrowLeft, ExternalLink, CheckCircle2, Shield, AlertTriangle } from 'lucide-react'
import { SeverityBadge } from '@/components/findings/SeverityBadge'
import { useTracePanel } from '@/lib/trace-panel-context'
import { useActionCooldown } from '@/hooks/useActionCooldown'

export default function FindingDetail() {
  const { id } = useParams<{ id: string }>()
  const navigate = useNavigate()
  const { data: finding, isLoading } = useFinding(id ?? '')
  const { openTimeline } = useTracePanel()
  const remediateCooldown = useActionCooldown({ key: `remediate-${id ?? ''}`, cooldownMs: 10_000 })

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
            <Badge variant="outline" className="text-[10px]">{finding.cloud_provider.toUpperCase()}</Badge>
          </div>
          <h1 className="text-xl font-semibold leading-snug">{finding.title}</h1>
          <p className="text-sm text-muted-foreground mt-1">{finding.description}</p>
        </div>
        <div className="shrink-0 flex flex-col gap-2">
          <Button
            size="sm"
            className="text-xs gap-1.5"
            disabled={!finding.auto_remediatable || !remediateCooldown.canFire}
            onClick={() => {
              if (!remediateCooldown.canFire) return
              openTimeline('Remediating: ' + finding.title, [
                {
                  span_id: 'span-rem-1',
                  name: 'remediate:' + finding.resource_name,
                  type: 'tool',
                  start_time: new Date().toISOString(),
                  end_time: new Date(Date.now() + 3200).toISOString(),
                  duration_ms: 3200,
                  status: 'ok',
                  attributes: { 'finding.id': finding.id },
                  events: [],
                  data: {},
                },
              ])
              remediateCooldown.fire()
            }}
          >
            <CheckCircle2 className="h-3.5 w-3.5" />{!remediateCooldown.canFire ? 'Running\u2026' : 'Remediate'}
          </Button>
          <Button size="sm" variant="outline" className="text-xs">Suppress</Button>
        </div>
      </div>

      <Separator />

      {/* Resource & location */}
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

      {/* CVEs */}
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
                    <span className="text-[10px]">CVSS <strong className={cve.cvss >= 9 ? 'text-red-600 dark:text-red-400' : cve.cvss >= 7 ? 'text-orange-600 dark:text-orange-400' : 'text-yellow-600 dark:text-yellow-400'}>{cve.cvss.toFixed(1)}</strong></span>
                    <span className="text-[10px]">EPSS <strong>{(cve.epss * 100).toFixed(1)}%</strong></span>
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

      {/* Compliance mappings */}
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

      {/* Remediation steps */}
      {finding.remediation_steps && finding.remediation_steps.length > 0 && (
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
      )}

      {/* Fallback if no detail data */}
      {!finding.cves?.length && !finding.compliance_mappings?.length && !finding.remediation_steps?.length && (
        <Card>
          <CardContent className="p-4">
            <p className="text-sm text-muted-foreground">{finding.remediation}</p>
          </CardContent>
        </Card>
      )}
    </div>
  )
}
