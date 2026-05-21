import { Link } from 'react-router-dom'
import {
  Activity,
  AlertTriangle,
  CheckCircle2,
  Database,
  ExternalLink,
  FileWarning,
  KeyRound,
  LockKeyhole,
  Network,
  Server,
  ShieldCheck,
  Workflow,
} from 'lucide-react'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
import { cn } from '@/lib/utils'

const readinessKpis = [
  { label: 'CUI-scoped systems', value: '19', detail: '7 production', tone: 'text-blue-600 dark:text-blue-400' },
  { label: 'Gov evidence gaps', value: '27', detail: '11 high priority', tone: 'text-amber-600 dark:text-amber-400' },
  { label: 'Artifact gates', value: '86%', detail: 'restricted-label coverage', tone: 'text-emerald-600 dark:text-emerald-400' },
  { label: 'Audit retention', value: '92%', detail: 'immutable log paths', tone: 'text-violet-600 dark:text-violet-400' },
]

const lanes = [
  {
    name: 'Cloud Boundary',
    status: 'Mapped',
    icon: Server,
    body: 'AWS commercial, AWS GovCloud, Azure commercial, and GCC High target zones are modeled as separate evidence boundaries.',
    checks: ['region allowlists', 'service catalog scope', 'account owner tags'],
  },
  {
    name: 'CUI / Export Labels',
    status: 'Needs tuning',
    icon: LockKeyhole,
    body: 'Synthetic CUI and export-control labels drive object storage, build artifact, and collaboration upload guardrails.',
    checks: ['data_classification tags', 'artifact release gates', 'commercial SaaS upload deny rules'],
  },
  {
    name: 'Evidence Collection',
    status: 'Operational',
    icon: FileWarning,
    body: 'Control evidence is generated from cloud state, tickets, scan output, and remediation workflow events.',
    checks: ['audit log integrity', 'ticket linkage', 'scan recency'],
  },
  {
    name: 'Developer Flow',
    status: 'Protected',
    icon: Workflow,
    body: 'CI/CD guardrails enforce policy checks without blocking low-risk engineering changes from moving quickly.',
    checks: ['IaC policy checks', 'secret scanning', 'break-glass approval trail'],
  },
]

const syntheticFindings = [
  {
    severity: 'HIGH',
    title: 'Bastion security group permits internet SSH',
    asset: 'admin-bastion-sg',
    mapping: 'CMMC AC.L2-3.1.1 / FedRAMP AC-4',
    action: 'Restrict to VPN/ZTNA CIDRs and require session logging.',
  },
  {
    severity: 'HIGH',
    title: 'Prototype artifact bucket lacks enforced KMS policy',
    asset: 'prototype-artifacts-prod',
    mapping: 'NIST 800-171 03.13.11 / FedRAMP SC-28',
    action: 'Enforce CMK, public-access block, and object-level audit logs.',
  },
  {
    severity: 'MEDIUM',
    title: 'Commercial CI artifact missing restricted-label gate',
    asset: 'deploy-autonomy-sim',
    mapping: 'ITAR/EAR Boundary EXP-01',
    action: 'Add classifier, release approver, and label-aware retention rule.',
  },
  {
    severity: 'MEDIUM',
    title: 'CloudTrail log validation missing in one mission account',
    asset: 'aws-mission-sandbox',
    mapping: 'FedRAMP AU-9 / CMMC AU.L2-3.3.1',
    action: 'Enable org trail validation and immutable central retention.',
  },
]

const talkTrack = [
  'I built CloudForge as a synthetic cloud readiness dashboard for fast-moving engineering teams that still need defensible security evidence.',
  'The defense lane is deliberately careful: it maps CMMC, NIST 800-171, FedRAMP, and export-control-style concerns without claiming certification or real controlled-data handling.',
  'The value is translating vague compliance pressure into practical engineering work: identity cleanup, logging guarantees, artifact controls, tagging, and CI/CD guardrails.',
]

const severityTone: Record<string, string> = {
  HIGH: 'border-amber-500/40 text-amber-700 dark:text-amber-300',
  MEDIUM: 'border-blue-500/40 text-blue-700 dark:text-blue-300',
}

export default function DefenseReadiness() {
  return (
    <div className="mx-auto max-w-6xl space-y-6">
      <div className="flex flex-col gap-3 lg:flex-row lg:items-start lg:justify-between">
        <div>
          <div className="flex flex-wrap items-center gap-2">
            <h1 className="text-xl font-semibold">Defense Readiness</h1>
            <Badge variant="outline" className="border-blue-500/30 text-blue-700 dark:text-blue-300">
              Synthetic demo
            </Badge>
            <Badge variant="outline" className="border-amber-500/30 text-amber-700 dark:text-amber-300">
              Not a certification claim
            </Badge>
          </div>
          <p className="mt-1 max-w-3xl text-sm text-muted-foreground">
            Gov-cloud and CUI-inspired control evidence for a defense-adjacent startup scenario. Demo data does not include classified, CUI, ITAR-controlled, customer, or government data.
          </p>
        </div>
        <div className="flex flex-wrap gap-2">
          <Button asChild variant="outline" size="sm">
            <Link to="/ops/compliance">
              <ShieldCheck className="mr-1.5 h-3.5 w-3.5" />
              Compliance
            </Link>
          </Button>
          <Button asChild variant="outline" size="sm">
            <Link to="/ops/threat-intel">
              <Activity className="mr-1.5 h-3.5 w-3.5" />
              Threat Intel
            </Link>
          </Button>
        </div>
      </div>

      <div className="grid grid-cols-2 gap-4 lg:grid-cols-4">
        {readinessKpis.map((kpi) => (
          <Card key={kpi.label}>
            <CardContent className="p-4">
              <p className="text-xs text-muted-foreground">{kpi.label}</p>
              <p className={cn('mt-1 text-2xl font-semibold tabular-nums', kpi.tone)}>{kpi.value}</p>
              <p className="mt-0.5 text-xs text-muted-foreground">{kpi.detail}</p>
            </CardContent>
          </Card>
        ))}
      </div>

      <div className="grid gap-4 lg:grid-cols-[1.2fr_0.8fr]">
        <Card>
          <CardHeader className="pb-3">
            <CardTitle className="flex items-center gap-2 text-sm">
              <Network className="h-4 w-4 text-blue-500" />
              Readiness Lanes
            </CardTitle>
          </CardHeader>
          <CardContent className="grid gap-3 md:grid-cols-2">
            {lanes.map((lane) => (
              <div key={lane.name} className="border border-border p-4">
                <div className="flex items-center gap-3">
                  <lane.icon className="h-4 w-4 text-muted-foreground" />
                  <div className="min-w-0 flex-1">
                    <p className="text-sm font-medium">{lane.name}</p>
                    <p className="text-xs text-muted-foreground">{lane.status}</p>
                  </div>
                  <CheckCircle2 className="h-4 w-4 text-emerald-500" />
                </div>
                <p className="mt-3 text-xs leading-relaxed text-muted-foreground">{lane.body}</p>
                <div className="mt-3 flex flex-wrap gap-1.5">
                  {lane.checks.map((check) => (
                    <Badge key={check} variant="secondary" className="text-[10px]">
                      {check}
                    </Badge>
                  ))}
                </div>
              </div>
            ))}
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="pb-3">
            <CardTitle className="flex items-center gap-2 text-sm">
              <KeyRound className="h-4 w-4 text-amber-500" />
              Interview Talk Track
            </CardTitle>
          </CardHeader>
          <CardContent className="space-y-3">
            {talkTrack.map((item, index) => (
              <div key={item} className="flex gap-3">
                <span className="flex h-6 w-6 shrink-0 items-center justify-center border border-border text-xs font-semibold tabular-nums">
                  {index + 1}
                </span>
                <p className="text-sm leading-relaxed text-muted-foreground">{item}</p>
              </div>
            ))}
          </CardContent>
        </Card>
      </div>

      <Card>
        <CardHeader className="pb-3">
          <CardTitle className="flex items-center gap-2 text-sm">
            <AlertTriangle className="h-4 w-4 text-amber-500" />
            Synthesized Defense Findings
          </CardTitle>
        </CardHeader>
        <CardContent className="overflow-x-auto p-0">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-border text-xs text-muted-foreground">
                <th className="px-4 py-2 text-left font-medium">Severity</th>
                <th className="px-4 py-2 text-left font-medium">Finding</th>
                <th className="px-4 py-2 text-left font-medium">Mapped Evidence</th>
                <th className="px-4 py-2 text-left font-medium">Next Action</th>
              </tr>
            </thead>
            <tbody>
              {syntheticFindings.map((finding) => (
                <tr key={finding.title} className="border-b border-border/60 last:border-b-0">
                  <td className="px-4 py-3 align-top">
                    <Badge variant="outline" className={cn('text-[10px]', severityTone[finding.severity])}>
                      {finding.severity}
                    </Badge>
                  </td>
                  <td className="px-4 py-3 align-top">
                    <p className="font-medium">{finding.title}</p>
                    <p className="mt-0.5 font-mono text-xs text-muted-foreground">{finding.asset}</p>
                  </td>
                  <td className="px-4 py-3 align-top text-xs text-muted-foreground">{finding.mapping}</td>
                  <td className="px-4 py-3 align-top text-xs text-muted-foreground">{finding.action}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </CardContent>
      </Card>

      <Card>
        <CardContent className="flex flex-col gap-3 p-4 md:flex-row md:items-center md:justify-between">
          <div className="flex items-start gap-3">
            <Database className="mt-0.5 h-4 w-4 text-muted-foreground" />
            <div>
              <p className="text-sm font-medium">Safe language guardrail</p>
              <p className="text-xs text-muted-foreground">
                CloudForge models defense-adjacent readiness patterns with synthetic data. Compliance references are control mappings, not legal determinations.
              </p>
            </div>
          </div>
          <Button asChild variant="ghost" size="sm">
            <a href="https://github.com/lvonguyen/cloudforge/blob/main/docs/core/architecture/defense-readiness.md" target="_blank" rel="noreferrer">
              Docs
              <ExternalLink className="ml-1.5 h-3.5 w-3.5" />
            </a>
          </Button>
        </CardContent>
      </Card>
    </div>
  )
}
