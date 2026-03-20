import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
import { Badge } from '@/components/ui/badge'
import { Cloud, Box, Settings, CheckCircle2, Shield, AlertTriangle, Wifi, Mail, Globe } from 'lucide-react'
import type { LucideIcon } from 'lucide-react'

interface Adapter {
  id: string
  name: string
  description: string
  icon: LucideIcon
  iconColor: string
  iconBg: string
  formats: string[]
  status: 'active' | 'available' | 'coming_soon'
  sampleFindings: number
}

const ADAPTERS: Adapter[] = [
  {
    id: 'prowler',
    name: 'Prowler',
    description: 'AWS, Azure, GCP security posture assessment. Supports CIS benchmarks, NIST, PCI-DSS, HIPAA, and custom checks.',
    icon: Cloud,
    iconColor: 'text-orange-600 dark:text-orange-400',
    iconBg: 'bg-orange-50 dark:bg-orange-950/20',
    formats: ['JSON', 'CSV', 'OCSF'],
    status: 'active',
    sampleFindings: 2340,
  },
  {
    id: 'trivy',
    name: 'Trivy',
    description: 'Container image and filesystem vulnerability scanner. Detects OS packages, language-specific packages, and IaC misconfigurations.',
    icon: Box,
    iconColor: 'text-cyan-600 dark:text-cyan-400',
    iconBg: 'bg-cyan-50 dark:bg-cyan-950/20',
    formats: ['JSON', 'SARIF', 'CycloneDX'],
    status: 'active',
    sampleFindings: 856,
  },
  {
    id: 'aws-config',
    name: 'AWS Config',
    description: 'AWS resource configuration recording and compliance evaluation. Monitors configuration changes and evaluates against rules.',
    icon: Settings,
    iconColor: 'text-amber-600 dark:text-amber-400',
    iconBg: 'bg-amber-50 dark:bg-amber-950/20',
    formats: ['JSON', 'Config Rules'],
    status: 'available',
    sampleFindings: 1120,
  },
]

interface ThreatFeed {
  id: string
  name: string
  description: string
  icon: LucideIcon
  iconColor: string
  iconBg: string
  status: 'active' | 'available'
  stat_label: string
  stat_value: string
}

const THREAT_FEEDS: ThreatFeed[] = [
  {
    id: 'epss',
    name: 'EPSS',
    description: 'Probabilistic scoring of CVE exploitability. Prioritizes patching by likelihood of exploitation in the wild.',
    icon: Shield,
    iconColor: 'text-violet-600 dark:text-violet-400',
    iconBg: 'bg-violet-50 dark:bg-violet-950/20',
    status: 'active',
    stat_label: 'CVEs scored',
    stat_value: '~200K',
  },
  {
    id: 'kev',
    name: 'CISA KEV',
    description: 'Known Exploited Vulnerabilities catalog. Actively exploited vulnerabilities mandated for federal remediation.',
    icon: AlertTriangle,
    iconColor: 'text-red-600 dark:text-red-400',
    iconBg: 'bg-red-50 dark:bg-red-950/20',
    status: 'active',
    stat_label: 'Entries',
    stat_value: '~1,100',
  },
  {
    id: 'greynoise',
    name: 'GreyNoise',
    description: 'Internet-wide scan and attack traffic analysis. Separates targeted attacks from background noise.',
    icon: Wifi,
    iconColor: 'text-slate-600 dark:text-slate-400',
    iconBg: 'bg-slate-50 dark:bg-slate-950/20',
    status: 'available',
    stat_label: 'IPs tracked',
    stat_value: '300K+',
  },
  {
    id: 'hibp',
    name: 'HIBP',
    description: 'Have I Been Pwned breach database. Email and domain exposure checking across known data breaches.',
    icon: Mail,
    iconColor: 'text-sky-600 dark:text-sky-400',
    iconBg: 'bg-sky-50 dark:bg-sky-950/20',
    status: 'available',
    stat_label: 'Breaches indexed',
    stat_value: '700+',
  },
  {
    id: 'otx',
    name: 'OTX',
    description: 'AlienVault Open Threat Exchange. Community threat intelligence with IoC sharing and pulse subscriptions.',
    icon: Globe,
    iconColor: 'text-emerald-600 dark:text-emerald-400',
    iconBg: 'bg-emerald-50 dark:bg-emerald-950/20',
    status: 'available',
    stat_label: 'Indicators',
    stat_value: '25M+',
  },
]

const STATUS_CONFIG: Record<string, { label: string; color: string }> = {
  active: { label: 'Active', color: 'bg-green-100 text-green-700 dark:bg-green-900/30 dark:text-green-300' },
  available: { label: 'Available', color: 'bg-blue-100 text-blue-700 dark:bg-blue-900/30 dark:text-blue-300' },
  coming_soon: { label: 'Coming Soon', color: 'bg-gray-100 text-gray-700 dark:bg-gray-900/30 dark:text-gray-300' },
}

export default function DataSources() {
  return (
    <div className="space-y-6 max-w-4xl">
      <div>
        <h1 className="text-xl font-semibold">Data Sources</h1>
        <p className="text-sm text-muted-foreground mt-0.5">
          Ingestion adapters for normalizing security findings from third-party scanners
        </p>
      </div>

      {/* Summary */}
      <div className="grid grid-cols-3 gap-3">
        <div className="border border-border p-3">
          <p className="text-[10px] text-muted-foreground uppercase tracking-wide">Adapters</p>
          <p className="text-lg font-semibold mt-0.5">{ADAPTERS.length}</p>
        </div>
        <div className="border border-border p-3">
          <p className="text-[10px] text-muted-foreground uppercase tracking-wide">Active</p>
          <p className="text-lg font-semibold mt-0.5 text-green-600 dark:text-green-400">
            {ADAPTERS.filter(a => a.status === 'active').length}
          </p>
        </div>
        <div className="border border-border p-3">
          <p className="text-[10px] text-muted-foreground uppercase tracking-wide">Total Findings Ingested</p>
          <p className="text-lg font-semibold mt-0.5">
            {ADAPTERS.reduce((s, a) => s + a.sampleFindings, 0).toLocaleString()}
          </p>
        </div>
      </div>

      {/* Adapter cards */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
        {ADAPTERS.map(adapter => {
          const Icon = adapter.icon
          const statusCfg = STATUS_CONFIG[adapter.status]
          return (
            <Card key={adapter.id}>
              <CardHeader className="pb-2">
                <div className="flex items-start justify-between">
                  <div className="flex items-center gap-2">
                    <div className={`p-2 rounded ${adapter.iconBg}`}>
                      <Icon className={`h-4 w-4 ${adapter.iconColor}`} />
                    </div>
                    <CardTitle className="text-sm">{adapter.name}</CardTitle>
                  </div>
                  <span className={`text-[10px] font-medium px-2 py-0.5 ${statusCfg.color}`}>
                    {statusCfg.label}
                  </span>
                </div>
              </CardHeader>
              <CardContent className="space-y-3">
                <p className="text-xs text-muted-foreground leading-relaxed">{adapter.description}</p>
                <div>
                  <p className="text-[10px] text-muted-foreground uppercase tracking-wide mb-1">Supported Formats</p>
                  <div className="flex flex-wrap gap-1">
                    {adapter.formats.map(fmt => (
                      <Badge key={fmt} variant="outline" className="text-[10px]">{fmt}</Badge>
                    ))}
                  </div>
                </div>
                <div className="flex items-center justify-between pt-2 border-t border-border">
                  <div>
                    <p className="text-[10px] text-muted-foreground">Findings ingested</p>
                    <p className="text-sm font-semibold tabular-nums">{adapter.sampleFindings.toLocaleString()}</p>
                  </div>
                  {adapter.status === 'active' && (
                    <div className="flex items-center gap-1 text-[10px] text-green-600 dark:text-green-400">
                      <CheckCircle2 className="h-3 w-3" />Connected
                    </div>
                  )}
                </div>
              </CardContent>
            </Card>
          )
        })}
      </div>

      {/* Threat Intelligence Feeds */}
      <div className="pt-4">
        <h2 className="text-lg font-semibold">Threat Intelligence Feeds</h2>
        <p className="text-sm text-muted-foreground mt-0.5">
          Real-time threat data enrichment for finding risk scoring
        </p>
      </div>

      <div className="border border-border px-3 py-2 text-sm text-muted-foreground tabular-nums">
        {THREAT_FEEDS.length} feeds{' · '}
        <span className="text-green-600 dark:text-green-400">
          {THREAT_FEEDS.filter(f => f.status === 'active').length} active
        </span>
        {' · '}
        <span className="text-blue-600 dark:text-blue-400">
          {THREAT_FEEDS.filter(f => f.status === 'available').length} pending
        </span>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
        {THREAT_FEEDS.map(feed => {
          const Icon = feed.icon
          const statusCfg = STATUS_CONFIG[feed.status]
          return (
            <Card key={feed.id}>
              <CardHeader className="pb-2">
                <div className="flex items-start justify-between">
                  <div className="flex items-center gap-2">
                    <div className={`p-2 rounded ${feed.iconBg}`}>
                      <Icon className={`h-4 w-4 ${feed.iconColor}`} />
                    </div>
                    <CardTitle className="text-sm">{feed.name}</CardTitle>
                  </div>
                  <span className={`text-[10px] font-medium px-2 py-0.5 ${statusCfg.color}`}>
                    {statusCfg.label}
                  </span>
                </div>
              </CardHeader>
              <CardContent className="space-y-3">
                <p className="text-xs text-muted-foreground leading-relaxed">{feed.description}</p>
                <div className="flex items-center justify-between pt-2 border-t border-border">
                  <div>
                    <p className="text-[10px] text-muted-foreground">{feed.stat_label}</p>
                    <p className="text-sm font-semibold tabular-nums">{feed.stat_value}</p>
                  </div>
                  {feed.status === 'active' ? (
                    <div className="flex items-center gap-1 text-[10px] text-green-600 dark:text-green-400">
                      <CheckCircle2 className="h-3 w-3" />Connected
                    </div>
                  ) : (
                    <p className="text-[10px] text-muted-foreground italic">Pending finding field enrichment</p>
                  )}
                </div>
              </CardContent>
            </Card>
          )
        })}
      </div>

      <div className="text-xs text-muted-foreground border border-border px-3 py-2">
        File upload and adapter selection for <code className="font-mono">POST /api/v1/findings/ingest</code> will be added in a future sprint.
      </div>
    </div>
  )
}
