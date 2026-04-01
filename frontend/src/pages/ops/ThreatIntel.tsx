import { useState, useMemo } from 'react'
import { useFindings } from '@/hooks/useFindings'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
import { Badge } from '@/components/ui/badge'
import { cn } from '@/lib/utils'
import {
  Shield, AlertTriangle, Wifi, Mail, Globe,
  Activity, TrendingUp, ExternalLink, type LucideIcon,
} from 'lucide-react'

type FeedId = 'overview' | 'epss' | 'kev' | 'greynoise' | 'hibp' | 'otx'

interface FeedTab {
  id: FeedId
  name: string
  icon: LucideIcon
  color: string
}

const TABS: FeedTab[] = [
  { id: 'overview', name: 'Overview', icon: Activity, color: 'text-blue-500' },
  { id: 'epss', name: 'EPSS', icon: Shield, color: 'text-violet-500' },
  { id: 'kev', name: 'CISA KEV', icon: AlertTriangle, color: 'text-red-500' },
  { id: 'greynoise', name: 'GreyNoise', icon: Wifi, color: 'text-slate-500' },
  { id: 'hibp', name: 'HIBP', icon: Mail, color: 'text-sky-500' },
  { id: 'otx', name: 'OTX', icon: Globe, color: 'text-emerald-500' },
]

export default function ThreatIntel() {
  const [activeTab, setActiveTab] = useState<FeedId>('overview')
  const { data: findings = [], total } = useFindings({ page: 1, perPage: 1000, sort: 'ai_risk', order: 'desc' })

  const stats = useMemo(() => {
    const corpusTotal = Math.max(total, findings.length)
    const sampled = corpusTotal > findings.length
    const withEpss = findings.filter((f) => f.epss && f.epss > 0)
    const withKev = findings.filter((f) => f.exploit_available)
    const withCves = findings.filter((f) => f.cves && f.cves.length > 0)
    const highEpss = withEpss.filter((f) => f.epss! >= 0.7)
    const kevCritical = withKev.filter((f) => f.severity === 'CRITICAL')

    // EPSS distribution buckets
    const epssBuckets = { low: 0, medium: 0, high: 0, critical: 0 }
    withEpss.forEach((f) => {
      const s = f.epss!
      if (s >= 0.7) epssBuckets.critical++
      else if (s >= 0.4) epssBuckets.high++
      else if (s >= 0.1) epssBuckets.medium++
      else epssBuckets.low++
    })

    return {
      sampleTotal: findings.length,
      corpusTotal,
      sampled,
      withCves: withCves.length,
      withEpss: withEpss.length,
      withKev: withKev.length,
      highEpss: highEpss.length,
      kevCritical: kevCritical.length,
      epssBuckets,
      epssFindings: [...withEpss].sort((a, b) => (b.epss ?? 0) - (a.epss ?? 0)).slice(0, 20),
      kevFindings: [...withKev].sort((a, b) => {
        const sevOrder: Record<string, number> = { CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3 }
        return (sevOrder[a.severity] ?? 4) - (sevOrder[b.severity] ?? 4)
      }).slice(0, 20),
    }
  }, [findings, total])

  return (
    <div className="space-y-6 max-w-5xl mx-auto">
      <div>
        <h1 className="text-xl font-semibold">Threat Intelligence</h1>
        <p className="text-sm text-muted-foreground mt-0.5">
          {stats.sampled
            ? `Feed status, enrichment coverage, and exploitability analysis across the top ${stats.sampleTotal.toLocaleString()} high-risk findings from ${stats.corpusTotal.toLocaleString()} total findings`
            : `Feed status, enrichment coverage, and exploitability analysis across ${stats.corpusTotal.toLocaleString()} findings`}
        </p>
        {stats.sampled && (
          <p className="text-xs text-muted-foreground mt-1">
            Feed drill-downs use a top-risk sample to keep the workspace responsive. Corpus totals still reflect the full finding set.
          </p>
        )}
      </div>

      {/* Tab bar */}
      <div className="flex gap-1 border-b border-border pb-px overflow-x-auto">
        {TABS.map((tab) => (
          <button
            key={tab.id}
            onClick={() => setActiveTab(tab.id)}
            className={cn(
              'flex items-center gap-1.5 px-3 py-2 text-sm font-medium rounded-t-md transition-colors whitespace-nowrap',
              activeTab === tab.id
                ? 'border-b-2 border-primary text-foreground bg-muted/50'
                : 'text-muted-foreground hover:text-foreground hover:bg-muted/30'
            )}
          >
            <tab.icon className={cn('h-3.5 w-3.5', activeTab === tab.id && tab.color)} />
            {tab.name}
          </button>
        ))}
      </div>

      {/* Tab content */}
      {activeTab === 'overview' && <OverviewTab stats={stats} onNavigate={setActiveTab} />}
      {activeTab === 'epss' && <EPSSTab stats={stats} />}
      {activeTab === 'kev' && <KEVTab stats={stats} />}
      {activeTab === 'greynoise' && <GreyNoiseTab />}
      {activeTab === 'hibp' && <HIBPTab />}
      {activeTab === 'otx' && <OTXTab />}
    </div>
  )
}

/* ---------- Overview ---------- */

interface TIStats {
  sampleTotal: number
  corpusTotal: number
  sampled: boolean
  withCves: number
  withEpss: number
  withKev: number
  highEpss: number
  kevCritical: number
  epssBuckets: { low: number; medium: number; high: number; critical: number }
  epssFindings: any[]
  kevFindings: any[]
}

function OverviewTab({ stats, onNavigate }: { stats: TIStats; onNavigate: (id: FeedId) => void }) {
  const sampleDenominator = stats.sampleTotal || 1
  const kpis = [
    { label: 'Findings with CVEs', value: stats.withCves, total: sampleDenominator, color: 'text-blue-600' },
    { label: 'EPSS Scored', value: stats.withEpss, total: sampleDenominator, color: 'text-violet-600' },
    { label: 'EPSS >= 0.7 (Critical)', value: stats.highEpss, total: stats.withEpss || 1, color: 'text-red-600' },
    { label: 'KEV Exploited', value: stats.withKev, total: sampleDenominator, color: 'text-amber-600' },
  ]

  const feeds = [
    { id: 'epss' as FeedId, name: 'EPSS', desc: 'Exploit Prediction Scoring System', status: 'active', coverage: stats.withEpss, icon: Shield, color: 'text-violet-500' },
    { id: 'kev' as FeedId, name: 'CISA KEV', desc: 'Known Exploited Vulnerabilities', status: 'active', coverage: stats.withKev, icon: AlertTriangle, color: 'text-red-500' },
    { id: 'greynoise' as FeedId, name: 'GreyNoise', desc: 'Internet-wide scan classification', status: 'configured', coverage: null, icon: Wifi, color: 'text-slate-500' },
    { id: 'hibp' as FeedId, name: 'HIBP', desc: 'Breach exposure monitoring', status: 'configured', coverage: null, icon: Mail, color: 'text-sky-500' },
    { id: 'otx' as FeedId, name: 'OTX', desc: 'AlienVault pulse intelligence', status: 'configured', coverage: null, icon: Globe, color: 'text-emerald-500' },
  ]

  return (
    <div className="space-y-6">
      {/* KPI row */}
      <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
        {kpis.map((kpi) => (
          <Card key={kpi.label}>
            <CardContent className="pt-4 pb-3 px-4">
              <p className="text-xs text-muted-foreground">{kpi.label}</p>
              <p className={cn('text-2xl font-semibold mt-1', kpi.color)}>
                {kpi.value.toLocaleString()}
              </p>
              <p className="text-xs text-muted-foreground mt-0.5">
                {((kpi.value / kpi.total) * 100).toFixed(1)}% of {stats.sampled ? `${kpi.total.toLocaleString()} sampled` : kpi.total.toLocaleString()}
              </p>
            </CardContent>
          </Card>
        ))}
      </div>

      {/* Feed status cards */}
      <div>
        <h2 className="text-sm font-medium mb-3">Feed Status</h2>
        <div className="grid gap-3">
          {feeds.map((feed) => (
            <button
              key={feed.id}
              onClick={() => onNavigate(feed.id)}
              className="flex items-center gap-4 p-4 rounded-lg border border-border hover:bg-muted/50 transition-colors text-left w-full"
            >
              <div className={cn('p-2 rounded-lg bg-muted/50')}>
                <feed.icon className={cn('h-5 w-5', feed.color)} />
              </div>
              <div className="flex-1 min-w-0">
                <p className="text-sm font-medium">{feed.name}</p>
                <p className="text-xs text-muted-foreground">{feed.desc}</p>
              </div>
              <div className="text-right">
                <Badge variant="outline" className={cn(
                  'text-[10px]',
                  feed.status === 'active' ? 'border-green-500/30 text-green-600 dark:text-green-400' : 'border-blue-500/30 text-blue-600 dark:text-blue-400'
                )}>
                  {feed.status === 'active' ? 'Active' : 'Per-Finding'}
                </Badge>
                {feed.coverage !== null && (
                  <p className="text-xs text-muted-foreground mt-1">{feed.coverage.toLocaleString()} findings</p>
                )}
              </div>
              <ExternalLink className="h-4 w-4 text-muted-foreground" />
            </button>
          ))}
        </div>
      </div>
    </div>
  )
}

/* ---------- EPSS ---------- */

function EPSSTab({ stats }: { stats: any }) {
  const { epssBuckets, epssFindings } = stats
  const bucketData = [
    { label: 'Critical (>=0.7)', count: epssBuckets.critical, color: 'bg-red-500', textColor: 'text-red-600' },
    { label: 'High (0.4-0.7)', count: epssBuckets.high, color: 'bg-amber-500', textColor: 'text-amber-600' },
    { label: 'Medium (0.1-0.4)', count: epssBuckets.medium, color: 'bg-yellow-500', textColor: 'text-yellow-600' },
    { label: 'Low (<0.1)', count: epssBuckets.low, color: 'bg-green-500', textColor: 'text-green-600' },
  ]
  const total = bucketData.reduce((s, b) => s + b.count, 0) || 1

  return (
    <div className="space-y-6">
      <Card>
        <CardHeader className="pb-3">
          <CardTitle className="text-sm font-medium flex items-center gap-2">
            <Shield className="h-4 w-4 text-violet-500" />
            EPSS Score Distribution
          </CardTitle>
        </CardHeader>
        <CardContent className="space-y-3">
          {bucketData.map((b) => (
            <div key={b.label} className="flex items-center gap-3">
              <span className="text-xs w-32 text-muted-foreground">{b.label}</span>
              <div className="flex-1 h-5 bg-muted rounded-full overflow-hidden">
                <div
                  className={cn('h-full rounded-full transition-all', b.color)}
                  style={{ width: `${Math.max((b.count / total) * 100, 1)}%` }}
                />
              </div>
              <span className={cn('text-sm font-medium w-12 text-right', b.textColor)}>
                {b.count}
              </span>
            </div>
          ))}
        </CardContent>
      </Card>

      <Card>
        <CardHeader className="pb-3">
          <CardTitle className="text-sm font-medium flex items-center gap-2">
            <TrendingUp className="h-4 w-4 text-red-500" />
            Top 20 by EPSS Score
          </CardTitle>
        </CardHeader>
        <CardContent>
          <FindingTable findings={epssFindings} scoreField="epss" />
        </CardContent>
      </Card>
    </div>
  )
}

/* ---------- KEV ---------- */

function KEVTab({ stats }: { stats: any }) {
  return (
    <div className="space-y-6">
      <div className="grid grid-cols-2 gap-4">
        <Card>
          <CardContent className="pt-4 pb-3 px-4">
            <p className="text-xs text-muted-foreground">Actively Exploited</p>
            <p className="text-2xl font-semibold text-red-600 mt-1">{stats.withKev}</p>
            <p className="text-xs text-muted-foreground mt-0.5">findings in CISA KEV catalog</p>
          </CardContent>
        </Card>
        <Card>
          <CardContent className="pt-4 pb-3 px-4">
            <p className="text-xs text-muted-foreground">KEV + CRITICAL</p>
            <p className="text-2xl font-semibold text-red-600 mt-1">{stats.kevCritical}</p>
            <p className="text-xs text-muted-foreground mt-0.5">highest priority for remediation</p>
          </CardContent>
        </Card>
      </div>

      <Card>
        <CardHeader className="pb-3">
          <CardTitle className="text-sm font-medium flex items-center gap-2">
            <AlertTriangle className="h-4 w-4 text-red-500" />
            Known Exploited Vulnerabilities — Top 20
          </CardTitle>
        </CardHeader>
        <CardContent>
          <FindingTable findings={stats.kevFindings} scoreField="exploit" />
        </CardContent>
      </Card>
    </div>
  )
}

/* ---------- GreyNoise / HIBP / OTX (per-finding enrichment) ---------- */

function GreyNoiseTab() {
  return <PerFindingFeedCard name="GreyNoise" icon={Wifi} color="text-slate-500" description="GreyNoise classifies IPs observed scanning the internet. Enrichment runs per-finding when an IP is associated with a finding. Classifications: malicious, benign, or unknown." stat="300K+ IPs tracked" envVar="GREYNOISE_API_KEY" />
}

function HIBPTab() {
  return <PerFindingFeedCard name="Have I Been Pwned" icon={Mail} color="text-sky-500" description="HIBP checks email addresses and domains against known data breaches. Enrichment runs per-finding when an email or domain is present in the finding context." stat="700+ breaches indexed" envVar="HIBP_API_KEY" />
}

function OTXTab() {
  return <PerFindingFeedCard name="AlienVault OTX" icon={Globe} color="text-emerald-500" description="OTX provides community-contributed threat intelligence pulses. Enrichment queries indicators (IPs, domains, hashes) from finding context against OTX pulse database." stat="25M+ indicators" envVar="OTX_API_KEY" />
}

function PerFindingFeedCard({ name, icon: Icon, color, description, stat, envVar }: {
  name: string; icon: LucideIcon; color: string; description: string; stat: string; envVar: string
}) {
  return (
    <div className="space-y-4">
      <Card>
        <CardContent className="pt-6 pb-4 px-6">
          <div className="flex items-start gap-4">
            <div className="p-3 rounded-lg bg-muted/50">
              <Icon className={cn('h-6 w-6', color)} />
            </div>
            <div className="flex-1">
              <h3 className="font-medium">{name}</h3>
              <p className="text-sm text-muted-foreground mt-1">{description}</p>
              <div className="flex gap-4 mt-4">
                <div>
                  <p className="text-xs text-muted-foreground">Coverage</p>
                  <p className="text-sm font-medium">{stat}</p>
                </div>
                <div>
                  <p className="text-xs text-muted-foreground">Enrichment</p>
                  <p className="text-sm font-medium">Per-finding (on demand)</p>
                </div>
                <div>
                  <p className="text-xs text-muted-foreground">API Key</p>
                  <Badge variant="outline" className="text-[10px]">{envVar}</Badge>
                </div>
              </div>
            </div>
          </div>
        </CardContent>
      </Card>
      <Card>
        <CardContent className="pt-6 pb-4 px-6 text-center text-muted-foreground">
          <Icon className="h-8 w-8 mx-auto mb-2 opacity-30" />
          <p className="text-sm">Enrichment results are shown on individual finding detail pages.</p>
          <p className="text-xs mt-1">Navigate to a finding and click &quot;Enrich&quot; to query {name}.</p>
        </CardContent>
      </Card>
    </div>
  )
}

/* ---------- Shared finding table ---------- */

function FindingTable({ findings, scoreField }: { findings: any[]; scoreField: 'epss' | 'exploit' }) {
  if (!findings.length) {
    return <p className="text-sm text-muted-foreground py-4 text-center">No findings with this enrichment data.</p>
  }

  const sevColor: Record<string, string> = {
    CRITICAL: 'bg-red-100 text-red-700 dark:bg-red-900/30 dark:text-red-300',
    HIGH: 'bg-amber-100 text-amber-700 dark:bg-amber-900/30 dark:text-amber-300',
    MEDIUM: 'bg-yellow-100 text-yellow-700 dark:bg-yellow-900/30 dark:text-yellow-300',
    LOW: 'bg-green-100 text-green-700 dark:bg-green-900/30 dark:text-green-300',
  }

  return (
    <div className="overflow-x-auto">
      <table className="w-full text-sm">
        <thead>
          <tr className="border-b border-border text-xs text-muted-foreground">
            <th className="text-left py-2 pr-3 font-medium">Finding</th>
            <th className="text-left py-2 pr-3 font-medium">Severity</th>
            <th className="text-left py-2 pr-3 font-medium">Resource</th>
            {scoreField === 'epss' && <th className="text-right py-2 font-medium">EPSS</th>}
            {scoreField === 'exploit' && <th className="text-right py-2 font-medium">Status</th>}
          </tr>
        </thead>
        <tbody>
          {findings.map((f: any) => (
            <tr key={f.id} className="border-b border-border/50 hover:bg-muted/30">
              <td className="py-2 pr-3">
                <a href={`/ops/findings/${f.id}`} className="text-primary hover:underline font-mono text-xs">
                  {f.id}
                </a>
                <p className="text-xs text-muted-foreground truncate max-w-[300px]">{f.title}</p>
              </td>
              <td className="py-2 pr-3">
                <Badge className={cn('text-[10px]', sevColor[f.severity])}>{f.severity}</Badge>
              </td>
              <td className="py-2 pr-3 text-xs text-muted-foreground truncate max-w-[200px]">
                {f.resource_id || f.resource_type || '—'}
              </td>
              {scoreField === 'epss' && (
                <td className="py-2 text-right font-mono text-xs">
                  <span className={cn(
                    'font-medium',
                    f.epss >= 0.7 ? 'text-red-600' : f.epss >= 0.4 ? 'text-amber-600' : 'text-muted-foreground'
                  )}>
                    {(f.epss * 100).toFixed(1)}%
                  </span>
                </td>
              )}
              {scoreField === 'exploit' && (
                <td className="py-2 text-right">
                  <Badge className="text-[10px] bg-red-100 text-red-700 dark:bg-red-900/30 dark:text-red-300">
                    Exploited
                  </Badge>
                </td>
              )}
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  )
}
