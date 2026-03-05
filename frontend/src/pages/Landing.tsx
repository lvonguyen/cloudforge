import { Link } from 'react-router-dom'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
import { Badge } from '@/components/ui/badge'
import {
  Shield, Cloud, Activity, Search, Bot, BarChart3,
  ArrowRight, GitBranch, Server,
} from 'lucide-react'

interface ProjectCard {
  name: string
  slug: string
  tier: 'flagship' | 'supporting'
  description: string
  icon: React.ElementType
  iconSvg?: string
  color: string
  bg: string
  tags: string[]
  stats: { label: string; value: string }[]
  link: string
  repo: string
}

const PROJECTS: ProjectCard[] = [
  {
    name: 'CloudForge',
    slug: 'cloudforge',
    tier: 'flagship',
    description:
      'Enterprise cloud security platform — policy-as-code provisioning, AI-powered risk scoring, automated remediation, and multi-cloud compliance across AWS, Azure, and GCP.',
    icon: Shield,
    iconSvg: '/icons/cloudforge-logo.svg',
    color: 'text-blue-600 dark:text-blue-400',
    bg: 'bg-blue-50 dark:bg-blue-900/30',
    tags: ['Go', 'OPA/Rego', 'React', 'Terraform', 'Multi-Cloud'],
    stats: [
      { label: 'Policies', value: '42' },
      { label: 'Handlers', value: '8' },
      { label: 'Test Coverage', value: '85%' },
    ],
    link: '/admin',
    repo: 'github.com/contoso/cloudforge',
  },
  {
    name: 'ThreatForge',
    slug: 'threatforge',
    tier: 'flagship',
    description:
      'Threat intelligence platform — MITRE ATT&CK mapping, real-time feed aggregation (OTX, MISP, VirusTotal), IoC correlation, and STIX/TAXII distribution.',
    icon: Search,
    iconSvg: '/icons/threatforge-logo.svg',
    color: 'text-red-600 dark:text-red-400',
    bg: 'bg-red-50 dark:bg-red-900/30',
    tags: ['Go', 'MITRE ATT&CK', 'STIX/TAXII', 'gRPC'],
    stats: [
      { label: 'TI Feeds', value: '4' },
      { label: 'ATT&CK Coverage', value: '78%' },
      { label: 'IoC Types', value: '12' },
    ],
    link: '#',
    repo: 'github.com/contoso/threatforge',
  },
  {
    name: 'CSPM Aggregator',
    slug: 'cspm-aggregator',
    tier: 'supporting',
    description:
      'Cloud Security Posture Management — normalizes findings from AWS SecurityHub, Azure Defender, and GCP SCC into a unified schema with LLM-powered contextual risk scoring.',
    icon: Cloud,
    iconSvg: '/icons/cspm-logo.svg',
    color: 'text-green-600 dark:text-green-400',
    bg: 'bg-green-50 dark:bg-green-900/30',
    tags: ['Go', 'EPSS', 'CISA KEV', 'Risk Scoring', 'Multi-Cloud'],
    stats: [
      { label: 'Finding Classes', value: '21' },
      { label: 'CSP Providers', value: '3' },
      { label: 'Edge Cases', value: '52' },
    ],
    link: '/ops/findings',
    repo: 'github.com/contoso/cspm-aggregator',
  },
  {
    name: 'Multicloud Observability',
    slug: 'multicloud-observability',
    tier: 'supporting',
    description:
      'Unified observability pipeline — collects metrics, logs, and alerts from AWS CloudWatch, Azure Monitor, and GCP Cloud Monitoring with cross-cloud alert correlation.',
    icon: Activity,
    iconSvg: '/icons/mco-logo.svg',
    color: 'text-purple-600 dark:text-purple-400',
    bg: 'bg-purple-50 dark:bg-purple-900/30',
    tags: ['Go', 'Prometheus', 'OpsGenie', 'CloudWatch', 'Stackdriver'],
    stats: [
      { label: 'Providers', value: '3' },
      { label: 'Alert Rules', value: '24' },
      { label: 'Correlation', value: 'ML' },
    ],
    link: '/ops',
    repo: 'github.com/contoso/multicloud-observability',
  },
  {
    name: 'AI Governance',
    slug: 'ai-governance',
    tier: 'supporting',
    description:
      'AI agent governance framework — STRIDE+ATLAS threat modeling, embedded OPA policy engine, agent registry, maturity assessment, and observability hooks.',
    icon: Bot,
    iconSvg: '/icons/ai-governance-logo.svg',
    color: 'text-indigo-600 dark:text-indigo-400',
    bg: 'bg-indigo-50 dark:bg-indigo-900/30',
    tags: ['Go', 'OPA', 'STRIDE', 'ATLAS', 'LLM Security'],
    stats: [
      { label: 'Threat Models', value: '2' },
      { label: 'Policy Engine', value: 'Embedded' },
      { label: 'Status', value: 'Merged to CF' },
    ],
    link: '/admin/ai-agents',
    repo: 'github.com/contoso/cloudforge',
  },
  {
    name: 'FinOps Platform',
    slug: 'finops',
    tier: 'supporting',
    description:
      'Multi-cloud cost optimization — chargeback allocation, anomaly detection, spend forecasting, and budget alerts across AWS, Azure, and GCP billing APIs.',
    icon: BarChart3,
    iconSvg: '/icons/finops-logo.svg',
    color: 'text-amber-600 dark:text-amber-400',
    bg: 'bg-amber-50 dark:bg-amber-900/30',
    tags: ['Go', 'Cost Explorer', 'Billing API', 'Forecasting'],
    stats: [
      { label: 'Cloud Accounts', value: '12' },
      { label: 'Anomaly Detection', value: 'Active' },
      { label: 'Savings Found', value: '$47K/yr' },
    ],
    link: '/ops/costs',
    repo: 'github.com/contoso/cloudforge',
  },
]

const TIER_BADGE: Record<string, string> = {
  flagship: 'bg-blue-100 text-blue-800 border-blue-200 dark:bg-blue-900/30 dark:text-blue-300 dark:border-blue-800',
  supporting: 'bg-gray-100 text-gray-700 border-gray-200 dark:bg-gray-800/50 dark:text-gray-300 dark:border-gray-700',
}

export default function Landing() {
  const flagship = PROJECTS.filter(p => p.tier === 'flagship')
  const supporting = PROJECTS.filter(p => p.tier === 'supporting')

  return (
    <div className="space-y-8 max-w-6xl mx-auto">
      {/* Header */}
      <div className="space-y-1">
        <div className="flex items-center gap-3">
          <div className="h-10 w-10 rounded-none overflow-hidden">
            <img src="/icons/cloudforge-logo.svg" alt="CloudForge" className="h-10 w-10" />
          </div>
          <div>
            <h1 className="text-xl font-semibold tracking-tight">CloudForge Portfolio</h1>
            <p className="text-sm text-muted-foreground">
              Enterprise cloud security platform — {PROJECTS.length} integrated modules
            </p>
          </div>
        </div>
      </div>

      {/* Architecture summary */}
      <div className="grid grid-cols-4 gap-3">
        {[
          { icon: Server, label: 'Multi-Cloud', value: 'AWS / Azure / GCP' },
          { icon: Shield, label: 'Policy Engine', value: 'Dual OPA (REST + Embedded)' },
          { icon: GitBranch, label: 'Language', value: 'Go + React + Terraform' },
          { icon: Activity, label: 'AI Providers', value: 'Bedrock / Vertex / Anthropic' },
        ].map(({ icon: Icon, label, value }) => (
          <Card key={label} className="border-dashed">
            <CardContent className="p-3 flex items-center gap-2.5">
              <Icon className="h-4 w-4 text-muted-foreground shrink-0" />
              <div>
                <p className="text-[10px] text-muted-foreground uppercase tracking-wide">{label}</p>
                <p className="text-xs font-medium">{value}</p>
              </div>
            </CardContent>
          </Card>
        ))}
      </div>

      {/* Flagship projects */}
      <section>
        <h2 className="text-xs font-medium uppercase tracking-wide text-muted-foreground mb-3">Tier 1 — Flagship</h2>
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
          {flagship.map(project => (
            <ProjectTile key={project.slug} project={project} />
          ))}
        </div>
      </section>

      {/* Supporting projects */}
      <section>
        <h2 className="text-xs font-medium uppercase tracking-wide text-muted-foreground mb-3">Tier 2 — Supporting Modules</h2>
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
          {supporting.map(project => (
            <ProjectTile key={project.slug} project={project} />
          ))}
        </div>
      </section>
    </div>
  )
}

function ProjectTile({ project }: { project: ProjectCard }) {
  const Icon = project.icon

  return (
    <Link to={project.link} className="group">
      <Card className="h-full transition-colors hover:border-primary/30 hover:shadow-sm">
        <CardHeader className="pb-2">
          <div className="flex items-start justify-between">
            <div className="flex items-center gap-2.5">
              <div className={`h-9 w-9 rounded-none ${project.bg} flex items-center justify-center overflow-hidden`}>
                {project.iconSvg ? (
                  <img src={project.iconSvg} alt={project.name} className="h-9 w-9" />
                ) : (
                  <Icon className={`h-4 w-4 ${project.color}`} />
                )}
              </div>
              <div>
                <CardTitle className="text-sm font-semibold">{project.name}</CardTitle>
                <span className={`text-[10px] font-medium px-1.5 py-0.5 rounded border ${TIER_BADGE[project.tier]}`}>
                  {project.tier}
                </span>
              </div>
            </div>
            {project.link === '#' ? (
              <span className="text-[10px] text-muted-foreground font-medium">Coming Soon</span>
            ) : (
              <ArrowRight className="h-4 w-4 text-muted-foreground opacity-0 group-hover:opacity-100 transition-opacity" />
            )}
          </div>
        </CardHeader>
        <CardContent className="space-y-3">
          <p className="text-xs text-muted-foreground leading-relaxed">{project.description}</p>

          {/* Tags */}
          <div className="flex flex-wrap gap-1">
            {project.tags.map(tag => (
              <Badge key={tag} variant="secondary" className="text-[10px] px-1.5 py-0">
                {tag}
              </Badge>
            ))}
          </div>

          {/* Stats */}
          <div className={`flex gap-4 pt-1 border-t ${project.link === '#' ? 'opacity-50' : ''}`}>
            {project.stats.map(({ label, value }) => (
              <div key={label}>
                <p className="text-xs font-semibold">{value}</p>
                <p className="text-[10px] text-muted-foreground">{label}</p>
              </div>
            ))}
            {project.link === '#' && (
              <div className="flex items-center ml-auto">
                <span className="text-[10px] italic text-muted-foreground">projected</span>
              </div>
            )}
          </div>
        </CardContent>
      </Card>
    </Link>
  )
}
