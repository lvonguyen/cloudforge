import { Link } from 'react-router-dom'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import {
  Shield, Cloud, Activity,
  ArrowRight, GitBranch, Server, Eye, Copy, Check,
} from 'lucide-react'
import { useState, useCallback } from 'react'
import { branding } from '@/lib/branding'
import { useAuth } from '@/lib/auth'

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
    name: branding.productName,
    slug: 'aegis',
    tier: 'flagship',
    description:
      'Enterprise cloud security platform — policy-as-code provisioning, AI-powered risk scoring, automated remediation, and multi-cloud compliance across AWS, Azure, and GCP.',
    icon: Shield,
    iconSvg: branding.logoPath,
    color: 'text-blue-600 dark:text-blue-400',
    bg: 'bg-blue-50 dark:bg-blue-900/30',
    tags: ['Go', 'OPA/Rego', 'React', 'Terraform', 'Multi-Cloud'],
    stats: [
      { label: 'Go Tests', value: '1,474' },
      { label: 'Frontend Tests', value: '420' },
      { label: 'Go Packages', value: '34' },
    ],
    link: '/admin',
    repo: `${branding.repoPrefix}/aegis`,
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
    repo: `${branding.repoPrefix}/cspm-aggregator`,
  },
]

export default function Landing() {
  // Filter projects by enabled modules from branding config
  const visibleProjects = PROJECTS.filter(p => branding.enabledModules.includes(p.slug))
  const flagship = visibleProjects.filter(p => p.tier === 'flagship')
  const supporting = visibleProjects.filter(p => p.tier === 'supporting')

  return (
    <div className="space-y-8 max-w-6xl mx-auto">
      {/* Header */}
      <div className="space-y-1">
        <div className="flex items-center gap-3">
          <div className="h-10 w-10 rounded-none overflow-hidden">
            <img src={branding.logoPath} alt={branding.productName} className="h-10 w-10" width={40} height={40} />
          </div>
          <div>
            <h1 className="text-xl font-semibold tracking-tight">{branding.productName} Platform</h1>
            <p className="text-sm text-muted-foreground">
              Enterprise cloud security platform — {visibleProjects.length} integrated module{visibleProjects.length !== 1 ? 's' : ''}
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
      {flagship.length > 0 && (
        <section>
          <h2 className="text-xs font-medium uppercase tracking-wide text-muted-foreground mb-3">Operational Modules</h2>
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
            {flagship.map(project => (
              <ProjectTile key={project.slug} project={project} />
            ))}
          </div>
        </section>
      )}

      {/* Supporting projects */}
      {supporting.length > 0 && (
        <section>
          <h2 className="text-xs font-medium uppercase tracking-wide text-muted-foreground mb-3">Supporting Modules</h2>
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
            {supporting.map(project => (
              <ProjectTile key={project.slug} project={project} />
            ))}
          </div>
        </section>
      )}

      {/* Demo Viewer Access */}
      {branding.demoAccess.enabled && <DemoAccessCard />}
    </div>
  )
}

function CopyButton({ value }: { value: string }) {
  const [copied, setCopied] = useState(false)

  const copy = useCallback(() => {
    navigator.clipboard.writeText(value)
    setCopied(true)
    setTimeout(() => setCopied(false), 2000)
  }, [value])

  return (
    <button
      onClick={copy}
      className="ml-2 p-0.5 rounded hover:bg-muted-foreground/10 transition-colors"
      title="Copy to clipboard"
    >
      {copied ? <Check className="h-3 w-3 text-green-500" /> : <Copy className="h-3 w-3 text-muted-foreground" />}
    </button>
  )
}

function DemoAccessCard() {
  const { loginAsDemo } = useAuth()
  const { email, password } = branding.demoAccess

  return (
    <section>
      <h2 className="text-xs font-medium uppercase tracking-wide text-muted-foreground mb-3">Demo Access</h2>
      <Card className="border-dashed border-blue-200 dark:border-blue-800 bg-blue-50/50 dark:bg-blue-950/20">
        <CardContent className="p-5">
          <div className="flex items-start gap-4">
            <div className="h-10 w-10 rounded-lg bg-blue-100 dark:bg-blue-900/40 flex items-center justify-center shrink-0">
              <Eye className="h-5 w-5 text-blue-600 dark:text-blue-400" />
            </div>
            <div className="flex-1 space-y-3">
              <div>
                <h3 className="text-sm font-semibold">Demo Viewer</h3>
                <p className="text-xs text-muted-foreground mt-0.5">
                  Read-only access via Okta SSO — explore findings, compliance dashboards, and AI agents.
                </p>
              </div>

              {/* Credentials */}
              {email && (
                <div className="bg-background border rounded-md p-3 space-y-1.5 font-mono text-xs">
                  <div className="flex items-center">
                    <span className="text-muted-foreground w-16">Email</span>
                    <span className="font-medium">{email}</span>
                    <CopyButton value={email} />
                  </div>
                  {password && (
                    <div className="flex items-center">
                      <span className="text-muted-foreground w-16">Password</span>
                      <span className="font-medium">{password}</span>
                      <CopyButton value={password} />
                    </div>
                  )}
                </div>
              )}

              <Button size="sm" onClick={() => loginAsDemo()} className="gap-1.5">
                <Shield className="h-3.5 w-3.5" />
                Sign in as Demo Viewer
              </Button>
            </div>
          </div>
        </CardContent>
      </Card>
    </section>
  )
}

function ProjectTile({ project }: { project: ProjectCard }) {
  const Icon = project.icon

  return (
    <Link to={project.link} className="group">
      <Card className="h-full min-h-[220px] transition-colors hover:border-primary/30 hover:shadow-sm">
        <CardHeader className="pb-2">
          <div className="flex items-start justify-between">
            <div className="flex items-center gap-2.5">
              <div className={`h-9 w-9 rounded-none ${project.bg} flex items-center justify-center overflow-hidden`}>
                {project.iconSvg ? (
                  <img
                    src={project.iconSvg}
                    alt={project.name}
                    className="h-9 w-9"
                    width={36}
                    height={36}
                    loading="lazy"
                    onError={e => { (e.target as HTMLImageElement).style.display = 'none'; (e.target as HTMLImageElement).nextElementSibling?.classList.remove('hidden') }}
                  />
                ) : null}
                <Icon className={`h-4 w-4 ${project.color}${project.iconSvg ? ' hidden' : ''}`} />
              </div>
              <div>
                <CardTitle className="text-sm font-semibold">{project.name}</CardTitle>
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
