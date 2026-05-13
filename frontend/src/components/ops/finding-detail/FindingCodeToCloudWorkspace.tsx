import {
  ArrowRight,
  GitBranch,
  Package,
  Rocket,
  Server,
  ShieldAlert,
  Workflow,
} from 'lucide-react'
import { branding } from '@/lib/branding'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
import type { AttackPath } from '@/types/attack-path'
import type { Finding } from '@/types/compliance'

interface FindingCodeToCloudWorkspaceProps {
  finding: Finding
  codeToCloud?: FindingCodeToCloudContext
  relatedPaths: AttackPath[]
  onOpenInvestigation: () => void
}

interface FindingCodeToCloudContext {
  repository_url?: string
  repository_name?: string
  repository_provider?: string
  branch?: string
  commit_sha?: string
  build_system?: string
  pipeline_name?: string
  pipeline_run_id?: string
  pipeline_run_url?: string
  artifact?: string
}

interface DeliveryStage {
  id: string
  label: string
  title: string
  detail: string
  inferred: boolean
  icon: typeof GitBranch
}

function slugify(value: string | undefined): string {
  return (value ?? '')
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, '-')
    .replace(/^-+|-+$/g, '') || 'service'
}

function formatValue(value: string | undefined): string {
  if (!value) return 'Unknown'
  return value
}

function deriveArtifactLabel(finding: Finding): string {
  switch (finding.resource_type) {
    case 'container':
      return `${finding.service_name} container image`
    case 'serverless':
      return `${finding.service_name} function bundle`
    case 'database':
      return `${finding.service_name} schema or access change`
    case 'identity':
      return `${finding.service_name} IAM policy package`
    default:
      return `${finding.service_name} deployable artifact`
  }
}

function deriveBuildFocus(finding: Finding): string {
  if (finding.remediation_steps?.[0]?.title) return finding.remediation_steps[0].title
  if (finding.remediation) return finding.remediation
  return 'Patch, scan, and redeploy through the standard release path.'
}

function deriveLikelyRepo(finding: Finding): string {
  const repoName = slugify(finding.service_name || finding.application || finding.resource_name)
  return `${branding.repoPrefix}/${repoName}`
}

function readFindingTag(tags: Record<string, string> | undefined, keys: string[]): string | undefined {
  if (!tags) return undefined
  const lookup = new Set(keys.map((key) => key.toLowerCase()))
  for (const [key, value] of Object.entries(tags)) {
    if (lookup.has(key.toLowerCase()) && value) return value
  }
  return undefined
}

function hasDirectRepositoryContext(codeToCloud: FindingCodeToCloudContext | undefined): boolean {
  return Boolean(
    codeToCloud?.repository_url ||
    codeToCloud?.repository_name ||
    codeToCloud?.branch ||
    codeToCloud?.commit_sha,
  )
}

function hasDirectBuildContext(codeToCloud: FindingCodeToCloudContext | undefined): boolean {
  return Boolean(
    codeToCloud?.build_system ||
    codeToCloud?.pipeline_name ||
    codeToCloud?.pipeline_run_id ||
    codeToCloud?.pipeline_run_url ||
    codeToCloud?.artifact,
  )
}

function formatCommit(value: string | undefined): string | undefined {
  if (!value) return undefined
  return value.length > 12 ? value.slice(0, 12) : value
}

function joinDetail(parts: Array<string | undefined>): string {
  return parts.filter(Boolean).join(' · ')
}

function deriveCodeToCloudFromTags(finding: Finding): FindingCodeToCloudContext | undefined {
  const fromTags: FindingCodeToCloudContext = {
    repository_url: readFindingTag(finding.tags, [
      'repository_url', 'repo_url', 'repository', 'repo', 'scm_url', 'git_repository',
      'git_url', 'github_repository', 'gitlab_repository',
    ]),
    repository_name: readFindingTag(finding.tags, [
      'repository_name', 'repo_name', 'service_repo', 'service_repository',
    ]),
    repository_provider: readFindingTag(finding.tags, [
      'repository_provider', 'repo_provider', 'scm_provider', 'git_provider',
    ]),
    branch: readFindingTag(finding.tags, [
      'branch', 'git_branch', 'repository_branch', 'repo_branch', 'workflow_branch',
    ]),
    commit_sha: readFindingTag(finding.tags, [
      'commit_sha', 'git_commit', 'commit', 'sha', 'revision', 'git_revision',
    ]),
    build_system: readFindingTag(finding.tags, [
      'build_system', 'ci_system', 'cicd', 'pipeline_system', 'workflow_system',
    ]),
    pipeline_name: readFindingTag(finding.tags, [
      'pipeline_name', 'pipeline', 'workflow', 'workflow_name', 'build_pipeline',
    ]),
    pipeline_run_id: readFindingTag(finding.tags, [
      'pipeline_run_id', 'run_id', 'workflow_run_id', 'build_id', 'pipeline_execution_id',
    ]),
    pipeline_run_url: readFindingTag(finding.tags, [
      'pipeline_run_url', 'pipeline_url', 'run_url', 'workflow_url', 'build_url',
    ]),
    artifact: readFindingTag(finding.tags, [
      'artifact', 'artifact_name', 'image', 'image_uri', 'container_image', 'build_artifact',
    ]),
  }

  if (!hasDirectRepositoryContext(fromTags) && !hasDirectBuildContext(fromTags)) return undefined
  return fromTags
}

function deriveOperatorNextMove(finding: Finding, relatedPaths: AttackPath[]): string {
  if (relatedPaths[0]) {
    return `Confirm the last delivery for ${finding.service_name}, then validate whether the linked path from ${relatedPaths[0].entry_point.resource_name} to ${relatedPaths[0].target.resource_name} is still live before remediation starts.`
  }
  return `Validate the most recent delivery for ${finding.service_name}, confirm the deployed configuration in ${finding.region}, and only then execute the remediation plan.`
}

export function FindingCodeToCloudWorkspace({
  finding,
  codeToCloud,
  relatedPaths,
  onOpenInvestigation,
}: FindingCodeToCloudWorkspaceProps) {
  const resolvedCodeToCloud = {
    ...(deriveCodeToCloudFromTags(finding) ?? {}),
    ...(codeToCloud ?? {}),
  }
  const directRepository = hasDirectRepositoryContext(resolvedCodeToCloud)
  const directBuild = hasDirectBuildContext(resolvedCodeToCloud)
  const likelyRepo = resolvedCodeToCloud.repository_name || resolvedCodeToCloud.repository_url || deriveLikelyRepo(finding)
  const linkedPath = relatedPaths[0]
  const linkedTargets = Array.from(new Set(relatedPaths.map((path) => path.target.resource_name))).slice(0, 3)
  const stages: DeliveryStage[] = [
    {
      id: 'repo',
      label: 'Source repo',
      title: likelyRepo,
      detail: directRepository
        ? joinDetail([
            resolvedCodeToCloud.repository_provider,
            resolvedCodeToCloud.branch ? `branch ${resolvedCodeToCloud.branch}` : undefined,
            resolvedCodeToCloud.commit_sha ? `commit ${formatCommit(resolvedCodeToCloud.commit_sha)}` : undefined,
          ]) || `Attached CI/CD repository context for ${finding.service_name}`
        : `Likely service repository for ${finding.service_name}`,
      inferred: !directRepository,
      icon: GitBranch,
    },
    {
      id: 'build',
      label: 'Build lane',
      title: resolvedCodeToCloud.pipeline_name || resolvedCodeToCloud.artifact || deriveArtifactLabel(finding),
      detail: directBuild
        ? joinDetail([
            resolvedCodeToCloud.build_system,
            resolvedCodeToCloud.pipeline_run_id ? `run ${resolvedCodeToCloud.pipeline_run_id}` : undefined,
            resolvedCodeToCloud.artifact,
          ]) || 'Attached CI/CD pipeline context'
        : deriveBuildFocus(finding),
      inferred: !directBuild,
      icon: Package,
    },
    {
      id: 'deploy',
      label: 'Deployment',
      title: `${finding.cloud_provider.toUpperCase()} ${finding.environment_type}`,
      detail: `${formatValue(finding.account_name ?? finding.account_id)} · ${finding.region}`,
      inferred: false,
      icon: Rocket,
    },
    {
      id: 'runtime',
      label: 'Runtime asset',
      title: finding.resource_name,
      detail: `${finding.resource_type.replace(/_/g, ' ')} · ${formatValue(finding.application ?? finding.line_of_business)}`,
      inferred: false,
      icon: Server,
    },
    {
      id: 'finding',
      label: 'Security signal',
      title: finding.title,
      detail: `${finding.severity} · ${finding.workflow_status.replace(/_/g, ' ')}`,
      inferred: false,
      icon: ShieldAlert,
    },
  ]

  return (
    <div className="space-y-6">
      <Card>
        <CardHeader className="pb-3">
          <CardTitle className="text-xs font-medium uppercase tracking-wide text-muted-foreground">
            <div className="flex items-center gap-1.5">
              <GitBranch className="h-3.5 w-3.5" />
              Code to Cloud Context
            </div>
          </CardTitle>
        </CardHeader>
        <CardContent className="space-y-4">
          <div className="rounded-2xl border border-border/80 bg-muted/20 p-4">
            <p className="text-[10px] font-semibold uppercase tracking-wide text-muted-foreground">
              Likely delivery path
            </p>
            <p className="mt-2 text-sm text-muted-foreground">
              {directRepository || directBuild
                ? 'Repository and build stages come from attached provenance metadata when present. Runtime asset and cloud scope remain direct from the finding itself.'
                : 'Runtime asset and cloud scope are direct from the finding. Source repo and build lane stay explicitly marked as inferred until the backend attaches CI/CD provenance.'}
            </p>
          </div>

          <div className="overflow-x-auto rounded-2xl border border-border/80 bg-background/90 p-3">
            <div className="flex min-w-max items-stretch gap-2">
              {stages.map((stage, index) => {
                const StageIcon = stage.icon
                return (
                  <div key={stage.id} className="flex items-center gap-2">
                    <div className="w-[13.5rem] rounded-2xl border border-border/80 bg-muted/20 p-3">
                      <div className="flex items-center justify-between gap-2">
                        <div className="flex items-center gap-2 text-[10px] font-semibold uppercase tracking-wide text-muted-foreground">
                          <StageIcon className="h-3.5 w-3.5" />
                          {stage.label}
                        </div>
                        <Badge variant="outline" className="text-[10px]">
                          {stage.inferred ? 'Inferred' : 'Direct'}
                        </Badge>
                      </div>
                      <p className="mt-2 text-sm font-semibold break-all">{stage.title}</p>
                      <p className="mt-1 text-xs text-muted-foreground">{stage.detail}</p>
                    </div>
                    {index < stages.length - 1 && (
                      <ArrowRight className="h-4 w-4 shrink-0 text-muted-foreground" />
                    )}
                  </div>
                )
              })}
            </div>
          </div>

          <div className="grid gap-4 lg:grid-cols-[minmax(0,1.15fr)_minmax(18rem,0.85fr)]">
            <Card className="border-border/80">
              <CardHeader className="pb-2">
                <CardTitle className="text-xs font-medium uppercase tracking-wide text-muted-foreground">
                  Delivery Notes
                </CardTitle>
              </CardHeader>
              <CardContent className="space-y-3 text-sm">
                <div className="rounded-2xl border border-border/80 bg-muted/20 p-3">
                  <p className="text-[10px] font-semibold uppercase tracking-wide text-muted-foreground">
                    Service anchor
                  </p>
                  <p className="mt-1 font-medium">{finding.service_name}</p>
                  <p className="text-xs text-muted-foreground">
                    {formatValue(finding.application ?? finding.line_of_business)} · {finding.cloud_provider.toUpperCase()} · {finding.region}
                  </p>
                </div>
                <div className="rounded-2xl border border-border/80 bg-muted/20 p-3">
                  <p className="text-[10px] font-semibold uppercase tracking-wide text-muted-foreground">
                    Build focus
                  </p>
                  <p className="mt-1 text-xs text-muted-foreground">
                    {directBuild
                      ? joinDetail([
                          resolvedCodeToCloud.pipeline_name,
                          resolvedCodeToCloud.pipeline_run_id ? `Run ${resolvedCodeToCloud.pipeline_run_id}` : undefined,
                          resolvedCodeToCloud.pipeline_run_url,
                        ]) || deriveBuildFocus(finding)
                      : deriveBuildFocus(finding)}
                  </p>
                </div>
                <div className="rounded-2xl border border-border/80 bg-muted/20 p-3">
                  <p className="text-[10px] font-semibold uppercase tracking-wide text-muted-foreground">
                    {directRepository || directBuild ? 'Provenance source' : 'Why this is inferred'}
                  </p>
                  <p className="mt-1 text-xs text-muted-foreground">
                    {directRepository || directBuild
                      ? 'This finding carries explicit repository or pipeline metadata, so the handoff does not need to guess source control or build lineage.'
                      : 'The finding exposes service, app, account, region, and runtime asset metadata, but it does not yet carry explicit repo, branch, commit, or pipeline run identifiers.'}
                  </p>
                </div>
              </CardContent>
            </Card>

            <div className="space-y-4">
              <Card className="border-border/80">
                <CardHeader className="pb-2">
                  <CardTitle className="text-xs font-medium uppercase tracking-wide text-muted-foreground">
                    Attack Path Handoff
                  </CardTitle>
                </CardHeader>
                <CardContent className="space-y-3">
                  {linkedPath ? (
                    <>
                      <div className="rounded-2xl border border-violet-200/70 bg-violet-50/70 p-3 dark:border-violet-900/40 dark:bg-violet-950/20">
                        <p className="text-[10px] font-semibold uppercase tracking-wide text-violet-700 dark:text-violet-300">
                          Linked exploit chain
                        </p>
                        <p className="mt-1 text-sm font-medium">{linkedPath.title}</p>
                        <p className="mt-1 text-xs text-muted-foreground">
                          {linkedPath.entry_point.resource_name} {'->'} {finding.resource_name} {'->'} {linkedPath.target.resource_name}
                        </p>
                      </div>
                      {linkedTargets.length > 0 && (
                        <div>
                          <p className="text-[10px] font-semibold uppercase tracking-wide text-muted-foreground">
                            Downstream targets
                          </p>
                          <div className="mt-2 flex flex-wrap gap-1.5">
                            {linkedTargets.map((target) => (
                              <Badge key={target} variant="secondary" className="text-[10px]">
                                {target}
                              </Badge>
                            ))}
                          </div>
                        </div>
                      )}
                    </>
                  ) : (
                    <p className="text-xs text-muted-foreground">
                      No graph-linked attack path is attached to this finding yet. Use this tab as a delivery-context checklist before you escalate or remediate.
                    </p>
                  )}
                  <Button size="sm" variant="outline" className="gap-1.5 text-xs" onClick={onOpenInvestigation}>
                    <Workflow className="h-3.5 w-3.5" />
                    Open attack-path investigation
                  </Button>
                </CardContent>
              </Card>

              <Card className="border-border/80">
                <CardHeader className="pb-2">
                  <CardTitle className="text-xs font-medium uppercase tracking-wide text-muted-foreground">
                    Operator Next Move
                  </CardTitle>
                </CardHeader>
                <CardContent>
                  <p className="text-sm text-muted-foreground">
                    {deriveOperatorNextMove(finding, relatedPaths)}
                  </p>
                </CardContent>
              </Card>
            </div>
          </div>
        </CardContent>
      </Card>
    </div>
  )
}
