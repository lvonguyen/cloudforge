import { ArrowRight, Crosshair, Network, ShieldAlert, Sparkles } from 'lucide-react'
import { AttackPathMiniGraph } from '@/components/attack-path/AttackPathMiniGraph'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
import type { AttackPath } from '@/types/attack-path'
import type { Finding } from '@/types/compliance'

interface FindingAttackPathWorkspaceProps {
  finding: Finding
  relatedPaths: AttackPath[]
  attackPathsEnabled: boolean
  onLoadAttackPaths: () => void
  onOpenSecurityGraph: () => void
}

export function FindingAttackPathWorkspace({
  finding,
  relatedPaths,
  attackPathsEnabled,
  onLoadAttackPaths,
  onOpenSecurityGraph,
}: FindingAttackPathWorkspaceProps) {
  const primaryPath = relatedPaths[0]
  const uniqueEntryPoints = Array.from(new Set(relatedPaths.map((path) => path.entry_point.resource_name)))
  const uniqueTargets = Array.from(new Set(relatedPaths.map((path) => path.target.resource_name)))
  const uniqueTechniques = Array.from(new Set(relatedPaths.flatMap((path) => path.mitre_tactics))).slice(0, 4)
  const edgeLabels = Array.from(
    new Set(
      relatedPaths.flatMap((path) =>
        path.edges.map((edge) => edge.label.replace(/[_-]/g, ' ')),
      ),
    ),
  ).slice(0, 4)

  if (!attackPathsEnabled) {
    return (
      <Card>
        <CardHeader className="pb-2">
          <CardTitle className="text-xs font-medium uppercase tracking-wide text-muted-foreground">
            <div className="flex items-center gap-1.5">
              <Crosshair className="h-3.5 w-3.5" />
              Attack Path
            </div>
          </CardTitle>
        </CardHeader>
        <CardContent className="space-y-4">
          <div className="rounded-2xl border border-border/80 bg-muted/20 p-4">
            <p className="text-sm font-semibold">Load attack-path analysis for this finding</p>
            <p className="mt-1 text-sm text-muted-foreground">
              Inline path context keeps the investigation nested under the finding instead of bouncing to a separate page.
            </p>
          </div>
          <div className="flex flex-wrap items-center gap-2">
            <Button size="sm" className="gap-1.5 text-xs" onClick={onLoadAttackPaths}>
              <Network className="h-3.5 w-3.5" />
              Load attack path analysis
            </Button>
            <Button size="sm" variant="outline" className="gap-1.5 text-xs" onClick={onOpenSecurityGraph}>
              <ShieldAlert className="h-3.5 w-3.5" />
              Open security graph context
            </Button>
          </div>
        </CardContent>
      </Card>
    )
  }

  if (relatedPaths.length === 0) {
    return (
      <Card>
        <CardHeader className="pb-2">
          <CardTitle className="text-xs font-medium uppercase tracking-wide text-muted-foreground">
            <div className="flex items-center gap-1.5">
              <Crosshair className="h-3.5 w-3.5" />
              Attack Path
            </div>
          </CardTitle>
        </CardHeader>
        <CardContent className="space-y-4">
          <div className="rounded-2xl border border-border/80 bg-muted/20 p-4">
            <p className="text-sm font-semibold">No graph-confirmed attack path is linked yet</p>
            <p className="mt-1 text-sm text-muted-foreground">
              This finding is still visible in the security graph and lifecycle timeline, but there is no path chain rooted on {finding.resource_name}.
            </p>
          </div>
          <Button size="sm" variant="outline" className="gap-1.5 text-xs" onClick={onOpenSecurityGraph}>
            <ShieldAlert className="h-3.5 w-3.5" />
            Review security graph context
          </Button>
        </CardContent>
      </Card>
    )
  }

  return (
    <div className="space-y-6">
      <Card>
        <CardHeader className="pb-3">
          <CardTitle className="text-xs font-medium uppercase tracking-wide text-muted-foreground">
            <div className="flex items-center gap-1.5">
              <Crosshair className="h-3.5 w-3.5" />
              Attack Path Analyst View
            </div>
          </CardTitle>
        </CardHeader>
        <CardContent className="space-y-4">
          <div className="grid gap-3 sm:grid-cols-2 xl:grid-cols-4">
            <div className="rounded-2xl border border-border/80 bg-muted/20 p-3">
              <p className="text-[10px] uppercase tracking-wide text-muted-foreground">Linked Paths</p>
              <p className="mt-1 text-lg font-semibold">{relatedPaths.length}</p>
              <p className="text-xs text-muted-foreground">Path chains include this finding or resource</p>
            </div>
            <div className="rounded-2xl border border-border/80 bg-muted/20 p-3">
              <p className="text-[10px] uppercase tracking-wide text-muted-foreground">Primary Entry</p>
              <p className="mt-1 text-sm font-semibold">{primaryPath.entry_point.resource_name}</p>
              <p className="text-xs text-muted-foreground">{primaryPath.entry_point.category.toLowerCase()} pivot</p>
            </div>
            <div className="rounded-2xl border border-border/80 bg-muted/20 p-3">
              <p className="text-[10px] uppercase tracking-wide text-muted-foreground">Target Asset</p>
              <p className="mt-1 text-sm font-semibold">{primaryPath.target.resource_name}</p>
              <p className="text-xs text-muted-foreground">{primaryPath.target.resource_type.replace(/_/g, ' ')}</p>
            </div>
            <div className="rounded-2xl border border-border/80 bg-muted/20 p-3">
              <p className="text-[10px] uppercase tracking-wide text-muted-foreground">Analyst Score</p>
              <p className="mt-1 text-lg font-semibold">{primaryPath.score.toFixed(0)}</p>
              <p className="text-xs text-muted-foreground">{primaryPath.hop_count} hops in the selected chain</p>
            </div>
          </div>

          <div className="rounded-2xl border border-border/80 bg-background p-4">
            <div className="flex flex-wrap items-start justify-between gap-3">
              <div className="space-y-2">
                <div className="flex flex-wrap items-center gap-2">
                  <Badge variant="outline" className="text-[10px]">
                    {primaryPath.severity}
                  </Badge>
                  <Badge variant="secondary" className="text-[10px]">
                    {primaryPath.finding_ids.length} findings in chain
                  </Badge>
                </div>
                <p className="text-sm font-semibold">{primaryPath.title}</p>
                <p className="text-sm text-muted-foreground">
                  {primaryPath.ai_risk_narrative ?? primaryPath.ai_description ?? primaryPath.description}
                </p>
              </div>
              <Button size="sm" variant="outline" className="gap-1.5 text-xs" onClick={onOpenSecurityGraph}>
                <ShieldAlert className="h-3.5 w-3.5" />
                Security graph context
              </Button>
            </div>
          </div>

          <div className="grid gap-4 lg:grid-cols-[minmax(0,1.25fr)_minmax(16rem,0.85fr)]">
            <div className="min-w-0">
              <AttackPathMiniGraph paths={relatedPaths} resourceId={finding.resource_id} focusFinding={finding} />
            </div>
            <div className="space-y-4">
              <Card className="border-border/80">
                <CardHeader className="pb-2">
                  <CardTitle className="text-xs font-medium uppercase tracking-wide text-muted-foreground">
                    Path Signals
                  </CardTitle>
                </CardHeader>
                <CardContent className="space-y-3">
                  <div>
                    <p className="text-[10px] uppercase tracking-wide text-muted-foreground">Entry Points</p>
                    <div className="mt-2 flex flex-wrap gap-1.5">
                      {uniqueEntryPoints.slice(0, 3).map((entry) => (
                        <Badge key={entry} variant="outline" className="text-[10px]">
                          {entry}
                        </Badge>
                      ))}
                    </div>
                  </div>
                  <div>
                    <p className="text-[10px] uppercase tracking-wide text-muted-foreground">Targets</p>
                    <div className="mt-2 flex flex-wrap gap-1.5">
                      {uniqueTargets.slice(0, 3).map((target) => (
                        <Badge key={target} variant="outline" className="text-[10px]">
                          {target}
                        </Badge>
                      ))}
                    </div>
                  </div>
                  {edgeLabels.length > 0 && (
                    <div>
                      <p className="text-[10px] uppercase tracking-wide text-muted-foreground">Relationship Types</p>
                      <div className="mt-2 flex flex-wrap gap-1.5">
                        {edgeLabels.map((label) => (
                          <Badge key={label} variant="secondary" className="text-[10px]">
                            {label}
                          </Badge>
                        ))}
                      </div>
                    </div>
                  )}
                  {uniqueTechniques.length > 0 && (
                    <div>
                      <p className="text-[10px] uppercase tracking-wide text-muted-foreground">MITRE Tactics</p>
                      <div className="mt-2 flex flex-wrap gap-1.5">
                        {uniqueTechniques.map((tactic) => (
                          <Badge key={tactic} variant="outline" className="text-[10px] font-mono">
                            {tactic}
                          </Badge>
                        ))}
                      </div>
                    </div>
                  )}
                </CardContent>
              </Card>

              <Card className="border-border/80">
                <CardHeader className="pb-2">
                  <CardTitle className="text-xs font-medium uppercase tracking-wide text-muted-foreground">
                    Why It Matters
                  </CardTitle>
                </CardHeader>
                <CardContent className="space-y-3">
                  <div className="flex items-start gap-2 text-sm text-muted-foreground">
                    <Sparkles className="mt-0.5 h-4 w-4 text-amber-500" />
                    <p>
                      {primaryPath.ai_remediation ?? 'Use the graph chain to validate containment order: remove the exposed entry, break the privilege hop, then protect the target asset.'}
                    </p>
                  </div>
                  <div className="flex items-center gap-2 text-xs font-medium text-muted-foreground">
                    <span>{primaryPath.entry_point.resource_name}</span>
                    <ArrowRight className="h-3 w-3" />
                    <span>{primaryPath.target.resource_name}</span>
                  </div>
                </CardContent>
              </Card>
            </div>
          </div>
        </CardContent>
      </Card>
    </div>
  )
}
