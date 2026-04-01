import {
  AlertTriangle,
  ArrowRight,
  GitBranch,
  Globe,
  Shield,
  ShieldAlert,
  ShieldCheck,
  TimerReset,
  Workflow,
} from "lucide-react";
import type { ThreatIntelEnrichment } from "@/hooks/useFindings";
import {
  buildFindingTimeline,
  type FindingTimelineEvent,
} from "@/components/ops/finding-detail/timeline";
import {
  formatDateTime,
  formatWorkflowStatus,
  getFindingSlaState,
} from "@/components/ops/finding-detail/helpers";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import type { AttackPath } from "@/types/attack-path";
import type { Finding } from "@/types/compliance";

interface FindingEnrichmentSummary {
  root_cause: string;
  impact: string;
  remediation: string;
  related_controls: string[];
  threat_intel?: ThreatIntelEnrichment;
  enriched_at: string;
}

const EVENT_STYLES: Record<FindingTimelineEvent["tone"], { dot: string }> = {
  sky: { dot: "bg-sky-500" },
  indigo: { dot: "bg-indigo-500" },
  amber: { dot: "bg-amber-500" },
  orange: { dot: "bg-orange-500" },
  emerald: { dot: "bg-emerald-500" },
  slate: { dot: "bg-slate-500" },
  violet: { dot: "bg-violet-500" },
  rose: { dot: "bg-rose-500" },
};

interface FindingSecurityGraphWorkspaceProps {
  finding: Finding;
  relatedPaths: AttackPath[];
  enrichment?: FindingEnrichmentSummary;
  ticketLinked: boolean;
  onOpenTimeline: () => void;
  onOpenAttackPath: () => void;
}

export function FindingSecurityGraphWorkspace({
  finding,
  relatedPaths,
  enrichment,
  ticketLinked,
  onOpenTimeline,
  onOpenAttackPath,
}: FindingSecurityGraphWorkspaceProps) {
  const slaState = getFindingSlaState(finding);
  const timeline = buildFindingTimeline(finding, {
    relatedPaths,
    enrichedAt: enrichment?.enriched_at,
    ticketLinked,
  });
  const uniqueTargets = Array.from(
    new Set(relatedPaths.map((path) => path.target.resource_name)),
  ).slice(0, 4);
  const relatedControls = Array.from(
    new Set([
      ...(enrichment?.related_controls ?? []),
      ...(finding.compliance_mappings?.map(
        (mapping) => `${mapping.framework_name} ${mapping.control_id}`,
      ) ?? []),
    ]),
  ).slice(0, 6);
  const analystSignals = [
    finding.exploit_available
      ? {
          label: "Exploit available",
          tone: "border-red-200 bg-red-100 text-red-800 dark:border-red-800 dark:bg-red-900/30 dark:text-red-300",
        }
      : null,
    finding.ai_contextual_factors?.includes("internet_exposed")
      ? {
          label: "Internet exposed",
          tone: "border-amber-200 bg-amber-100 text-amber-800 dark:border-amber-800 dark:bg-amber-900/30 dark:text-amber-300",
        }
      : null,
    ticketLinked
      ? {
          label: "Ticket linked",
          tone: "border-sky-200 bg-sky-100 text-sky-800 dark:border-sky-800 dark:bg-sky-900/30 dark:text-sky-300",
        }
      : null,
    relatedPaths.length > 0
      ? {
          label: `${relatedPaths.length} path-linked`,
          tone: "border-violet-200 bg-violet-100 text-violet-800 dark:border-violet-800 dark:bg-violet-900/30 dark:text-violet-300",
        }
      : null,
  ].filter(
    (signal): signal is { label: string; tone: string } => signal !== null,
  );
  const primaryTarget =
    uniqueTargets[0] ??
    finding.impacted_resources?.[0]?.resource_name ??
    "downstream asset";
  const containmentGuidance =
    enrichment?.remediation ??
    "Contain ingress exposure first, remove the identity or trust hop that enables lateral movement, and then validate target protections before closing the finding.";

  return (
    <div className="space-y-6">
      <Card>
        <CardHeader className="pb-3">
          <CardTitle className="text-xs font-medium uppercase tracking-wide text-muted-foreground">
            <div className="flex items-center gap-1.5">
              <GitBranch className="h-3.5 w-3.5" />
              Security Graph Context
            </div>
          </CardTitle>
        </CardHeader>
        <CardContent className="space-y-4">
          <div className="grid gap-3 sm:grid-cols-2 xl:grid-cols-4">
            <div className="rounded-2xl border border-border/80 bg-muted/20 p-3">
              <p className="text-[10px] uppercase tracking-wide text-muted-foreground">
                Workflow
              </p>
              <p className="mt-1 text-sm font-semibold">
                {formatWorkflowStatus(finding.workflow_status)}
              </p>
              <p className="text-xs text-muted-foreground">{finding.status}</p>
            </div>
            <div className="rounded-2xl border border-border/80 bg-muted/20 p-3">
              <p className="text-[10px] uppercase tracking-wide text-muted-foreground">
                SLA State
              </p>
              <div className="mt-1 flex items-center gap-2">
                <Badge
                  variant="outline"
                  className={`text-[10px] ${slaState.badgeClass}`}
                >
                  {slaState.label}
                </Badge>
              </div>
              <p className="mt-1 text-xs text-muted-foreground">
                {slaState.detail}
              </p>
            </div>
            <div className="rounded-2xl border border-border/80 bg-muted/20 p-3">
              <p className="text-[10px] uppercase tracking-wide text-muted-foreground">
                Controls
              </p>
              <p className="mt-1 text-lg font-semibold">
                {relatedControls.length || 1}
              </p>
              <p className="text-xs text-muted-foreground">
                Mapped controls or related policies
              </p>
            </div>
            <div className="rounded-2xl border border-border/80 bg-muted/20 p-3">
              <p className="text-[10px] uppercase tracking-wide text-muted-foreground">
                Linked Paths
              </p>
              <p className="mt-1 text-lg font-semibold">
                {relatedPaths.length}
              </p>
              <p className="text-xs text-muted-foreground">
                Graph-derived chains touching this asset
              </p>
            </div>
          </div>

          <div className="rounded-2xl border border-sky-200/70 bg-sky-50/80 p-4 dark:border-sky-900/50 dark:bg-sky-950/30">
            <div className="flex items-start gap-3">
              <div className="rounded-full bg-white/90 p-2 shadow-sm dark:bg-slate-950">
                <ShieldAlert className="h-4 w-4 text-sky-700 dark:text-sky-300" />
              </div>
              <div className="min-w-0 flex-1 space-y-3">
                <div>
                  <p className="text-[10px] font-semibold uppercase tracking-wide text-sky-700 dark:text-sky-300">
                    Analyst Briefing
                  </p>
                  <p className="mt-1 text-sm font-semibold">
                    Containment order for this finding
                  </p>
                  <p className="mt-1 text-sm text-muted-foreground">
                    {containmentGuidance}
                  </p>
                </div>
                {analystSignals.length > 0 && (
                  <div className="flex flex-wrap gap-1.5">
                    {analystSignals.map((signal) => (
                      <Badge
                        key={signal.label}
                        variant="outline"
                        className={`text-[10px] ${signal.tone}`}
                      >
                        {signal.label}
                      </Badge>
                    ))}
                  </div>
                )}
                <div className="flex flex-wrap items-center gap-2 text-xs text-muted-foreground">
                  <span>{finding.resource_name}</span>
                  <ArrowRight className="h-3.5 w-3.5" />
                  <span>{primaryTarget}</span>
                  <span className="rounded-full bg-background/70 px-2 py-0.5 text-[10px]">
                    Contain the entry before validating the target
                  </span>
                </div>
              </div>
            </div>
          </div>

          <div className="grid gap-4 lg:grid-cols-[minmax(0,1.15fr)_minmax(18rem,0.85fr)]">
            <Card className="border-border/80">
              <CardHeader className="pb-2">
                <CardTitle className="text-xs font-medium uppercase tracking-wide text-muted-foreground">
                  Timeline Context
                </CardTitle>
              </CardHeader>
              <CardContent className="space-y-0">
                {timeline.map((event, index) => (
                  <div key={event.id} className="flex gap-3">
                    <div className="flex flex-col items-center">
                      <div className="flex h-6 w-6 items-center justify-center rounded-full bg-muted">
                        <span
                          className={`h-2.5 w-2.5 rounded-full ${EVENT_STYLES[event.tone].dot}`}
                        />
                      </div>
                      {index < timeline.length - 1 && (
                        <div className="h-8 w-px bg-border" />
                      )}
                    </div>
                    <div className="min-w-0 flex-1 pb-4">
                      <div className="flex flex-wrap items-center gap-2">
                        <p className="text-xs font-medium">{event.label}</p>
                        {event.actor && (
                          <span className="text-[10px] text-muted-foreground">
                            by {event.actor}
                          </span>
                        )}
                      </div>
                      <p className="text-[10px] text-muted-foreground">
                        {event.description}
                      </p>
                      <p className="mt-0.5 text-[10px] text-muted-foreground/70">
                        {formatDateTime(event.time)}
                      </p>
                    </div>
                  </div>
                ))}
                <div className="border-t border-border pt-3">
                  <Button
                    size="sm"
                    variant="outline"
                    className="gap-1.5 text-xs"
                    onClick={onOpenTimeline}
                  >
                    <TimerReset className="h-3.5 w-3.5" />
                    Open trace timeline
                  </Button>
                </div>
              </CardContent>
            </Card>

            <div className="space-y-4">
              <Card className="border-border/80">
                <CardHeader className="pb-2">
                  <CardTitle className="text-xs font-medium uppercase tracking-wide text-muted-foreground">
                    Graph Context
                  </CardTitle>
                </CardHeader>
                <CardContent className="space-y-3">
                  <div className="grid gap-2 sm:grid-cols-2">
                    <div className="rounded-2xl border border-border/80 bg-muted/20 p-3">
                      <div className="flex items-center gap-2 text-[10px] font-semibold uppercase tracking-wide text-muted-foreground">
                        <AlertTriangle className="h-3.5 w-3.5" />
                        Investigation Focus
                      </div>
                      <p className="mt-2 text-sm font-medium">
                        {finding.title}
                      </p>
                      <p className="mt-1 text-xs text-muted-foreground">
                        {finding.ai_risk_rationale ?? finding.description}
                      </p>
                    </div>
                    <div className="rounded-2xl border border-border/80 bg-muted/20 p-3">
                      <div className="flex items-center gap-2 text-[10px] font-semibold uppercase tracking-wide text-muted-foreground">
                        <Globe className="h-3.5 w-3.5" />
                        Exposure Snapshot
                      </div>
                      <p className="mt-2 text-sm font-medium">
                        {finding.cloud_provider.toUpperCase()} /{" "}
                        {finding.region}
                      </p>
                      <p className="mt-1 text-xs text-muted-foreground">
                        {finding.account_name ?? finding.account_id} •{" "}
                        {finding.environment_type} scope
                      </p>
                    </div>
                  </div>
                  <div className="grid gap-3 sm:grid-cols-2">
                    <div>
                      <p className="text-[10px] uppercase tracking-wide text-muted-foreground">
                        Resource
                      </p>
                      <p className="mt-1 text-sm font-semibold">
                        {finding.resource_name}
                      </p>
                      <p className="text-xs text-muted-foreground">
                        {finding.resource_type.replace(/_/g, " ")}
                      </p>
                    </div>
                    <div>
                      <p className="text-[10px] uppercase tracking-wide text-muted-foreground">
                        Owner
                      </p>
                      <p className="mt-1 text-sm font-semibold">
                        {finding.assignee?.user_name ?? "Unassigned"}
                      </p>
                      <p className="text-xs text-muted-foreground">
                        {finding.team ?? finding.line_of_business}
                      </p>
                    </div>
                    <div>
                      <p className="text-[10px] uppercase tracking-wide text-muted-foreground">
                        Cloud Scope
                      </p>
                      <p className="mt-1 text-sm font-semibold">
                        {finding.cloud_provider.toUpperCase()} /{" "}
                        {finding.region}
                      </p>
                      <p className="text-xs text-muted-foreground">
                        {finding.account_name ?? finding.account_id}
                      </p>
                    </div>
                    <div>
                      <p className="text-[10px] uppercase tracking-wide text-muted-foreground">
                        Service Context
                      </p>
                      <p className="mt-1 text-sm font-semibold">
                        {finding.service_name}
                      </p>
                      <p className="text-xs text-muted-foreground">
                        {finding.application ?? finding.line_of_business}
                      </p>
                    </div>
                  </div>
                  {uniqueTargets.length > 0 && (
                    <div>
                      <p className="text-[10px] uppercase tracking-wide text-muted-foreground">
                        Exposed Targets
                      </p>
                      <div className="mt-2 flex flex-wrap gap-1.5">
                        {uniqueTargets.map((target) => (
                          <Badge
                            key={target}
                            variant="secondary"
                            className="text-[10px]"
                          >
                            {target}
                          </Badge>
                        ))}
                      </div>
                    </div>
                  )}
                  <Button
                    size="sm"
                    variant="outline"
                    className="gap-1.5 text-xs"
                    onClick={onOpenAttackPath}
                  >
                    <Workflow className="h-3.5 w-3.5" />
                    Open attack-path workspace
                  </Button>
                </CardContent>
              </Card>

              <Card className="border-border/80">
                <CardHeader className="pb-2">
                  <CardTitle className="text-xs font-medium uppercase tracking-wide text-muted-foreground">
                    Controls and Evidence
                  </CardTitle>
                </CardHeader>
                <CardContent className="space-y-3">
                  <div className="grid gap-2 sm:grid-cols-2">
                    <div className="rounded-2xl border border-border/80 bg-muted/20 p-3">
                      <div className="flex items-center gap-2 text-[10px] font-semibold uppercase tracking-wide text-muted-foreground">
                        <ShieldCheck className="h-3.5 w-3.5" />
                        Operator Cue
                      </div>
                      <p className="mt-2 text-xs text-muted-foreground">
                        Validate ingress exposure, then break the privilege or
                        trust hop that connects this resource to the downstream
                        target.
                      </p>
                    </div>
                    <div className="rounded-2xl border border-border/80 bg-muted/20 p-3">
                      <div className="flex items-center gap-2 text-[10px] font-semibold uppercase tracking-wide text-muted-foreground">
                        <Workflow className="h-3.5 w-3.5" />
                        Investigation Pivot
                      </div>
                      <p className="mt-2 text-xs text-muted-foreground">
                        Use the attack-path workspace to confirm the chain, then
                        return here to capture ownership, controls, and
                        evidence.
                      </p>
                    </div>
                  </div>
                  {enrichment && (
                    <div className="rounded-2xl border border-border/80 bg-muted/20 p-3">
                      <div className="flex items-center gap-1.5 text-[10px] font-semibold uppercase tracking-wide text-muted-foreground">
                        <ShieldCheck className="h-3.5 w-3.5" />
                        Graph Reasoning
                      </div>
                      <p className="mt-2 text-sm text-muted-foreground">
                        {enrichment.root_cause}
                      </p>
                      <p className="mt-2 text-xs text-muted-foreground">
                        {enrichment.impact}
                      </p>
                    </div>
                  )}
                  {relatedControls.length > 0 && (
                    <div>
                      <p className="text-[10px] uppercase tracking-wide text-muted-foreground">
                        Mapped Controls
                      </p>
                      <div className="mt-2 flex flex-wrap gap-1.5">
                        {relatedControls.map((control) => (
                          <Badge
                            key={control}
                            variant="outline"
                            className="text-[10px]"
                          >
                            {control}
                          </Badge>
                        ))}
                      </div>
                    </div>
                  )}
                  <div className="grid gap-3 sm:grid-cols-2">
                    <div>
                      <p className="text-[10px] uppercase tracking-wide text-muted-foreground">
                        Canonical Rule
                      </p>
                      <p className="mt-1 text-xs font-mono">
                        {finding.canonical_rule_id}
                      </p>
                    </div>
                    <div>
                      <p className="text-[10px] uppercase tracking-wide text-muted-foreground">
                        Latest Observation
                      </p>
                      <p className="mt-1 text-xs">
                        {formatDateTime(finding.last_seen_at)}
                      </p>
                    </div>
                  </div>
                  {enrichment?.threat_intel && (
                    <div className="flex flex-wrap gap-1.5">
                      {enrichment.threat_intel.kev_exploited && (
                        <Badge
                          variant="outline"
                          className="text-[10px] bg-red-100 text-red-800 border-red-200 dark:bg-red-900/30 dark:text-red-300 dark:border-red-800"
                        >
                          KEV
                        </Badge>
                      )}
                      {enrichment.threat_intel.epss_score > 0 && (
                        <Badge variant="outline" className="text-[10px]">
                          EPSS{" "}
                          {(enrichment.threat_intel.epss_score * 100).toFixed(
                            1,
                          )}
                          %
                        </Badge>
                      )}
                      {(enrichment.threat_intel.otx_pulse_count ?? 0) > 0 && (
                        <Badge variant="outline" className="text-[10px]">
                          OTX {enrichment.threat_intel.otx_pulse_count}
                        </Badge>
                      )}
                    </div>
                  )}
                </CardContent>
              </Card>

              <Card className="border-border/80">
                <CardHeader className="pb-2">
                  <CardTitle className="text-xs font-medium uppercase tracking-wide text-muted-foreground">
                    Compliance Posture
                  </CardTitle>
                </CardHeader>
                <CardContent className="space-y-3">
                  <div className="flex flex-wrap gap-1.5">
                    <Badge
                      variant="outline"
                      className={`text-[10px] ${slaState.badgeClass}`}
                    >
                      {slaState.label}
                    </Badge>
                    <Badge variant="secondary" className="text-[10px]">
                      {finding.compliance_mappings?.length ?? 0} mapped controls
                    </Badge>
                    <Badge variant="secondary" className="text-[10px]">
                      {finding.mitre_techniques?.length ?? 0} MITRE techniques
                    </Badge>
                  </div>
                  <p className="text-sm text-muted-foreground">
                    {slaState.detail}
                  </p>
                  <div className="text-xs text-muted-foreground">
                    <span className="font-medium text-foreground">
                      {finding.severity}
                    </span>{" "}
                    severity against {finding.environment_type} scope.
                  </div>
                  <div className="flex items-center gap-2 text-xs text-muted-foreground">
                    <Shield className="h-3.5 w-3.5" />
                    <span>{finding.source_finding_id}</span>
                  </div>
                </CardContent>
              </Card>
            </div>
          </div>
        </CardContent>
      </Card>
    </div>
  );
}
