import { Activity, MessageSquare, Ticket, TimerReset } from 'lucide-react'
import {
  buildFindingTimeline,
  type FindingTimelineEvent,
} from '@/components/ops/finding-detail/timeline'
import {
  formatDateTime,
  formatWorkflowStatus,
  getFindingSlaState,
} from '@/components/ops/finding-detail/helpers'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
import type { AttackPath } from '@/types/attack-path'
import type { Finding } from '@/types/compliance'

interface FindingHistoryWorkspaceProps {
  finding: Finding
  relatedPaths: AttackPath[]
  enrichedAt?: string
  ticketLinked: boolean
  commentsCount: number
  onOpenTimeline: () => void
}

const EVENT_STYLES: Record<FindingTimelineEvent['tone'], { dot: string }> = {
  sky: { dot: 'bg-sky-500' },
  indigo: { dot: 'bg-indigo-500' },
  amber: { dot: 'bg-amber-500' },
  orange: { dot: 'bg-orange-500' },
  emerald: { dot: 'bg-emerald-500' },
  slate: { dot: 'bg-slate-500' },
  violet: { dot: 'bg-violet-500' },
  rose: { dot: 'bg-rose-500' },
}

export function FindingHistoryWorkspace({
  finding,
  relatedPaths,
  enrichedAt,
  ticketLinked,
  commentsCount,
  onOpenTimeline,
}: FindingHistoryWorkspaceProps) {
  const timeline = buildFindingTimeline(finding, {
    relatedPaths,
    enrichedAt,
    ticketLinked,
  })
  const slaState = getFindingSlaState(finding)

  return (
    <div className="space-y-6">
      <Card>
        <CardHeader className="pb-3">
          <CardTitle className="text-xs font-medium uppercase tracking-wide text-muted-foreground">
            <div className="flex items-center gap-1.5">
              <Activity className="h-3.5 w-3.5" />
              Finding History
            </div>
          </CardTitle>
        </CardHeader>
        <CardContent className="space-y-4">
          <div className="grid gap-3 sm:grid-cols-2 xl:grid-cols-4">
            <div className="rounded-2xl border border-border/80 bg-muted/20 p-3">
              <p className="text-[10px] uppercase tracking-wide text-muted-foreground">Workflow</p>
              <p className="mt-1 text-sm font-semibold">{formatWorkflowStatus(finding.workflow_status)}</p>
              <p className="text-xs text-muted-foreground">{finding.status}</p>
            </div>
            <div className="rounded-2xl border border-border/80 bg-muted/20 p-3">
              <p className="text-[10px] uppercase tracking-wide text-muted-foreground">SLA State</p>
              <Badge variant="outline" className={`mt-1 text-[10px] ${slaState.badgeClass}`}>
                {slaState.label}
              </Badge>
              <p className="mt-1 text-xs text-muted-foreground">{slaState.detail}</p>
            </div>
            <div className="rounded-2xl border border-border/80 bg-muted/20 p-3">
              <p className="text-[10px] uppercase tracking-wide text-muted-foreground">Comments</p>
              <p className="mt-1 text-lg font-semibold">{commentsCount}</p>
              <p className="text-xs text-muted-foreground">Analyst discussion entries</p>
            </div>
            <div className="rounded-2xl border border-border/80 bg-muted/20 p-3">
              <p className="text-[10px] uppercase tracking-wide text-muted-foreground">Last Seen</p>
              <p className="mt-1 text-sm font-semibold">{formatDateTime(finding.last_seen_at)}</p>
              <p className="text-xs text-muted-foreground">{relatedPaths.length} linked path{relatedPaths.length === 1 ? '' : 's'}</p>
            </div>
          </div>

          <div className="grid gap-4 lg:grid-cols-[minmax(0,1.15fr)_minmax(18rem,0.85fr)]">
            <Card className="border-border/80">
              <CardHeader className="pb-2">
                <CardTitle className="text-xs font-medium uppercase tracking-wide text-muted-foreground">
                  Timeline
                </CardTitle>
              </CardHeader>
              <CardContent className="space-y-0">
                {timeline.map((event, index) => (
                  <div key={event.id} className="flex gap-3">
                    <div className="flex flex-col items-center">
                      <div className="flex h-6 w-6 items-center justify-center rounded-full bg-muted">
                        <span className={`h-2.5 w-2.5 rounded-full ${EVENT_STYLES[event.tone].dot}`} />
                      </div>
                      {index < timeline.length - 1 && (
                        <div className="h-8 w-px bg-border" />
                      )}
                    </div>
                    <div className="min-w-0 flex-1 pb-4">
                      <div className="flex flex-wrap items-center gap-2">
                        <p className="text-xs font-medium">{event.label}</p>
                        {event.actor && (
                          <span className="text-[10px] text-muted-foreground">by {event.actor}</span>
                        )}
                      </div>
                      <p className="text-[10px] text-muted-foreground">{event.description}</p>
                      <p className="mt-0.5 text-[10px] text-muted-foreground/70">{formatDateTime(event.time)}</p>
                    </div>
                  </div>
                ))}
                <div className="border-t border-border pt-3">
                  <Button size="sm" variant="outline" className="gap-1.5 text-xs" onClick={onOpenTimeline}>
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
                    State Snapshot
                  </CardTitle>
                </CardHeader>
                <CardContent className="space-y-3 text-sm">
                  <div className="rounded-2xl border border-border/80 bg-muted/20 p-3">
                    <p className="text-[10px] uppercase tracking-wide text-muted-foreground">Current owner</p>
                    <p className="mt-1 font-medium">{finding.assignee?.user_name ?? 'Unassigned'}</p>
                    <p className="text-xs text-muted-foreground">{finding.assignee?.team ?? finding.line_of_business}</p>
                  </div>
                  <div className="rounded-2xl border border-border/80 bg-muted/20 p-3">
                    <p className="text-[10px] uppercase tracking-wide text-muted-foreground">Ticket status</p>
                    <div className="mt-1 flex items-center gap-2">
                      <Ticket className="h-3.5 w-3.5 text-muted-foreground" />
                      <span className="text-sm font-medium">{ticketLinked ? 'Linked' : 'Not linked'}</span>
                    </div>
                  </div>
                  <div className="rounded-2xl border border-border/80 bg-muted/20 p-3">
                    <p className="text-[10px] uppercase tracking-wide text-muted-foreground">Comments</p>
                    <div className="mt-1 flex items-center gap-2">
                      <MessageSquare className="h-3.5 w-3.5 text-muted-foreground" />
                      <span className="text-sm font-medium">{commentsCount} total</span>
                    </div>
                  </div>
                </CardContent>
              </Card>

              <Card className="border-border/80">
                <CardHeader className="pb-2">
                  <CardTitle className="text-xs font-medium uppercase tracking-wide text-muted-foreground">
                    What Changed
                  </CardTitle>
                </CardHeader>
                <CardContent>
                  <p className="text-sm text-muted-foreground">
                    History tracks scanner detection, enrichment, ownership, path linkage, and external workflow changes. Comment events are summarized as count only until per-comment timeline entries are added.
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
