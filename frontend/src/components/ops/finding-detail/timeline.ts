import type { AttackPath } from '@/types/attack-path'
import type { Span } from '@/types/ai-governance'
import type { Finding } from '@/types/compliance'

export type FindingTimelineTone = 'sky' | 'indigo' | 'amber' | 'orange' | 'emerald' | 'slate' | 'violet' | 'rose'

export interface FindingTimelineEvent {
  id: string
  label: string
  time: string
  description: string
  actor?: string
  tone: FindingTimelineTone
}

interface BuildTimelineOptions {
  relatedPaths?: AttackPath[]
  enrichedAt?: string
  ticketLinked?: boolean
}

export function buildFindingTimeline(
  finding: Finding,
  options: BuildTimelineOptions = {},
): FindingTimelineEvent[] {
  const events: FindingTimelineEvent[] = [
    {
      id: 'detected',
      label: 'First detected',
      time: finding.first_found_at,
      description: `Detected by ${finding.source} scanner`,
      tone: 'sky',
    },
    {
      id: 'last-seen',
      label: 'Last seen',
      time: finding.last_seen_at,
      description: 'Latest scan confirmed the finding state',
      tone: 'indigo',
    },
  ]

  if (finding.workflow_status !== 'new') {
    events.push({
      id: 'triaged',
      label: 'Triaged',
      time: finding.first_found_at,
      description: `Workflow moved to ${finding.workflow_status.replace(/_/g, ' ')}`,
      tone: 'amber',
    })
  }

  if (options.enrichedAt || finding.ai_risk_rationale) {
    events.push({
      id: 'enriched',
      label: 'Risk enriched',
      time: options.enrichedAt ?? finding.last_seen_at,
      description: 'AI and contextual evidence refreshed the risk narrative',
      tone: 'violet',
    })
  }

  if ((options.relatedPaths?.length ?? 0) > 0) {
    events.push({
      id: 'attack-path',
      label: 'Attack path linked',
      time: finding.last_seen_at,
      description: `${options.relatedPaths!.length} active attack path${options.relatedPaths!.length === 1 ? '' : 's'} include this resource`,
      tone: 'rose',
    })
  }

  if (finding.assignee) {
    events.push({
      id: 'assigned',
      label: 'Assigned',
      time: finding.assignee.assigned_at,
      description: `Assigned to ${finding.assignee.team}`,
      actor: finding.assignee.user_name,
      tone: 'orange',
    })
  }

  if (options.ticketLinked) {
    events.push({
      id: 'ticket-linked',
      label: 'Ticket linked',
      time: finding.last_seen_at,
      description: 'External remediation workflow is tracking this finding',
      tone: 'amber',
    })
  }

  if (finding.due_date) {
    events.push({
      id: 'sla-due',
      label: finding.sla_breach_date ? 'SLA breached' : 'SLA due',
      time: finding.due_date,
      description: finding.sla_breach_date ? 'Remediation deadline passed' : 'Remediation deadline scheduled',
      tone: finding.sla_breach_date ? 'rose' : 'amber',
    })
  }

  if (finding.resolved_at) {
    events.push({
      id: 'resolved',
      label: 'Resolved',
      time: finding.resolved_at,
      description: 'Finding resolved and verified',
      tone: 'emerald',
    })
  } else if (finding.workflow_status === 'false_positive' || finding.workflow_status === 'risk_accepted') {
    events.push({
      id: 'suppressed',
      label: finding.workflow_status === 'false_positive' ? 'Marked false positive' : 'Risk accepted',
      time: finding.last_seen_at,
      description: finding.suppression_reason ?? 'Workflow suppression recorded',
      tone: 'slate',
    })
  }

  return events.sort((a, b) => new Date(a.time).getTime() - new Date(b.time).getTime())
}

export function buildFindingTimelineSpans(
  finding: Finding,
  events: FindingTimelineEvent[],
): Span[] {
  return events.map((event, index) => ({
    span_id: `finding-${finding.id}-${event.id}`,
    name: event.label,
    type: event.id === 'attack-path' || event.id === 'enriched' ? 'policy' : 'tool',
    start_time: event.time,
    end_time: event.time,
    duration_ms: 1,
    status: 'ok',
    attributes: {
      'finding.id': finding.id,
      'finding.resource': finding.resource_name,
      'finding.severity': finding.severity,
      'timeline.order': index,
      'timeline.event': event.id,
      'timeline.description': event.description,
      ...(event.actor ? { 'timeline.actor': event.actor } : {}),
    },
    events: [],
    data: {},
  }))
}
