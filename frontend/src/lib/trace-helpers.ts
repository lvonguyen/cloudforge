import type { DeployEvent, DeployPhase } from '@/types/deploy'
import type { Span, SpanData, SpanEvent, SpanType } from '@/types/ai-governance'

interface TimelineStep {
  id?: string
  parentSpanId?: string
  name: string
  type: SpanType
  durationMs: number
  status?: string
  attributes?: Record<string, unknown>
  data?: SpanData
  events?: SpanEvent[]
}

interface StreamStep {
  phase: DeployPhase
  message: string
  detail?: string
}

interface StreamingDriver {
  openStreaming: (label: string) => void
  appendEvent: (event: DeployEvent) => void
  setRunning: (isRunning: boolean) => void
}

export function buildTraceTimeline(steps: TimelineStep[], startAt = new Date()): Span[] {
  let cursor = startAt.getTime()

  return steps.map((step, index) => {
    const start = new Date(cursor)
    const end = new Date(cursor + step.durationMs)
    cursor = end.getTime()

    return {
      span_id: step.id ?? `span-${index + 1}`,
      parent_span_id: step.parentSpanId,
      name: step.name,
      type: step.type,
      start_time: start.toISOString(),
      end_time: end.toISOString(),
      duration_ms: step.durationMs,
      status: step.status ?? 'completed',
      attributes: step.attributes ?? {},
      events: step.events ?? [],
      data: step.data ?? {},
    }
  })
}

export function playStreamingTrace(driver: StreamingDriver, label: string, steps: StreamStep[], startAt = new Date()) {
  driver.openStreaming(label)

  steps.forEach((step, index) => {
    driver.appendEvent({
      timestamp: new Date(startAt.getTime() + index * 180).toISOString(),
      phase: step.phase,
      message: step.message,
      detail: step.detail,
    })
  })

  driver.setRunning(false)
}
