import { useState } from 'react'
import { cn } from '@/lib/utils'
import { Shield, Bot, Cpu, Search, Link, ChevronDown, ChevronRight, type LucideIcon } from 'lucide-react'
import type { Span, SpanType } from '@/types/ai-governance'

const SPAN_ICONS: Record<SpanType, LucideIcon> = {
  llm: Bot,
  retrieval: Search,
  tool: Cpu,
  chain: Link,
  agent: Bot,
  policy: Shield,
}

const SPAN_COLORS: Record<SpanType, string> = {
  llm: 'border-purple-300 bg-purple-50 dark:border-purple-800 dark:bg-purple-950/20',
  retrieval: 'border-blue-300 bg-blue-50 dark:border-blue-800 dark:bg-blue-950/20',
  tool: 'border-orange-300 bg-orange-50 dark:border-orange-800 dark:bg-orange-950/20',
  chain: 'border-gray-300 bg-gray-50 dark:border-gray-800 dark:bg-gray-950/20',
  agent: 'border-indigo-300 bg-indigo-50 dark:border-indigo-800 dark:bg-indigo-950/20',
  policy: 'border-red-300 bg-red-50 dark:border-red-800 dark:bg-red-950/20',
}

function buildPayload(span: Span): Record<string, unknown> | null {
  const sections: Record<string, unknown> = {}

  if (span.data.llm) {
    const d = span.data.llm
    sections.llm = {
      model: d.model,
      provider: d.provider,
      prompt_tokens: d.prompt_tokens,
      completion_tokens: d.completion_tokens,
      total_tokens: d.total_tokens,
      temperature: d.temperature,
      finish_reason: d.finish_reason,
    }
  }

  if (span.data.tool) {
    const d = span.data.tool
    const entry: Record<string, unknown> = {
      tool_name: d.tool_name,
      category: d.tool_category,
      parameter_count: d.parameter_count,
      external_call: d.external_call,
    }
    if (d.policy_decision) {
      entry.policy_decision = {
        policy_id: d.policy_decision.policy_id,
        decision: d.policy_decision.decision,
        reason: d.policy_decision.reason,
        eval_time_us: d.policy_decision.eval_time_us,
      }
    }
    sections.tool = entry
  }

  if (span.data.retrieval) {
    const d = span.data.retrieval
    sections.retrieval = {
      vector_store: d.vector_store,
      query: d.query,
      num_results: d.num_results,
      top_scores: d.top_scores,
      filter_applied: d.filter_applied,
    }
  }

  if (span.attributes && Object.keys(span.attributes).length > 0) {
    sections.attributes = span.attributes
  }

  if (span.events && span.events.length > 0) {
    sections.events = span.events
  }

  return Object.keys(sections).length > 0 ? sections : null
}

export function TraceTimeline({ spans }: { spans: Span[] }) {
  const [expandedSpans, setExpandedSpans] = useState<Set<string>>(new Set())
  const rootSpans = spans.filter(s => !s.parent_span_id)
  const childSpans = spans.filter(s => s.parent_span_id)

  const getChildren = (spanId: string) => childSpans.filter(s => s.parent_span_id === spanId)

  const toggleExpand = (spanId: string) => {
    setExpandedSpans(prev => {
      const next = new Set(prev)
      if (next.has(spanId)) {
        next.delete(spanId)
      } else {
        next.add(spanId)
      }
      return next
    })
  }

  const renderSpan = (span: Span, depth = 0) => {
    const Icon = SPAN_ICONS[span.type] ?? Bot
    const colorClass = SPAN_COLORS[span.type] ?? SPAN_COLORS.chain
    const children = getChildren(span.span_id)
    const blocked = span.status === 'blocked' || span.status === 'error'
    const isOk = span.status === 'ok' || span.status === 'success' || span.status === 'completed'
    const policyDecision = span.data.tool?.policy_decision
    const payload = buildPayload(span)
    const isExpanded = expandedSpans.has(span.span_id)

    return (
      <div key={span.span_id} className={cn('relative', depth > 0 && 'ml-6 mt-2')}>
        {depth > 0 && (
          <div className="absolute -left-3 top-3 h-[1px] w-3 bg-border" />
        )}
        <div
          className={cn(
            'rounded-none border px-3 py-2 text-xs',
            colorClass,
            blocked && 'border-red-400 bg-red-50 dark:border-red-700 dark:bg-red-950/20',
            isOk && 'border-green-300 bg-green-50 dark:border-green-800 dark:bg-green-950/20'
          )}
        >
          <div className="flex items-start gap-2">
            <Icon className={cn('h-3.5 w-3.5 mt-0.5 shrink-0', blocked && 'text-red-600 dark:text-red-400')} />
            <div className="flex-1 min-w-0">
              <p className={cn('font-medium font-mono truncate', blocked && 'text-red-700 dark:text-red-400')}>{span.name}</p>
              <div className="flex items-center gap-2 mt-0.5 text-muted-foreground">
                <span>{span.duration_ms}ms</span>
                {span.data.llm && (
                  <span>{span.data.llm.total_tokens.toLocaleString()} tokens</span>
                )}
                {policyDecision && (
                  <span className={cn(
                    'font-medium',
                    policyDecision.decision === 'deny' ? 'text-red-600 dark:text-red-400' :
                    policyDecision.decision === 'warn' ? 'text-yellow-600 dark:text-yellow-400' : 'text-green-600 dark:text-green-400'
                  )}>
                    Policy: {policyDecision.decision.toUpperCase()}
                  </span>
                )}
              </div>
              {policyDecision?.decision === 'deny' && (
                <p className="mt-1 text-red-700 dark:text-red-400 leading-tight">{policyDecision.reason}</p>
              )}
            </div>
            <span className={cn(
              'text-[10px] font-medium shrink-0',
              blocked || span.status === 'error' ? 'text-red-600 dark:text-red-400' :
              span.status === 'ok' || span.status === 'success' || span.status === 'completed' ? 'text-green-600 dark:text-green-400' :
              'text-muted-foreground'
            )}>
              {span.status}
            </span>
            {payload && (
              <button
                type="button"
                onClick={() => toggleExpand(span.span_id)}
                className="shrink-0 p-0.5 rounded hover:bg-black/5 dark:hover:bg-white/10 text-muted-foreground"
                aria-label={isExpanded ? 'Collapse payload' : 'Expand payload'}
              >
                {isExpanded
                  ? <ChevronDown className="h-3.5 w-3.5" />
                  : <ChevronRight className="h-3.5 w-3.5" />
                }
              </button>
            )}
          </div>
          {isExpanded && payload && (
            <pre className="text-[10px] font-mono bg-muted/50 p-2 mt-1 overflow-x-auto max-h-48 overflow-y-auto border border-border">
              {JSON.stringify(payload, null, 2)}
            </pre>
          )}
        </div>
        {children.length > 0 && (
          <div className="relative mt-0 border-l border-dashed border-border ml-3.5 pl-0">
            {children.map(child => renderSpan(child, depth + 1))}
          </div>
        )}
      </div>
    )
  }

  return (
    <div className="space-y-2">
      {rootSpans.map(span => renderSpan(span))}
    </div>
  )
}
