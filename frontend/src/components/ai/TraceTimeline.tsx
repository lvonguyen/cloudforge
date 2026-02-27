import { cn } from '@/lib/utils'
import { Shield, Bot, Cpu, Search, Link, type LucideIcon } from 'lucide-react'
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
  llm: 'border-purple-300 bg-purple-50',
  retrieval: 'border-blue-300 bg-blue-50',
  tool: 'border-orange-300 bg-orange-50',
  chain: 'border-gray-300 bg-gray-50',
  agent: 'border-indigo-300 bg-indigo-50',
  policy: 'border-red-300 bg-red-50',
}

export function TraceTimeline({ spans }: { spans: Span[] }) {
  const rootSpans = spans.filter(s => !s.parent_span_id)
  const childSpans = spans.filter(s => s.parent_span_id)

  const getChildren = (spanId: string) => childSpans.filter(s => s.parent_span_id === spanId)

  const renderSpan = (span: Span, depth = 0) => {
    const Icon = SPAN_ICONS[span.type] ?? Bot
    const colorClass = SPAN_COLORS[span.type] ?? SPAN_COLORS.chain
    const children = getChildren(span.span_id)
    const blocked = span.status === 'blocked'
    const policyDecision = span.data.tool?.policy_decision

    return (
      <div key={span.span_id} className={cn('relative', depth > 0 && 'ml-6 mt-2')}>
        {depth > 0 && (
          <div className="absolute -left-3 top-3 h-[1px] w-3 bg-border" />
        )}
        <div
          className={cn(
            'flex items-start gap-2 rounded-md border px-3 py-2 text-xs',
            colorClass,
            blocked && 'border-red-400 bg-red-50'
          )}
        >
          <Icon className={cn('h-3.5 w-3.5 mt-0.5 shrink-0', blocked && 'text-red-600')} />
          <div className="flex-1 min-w-0">
            <p className={cn('font-medium font-mono truncate', blocked && 'text-red-700')}>{span.name}</p>
            <div className="flex items-center gap-2 mt-0.5 text-muted-foreground">
              <span>{span.duration_ms}ms</span>
              {span.data.llm && (
                <span>{span.data.llm.total_tokens.toLocaleString()} tokens</span>
              )}
              {policyDecision && (
                <span className={cn(
                  'font-medium',
                  policyDecision.decision === 'deny' ? 'text-red-600' :
                  policyDecision.decision === 'warn' ? 'text-yellow-600' : 'text-green-600'
                )}>
                  Policy: {policyDecision.decision.toUpperCase()}
                </span>
              )}
            </div>
            {policyDecision?.decision === 'deny' && (
              <p className="mt-1 text-red-700 leading-tight">{policyDecision.reason}</p>
            )}
          </div>
          <span className={cn('text-[10px] font-medium shrink-0', blocked ? 'text-red-600' : 'text-muted-foreground')}>
            {span.status}
          </span>
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
