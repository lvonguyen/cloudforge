// MVP page — shell with correct imports, to be implemented by ai-agent agent
import { useAgent, useAgentTraces } from '@/hooks/useAgents'
import { AgentCard } from '@/components/ai/AgentCard'
import { AgentStatusBadge } from '@/components/ai/AgentStatusBadge'
import { TraceTimeline } from '@/components/ai/TraceTimeline'
import { SecuritySignalBadge } from '@/components/ai/SecuritySignalBadge'

// Suppress unused import warnings during scaffold phase
void (useAgent as unknown)
void (useAgentTraces as unknown)
void (AgentCard as unknown)
void (AgentStatusBadge as unknown)
void (TraceTimeline as unknown)
void (SecuritySignalBadge as unknown)

export default function AIAgentDetail() {
  return (
    <div className="space-y-4">
      <h1 className="text-xl font-semibold">AI Agent Detail</h1>
      <p className="text-sm text-muted-foreground">
        Trace timeline, security signals, STRIDE threat model, token usage. Implementation pending.
      </p>
    </div>
  )
}
