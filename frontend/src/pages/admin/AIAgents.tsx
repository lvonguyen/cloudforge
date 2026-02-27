import { useNavigate } from 'react-router-dom'
import { useAgents } from '@/hooks/useAgents'
import { AgentCard } from '@/components/ai/AgentCard'

export default function AIAgents() {
  const navigate = useNavigate()
  const { data: agents = [], isLoading } = useAgents()

  if (isLoading) {
    return <div className="text-sm text-muted-foreground">Loading agents…</div>
  }

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-xl font-semibold">AI Agent Registry</h1>
          <p className="text-sm text-muted-foreground">{agents.length} registered agents</p>
        </div>
      </div>
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-4">
        {agents.map(agent => (
          <AgentCard
            key={agent.id}
            agent={agent}
            onClick={() => navigate(`/admin/ai-agents/${agent.id}`)}
          />
        ))}
      </div>
    </div>
  )
}
