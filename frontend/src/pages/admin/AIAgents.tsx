import { useNavigate } from 'react-router-dom'
import { useAgents } from '@/hooks/useAgents'
import { AgentCard } from '@/components/ai/AgentCard'
import { CheckCircle2, AlertTriangle, XCircle } from 'lucide-react'

export default function AIAgents() {
  const navigate = useNavigate()
  const { data: agents = [], isLoading } = useAgents()

  if (isLoading) {
    return <div className="text-sm text-muted-foreground">Loading agents…</div>
  }

  const statusCounts = {
    active: agents.filter(a => a.status === 'active').length,
    suspended: agents.filter(a => a.status === 'suspended').length,
    inactive: agents.filter(a => a.status === 'inactive').length,
  }

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-xl font-semibold">AI Agent Registry</h1>
          <p className="text-sm text-muted-foreground">{agents.length} registered agents</p>
        </div>
      </div>
      <div className="flex gap-3">
        {statusCounts.active > 0 && (
          <div className="flex items-center gap-1.5 px-3 py-1.5 rounded-none bg-green-50 dark:bg-green-950/20 text-green-700 dark:text-green-300 text-xs font-medium">
            <CheckCircle2 className="h-3.5 w-3.5" />{statusCounts.active} active
          </div>
        )}
        {statusCounts.suspended > 0 && (
          <div className="flex items-center gap-1.5 px-3 py-1.5 rounded-none bg-red-50 dark:bg-red-950/20 text-red-700 dark:text-red-300 text-xs font-medium">
            <XCircle className="h-3.5 w-3.5" />{statusCounts.suspended} suspended
          </div>
        )}
        {statusCounts.inactive > 0 && (
          <div className="flex items-center gap-1.5 px-3 py-1.5 rounded-none bg-gray-100 dark:bg-gray-900/30 text-gray-600 dark:text-gray-400 text-xs font-medium">
            <AlertTriangle className="h-3.5 w-3.5" />{statusCounts.inactive} inactive
          </div>
        )}
      </div>
      <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
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
