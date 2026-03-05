import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
import { Badge } from '@/components/ui/badge'
import { AgentStatusBadge } from './AgentStatusBadge'
import { Bot, Cpu } from 'lucide-react'
import type { Agent } from '@/types/ai-governance'

const RISK_CONFIG: Record<string, string> = {
  low: 'bg-green-100 text-green-700 dark:bg-green-900/30 dark:text-green-300',
  medium: 'bg-yellow-100 text-yellow-700 dark:bg-yellow-900/30 dark:text-yellow-300',
  high: 'bg-red-100 text-red-700 dark:bg-red-900/30 dark:text-red-300',
}

export function AgentCard({ agent, onClick }: { agent: Agent; onClick?: () => void }) {
  return (
    <Card
      className={`hover:shadow-sm transition-shadow ${onClick ? 'cursor-pointer' : ''}`}
      onClick={onClick}
    >
      <CardHeader className="pb-2">
        <div className="flex items-start justify-between gap-2">
          <div className="flex items-center gap-2">
            <Bot className="h-5 w-5 text-muted-foreground" />
            <CardTitle className="text-sm">{agent.name}</CardTitle>
          </div>
          <AgentStatusBadge status={agent.status} />
        </div>
      </CardHeader>
      <CardContent className="space-y-2">
        <p className="text-xs text-muted-foreground line-clamp-2">{agent.description}</p>
        <div className="flex items-center gap-2 flex-wrap">
          <Badge variant="secondary" className="flex items-center gap-1 text-[10px]">
            <Cpu className="h-3 w-3" />
            {agent.framework}
          </Badge>
          <Badge
            variant="secondary"
            className={`text-[10px] ${RISK_CONFIG[agent.risk_level] ?? ''}`}
          >
            {agent.risk_level} risk
          </Badge>
          <span className="text-[10px] text-muted-foreground ml-auto">{agent.tools.length} tools</span>
        </div>
      </CardContent>
    </Card>
  )
}
