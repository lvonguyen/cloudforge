import { useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { useAgents } from '@/hooks/useAgents'
import { AgentCard } from '@/components/ai/AgentCard'
import { AgentStatusBadge } from '@/components/ai/AgentStatusBadge'
import { Badge } from '@/components/ui/badge'
import {
  Table, TableBody, TableCell, TableHead, TableHeader, TableRow,
} from '@/components/ui/table'
import { CheckCircle2, AlertTriangle, XCircle, LayoutGrid, List, Cpu } from 'lucide-react'

export default function AIAgents() {
  const navigate = useNavigate()
  const { data: agents = [], isLoading } = useAgents()
  const [view, setView] = useState<'grid' | 'list'>('grid')

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
        <div className="flex items-center gap-0.5 border border-border p-0.5">
          <button
            onClick={() => setView('grid')}
            className={`p-1.5 transition-colors ${view === 'grid' ? 'bg-foreground text-background' : 'text-muted-foreground hover:text-foreground'}`}
          >
            <LayoutGrid className="h-3.5 w-3.5" />
          </button>
          <button
            onClick={() => setView('list')}
            className={`p-1.5 transition-colors ${view === 'list' ? 'bg-foreground text-background' : 'text-muted-foreground hover:text-foreground'}`}
          >
            <List className="h-3.5 w-3.5" />
          </button>
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
      {agents.length === 0 ? (
        <div className="flex items-center justify-center h-40 text-sm text-muted-foreground">No agents registered.</div>
      ) : view === 'grid' ? (
        <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
          {agents.map(agent => (
            <AgentCard
              key={agent.id}
              agent={agent}
              onClick={() => navigate(`/admin/ai-agents/${agent.id}`)}
            />
          ))}
        </div>
      ) : (
        <div className="border border-border overflow-x-auto">
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead className="text-xs pl-4">Name</TableHead>
                <TableHead className="text-xs">Framework</TableHead>
                <TableHead className="text-xs">Risk</TableHead>
                <TableHead className="text-xs">Tools</TableHead>
                <TableHead className="text-xs">Status</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {agents.map(agent => (
                <TableRow
                  key={agent.id}
                  className="cursor-pointer hover:bg-muted/30"
                  onClick={() => navigate(`/admin/ai-agents/${agent.id}`)}
                >
                  <TableCell className="pl-4">
                    <span className="text-xs font-medium">{agent.name}</span>
                  </TableCell>
                  <TableCell>
                    <Badge variant="secondary" className="flex items-center gap-1 text-[10px] w-fit">
                      <Cpu className="h-3 w-3" />
                      {agent.framework}
                    </Badge>
                  </TableCell>
                  <TableCell>
                    <span className={`text-[10px] font-medium px-2 py-0.5 rounded-none ${
                      agent.risk_level === 'high' ? 'bg-red-100 text-red-700 dark:bg-red-900/30 dark:text-red-300' :
                      agent.risk_level === 'medium' ? 'bg-yellow-100 text-yellow-700 dark:bg-yellow-900/30 dark:text-yellow-300' :
                      'bg-green-100 text-green-700 dark:bg-green-900/30 dark:text-green-300'
                    }`}>
                      {agent.risk_level}
                    </span>
                  </TableCell>
                  <TableCell className="text-xs text-muted-foreground">{agent.tools.length}</TableCell>
                  <TableCell>
                    <AgentStatusBadge status={agent.status} />
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </div>
      )}
    </div>
  )
}
