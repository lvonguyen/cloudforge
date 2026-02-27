import { useQuery } from '@tanstack/react-query'
import agentsData from '@/lib/mock/agents.json'
import tracesData from '@/lib/mock/traces.json'
import type { Agent, AgentTrace } from '@/types/ai-governance'

const agents = agentsData as Agent[]
const traces = tracesData as AgentTrace[]

export function useAgents() {
  return useQuery({
    queryKey: ['agents'],
    queryFn: async () => agents,
  })
}

export function useAgent(id: string) {
  return useQuery({
    queryKey: ['agents', id],
    queryFn: async () => agents.find(a => a.id === id) ?? null,
    enabled: Boolean(id),
  })
}

export function useAgentTraces(agentId: string) {
  return useQuery({
    queryKey: ['agents', agentId, 'traces'],
    queryFn: async () => traces.filter(t => t.agent_id === agentId),
    enabled: Boolean(agentId),
  })
}
