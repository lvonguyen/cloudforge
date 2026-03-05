import { useQuery } from '@tanstack/react-query'
import { apiClient } from '@/lib/api'
import tracesData from '@/lib/mock/traces.json'
import type { Agent, AgentTrace } from '@/types/ai-governance'

const traces = tracesData as AgentTrace[]

export function useAgents() {
  return useQuery({
    queryKey: ['agents'],
    queryFn: () => apiClient.get<Agent[]>('/agents'),
  })
}

export function useAgent(id: string) {
  return useQuery({
    queryKey: ['agents', id],
    queryFn: () => apiClient.get<Agent>(`/agents/${id}`),
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
