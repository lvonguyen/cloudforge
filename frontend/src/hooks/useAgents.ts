import { useQuery } from '@tanstack/react-query'
import { apiClient, ApiError, fetchWithMockFallback } from '@/lib/api'
import type { Agent, AgentTrace } from '@/types/ai-governance'
import agentsData from '@/lib/mock/agents.json'
import tracesData from '@/lib/mock/traces.json'

export function useAgents() {
  return useQuery({
    queryKey: ['agents'],
    queryFn: () => fetchWithMockFallback<Agent[]>(
      '/agents',
      () => Promise.resolve({ default: agentsData as unknown as Agent[] }),
      'useAgents',
    ),
  })
}

export function useAgent(id: string) {
  return useQuery({
    queryKey: ['agents', id],
    queryFn: async () => {
      try {
        return await apiClient.get<Agent>(`/agents/${id}`)
      } catch (err) {
        if (err instanceof ApiError && err.status < 500) throw err
        console.warn('[useAgent] API unavailable, using mock data')
        return (agentsData as unknown as Agent[]).find((a) => a.id === id) ?? null
      }
    },
    enabled: Boolean(id),
  })
}

export function useAgentTraces(agentId: string) {
  return useQuery({
    queryKey: ['agents', agentId, 'traces'],
    queryFn: () => fetchWithMockFallback<AgentTrace[]>(
      `/agents/${agentId}/traces`,
      () => Promise.resolve({ default: tracesData as unknown as AgentTrace[] }),
      'useAgentTraces',
    ),
    enabled: Boolean(agentId),
  })
}
