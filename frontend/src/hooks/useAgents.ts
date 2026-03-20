import { useQuery } from '@tanstack/react-query'
import { apiClient, ApiError, fetchWithMockFallback } from '@/lib/api'
import type { Agent, AgentTrace } from '@/types/ai-governance'

export function useAgents() {
  return useQuery({
    queryKey: ['agents'],
    queryFn: () => fetchWithMockFallback<Agent[]>(
      '/agents',
      () => import('@/lib/mock/agents.json') as Promise<{ default: Agent[] }>,
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
        const mod = await import('@/lib/mock/agents.json')
        return (mod.default as unknown as Agent[]).find((a) => a.id === id) ?? null
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
      () => import('@/lib/mock/traces.json') as Promise<{ default: AgentTrace[] }>,
      'useAgentTraces',
    ),
    enabled: Boolean(agentId),
  })
}
