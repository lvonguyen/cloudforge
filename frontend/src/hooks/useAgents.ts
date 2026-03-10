import { useQuery } from '@tanstack/react-query'
import { apiClient, ApiError } from '@/lib/api'
import type { Agent, AgentTrace } from '@/types/ai-governance'

export function useAgents() {
  return useQuery({
    queryKey: ['agents'],
    queryFn: async () => {
      try {
        return await apiClient.get<Agent[]>('/agents')
      } catch (err) {
        if (err instanceof ApiError && err.status < 500) throw err
        console.warn('[useAgents] API unavailable, using mock data')
        const mod = await import('@/lib/mock/agents.json')
        return mod.default as unknown as Agent[]
      }
    },
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
    queryFn: async () => {
      try {
        return await apiClient.get<AgentTrace[]>(`/agents/${agentId}/traces`)
      } catch (err) {
        if (err instanceof ApiError && err.status < 500) throw err
        console.warn('[useAgentTraces] API unavailable, using mock data')
        const mod = await import('@/lib/mock/traces.json')
        return mod.default as unknown as AgentTrace[]
      }
    },
    enabled: Boolean(agentId),
  })
}
