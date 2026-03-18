import { useQuery } from '@tanstack/react-query'
import { apiClient, ApiError } from '@/lib/api'

interface Policy {
  id: string
  name: string
  namespace: string
  status: 'active' | 'inactive' | 'draft'
  category: string
  evaluations: number
  denials: number
  last_updated: string
}

export function usePolicies(filter?: string) {
  const status = filter && filter !== 'all' ? filter : undefined
  return useQuery({
    queryKey: ['policies', filter],
    queryFn: async () => {
      try {
        return await apiClient.get<Policy[]>(`/policies${status ? `?status=${status}` : ''}`)
      } catch (err) {
        if (err instanceof ApiError && err.status < 500) throw err
        console.warn('[usePolicies] API unavailable, using mock data')
        const mod = await import('@/lib/mock/policies.json')
        return mod.default as Policy[]
      }
    },
  })
}

export function usePolicy(id: string) {
  return useQuery({
    queryKey: ['policies', id],
    queryFn: async () => {
      try {
        return await apiClient.get<Policy>(`/policies/${id}`)
      } catch (err) {
        if (err instanceof ApiError && err.status < 500) throw err
        console.warn(`[usePolicy] API unavailable for ${id}, using mock`)
        const mod = await import('@/lib/mock/policies.json')
        const match = (mod.default as Policy[]).find(p => p.id === id)
        return match ?? null
      }
    },
    enabled: Boolean(id),
  })
}
