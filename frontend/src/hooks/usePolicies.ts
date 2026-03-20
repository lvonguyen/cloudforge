import { useQuery } from '@tanstack/react-query'
import { apiClient, ApiError, fetchWithMockFallback } from '@/lib/api'
import policiesData from '@/lib/mock/policies.json'

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
    queryFn: () => fetchWithMockFallback<Policy[]>(
      `/policies${status ? `?status=${status}` : ''}`,
      () => Promise.resolve({ default: policiesData as Policy[] }),
      'usePolicies',
    ),
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
        const match = (policiesData as Policy[]).find(p => p.id === id)
        return match ?? null
      }
    },
    enabled: Boolean(id),
  })
}
