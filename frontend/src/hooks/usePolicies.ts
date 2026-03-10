import { useQuery } from '@tanstack/react-query'
import { apiClient } from '@/lib/api'

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
      } catch {
        const mod = await import('@/lib/mock/policies.json')
        return mod.default as Policy[]
      }
    },
  })
}
