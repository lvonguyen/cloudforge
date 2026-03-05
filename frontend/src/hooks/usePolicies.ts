import { useQuery } from '@tanstack/react-query'
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

const policies = policiesData as Policy[]

export function usePolicies(filter?: string) {
  return useQuery({
    queryKey: ['policies', filter],
    queryFn: async () => {
      if (!filter || filter === 'all') return policies
      return policies.filter(p => p.status === filter || p.category === filter)
    },
  })
}
