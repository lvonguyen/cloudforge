import { useQuery } from '@tanstack/react-query'
import { apiClient } from '@/lib/api'

interface Framework {
  id: string
  name: string
  description: string
  total_controls: number
  controls_passing: number
  controls_failing: number
  score: number
  category: string
}

export function useCompliance() {
  return useQuery({
    queryKey: ['compliance', 'frameworks'],
    queryFn: async () => {
      try {
        return await apiClient.get<Framework[]>('/compliance/frameworks')
      } catch {
        const mod = await import('@/lib/mock/frameworks.json')
        return mod.default as Framework[]
      }
    },
  })
}
