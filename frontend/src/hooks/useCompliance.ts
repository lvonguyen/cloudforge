import { useQuery } from '@tanstack/react-query'
import { fetchWithMockFallback } from '@/lib/api'

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
    queryFn: () => fetchWithMockFallback<Framework[]>(
      '/compliance/frameworks',
      () => import('@/lib/mock/frameworks.json') as Promise<{ default: Framework[] }>,
      'useCompliance',
    ),
  })
}
