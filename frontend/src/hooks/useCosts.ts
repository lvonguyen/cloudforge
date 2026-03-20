import { useQuery } from '@tanstack/react-query'
import { fetchWithMockFallback } from '@/lib/api'
import type { CostSummary } from '@/types/finops'

export function useCostSummary() {
  return useQuery({
    queryKey: ['costs', 'summary'],
    queryFn: () => fetchWithMockFallback<CostSummary>(
      '/costs/summary',
      () => import('@/lib/mock/costs.json') as Promise<{ default: CostSummary }>,
      'useCostSummary',
    ),
  })
}

export function useCostAnomalies() {
  return useQuery({
    queryKey: ['costs', 'summary'],
    queryFn: () => fetchWithMockFallback<CostSummary>(
      '/costs/summary',
      () => import('@/lib/mock/costs.json') as Promise<{ default: CostSummary }>,
      'useCostAnomalies',
    ),
    select: (data) => data.anomalies,
  })
}
