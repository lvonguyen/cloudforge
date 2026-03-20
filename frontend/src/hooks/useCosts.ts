import { useQuery } from '@tanstack/react-query'
import { fetchWithMockFallback } from '@/lib/api'
import type { CostSummary } from '@/types/finops'
import costsData from '@/lib/mock/costs.json'

export function useCostSummary() {
  return useQuery({
    queryKey: ['costs', 'summary'],
    queryFn: () => fetchWithMockFallback<CostSummary>(
      '/costs/summary',
      () => Promise.resolve({ default: costsData as unknown as CostSummary }),
      'useCostSummary',
    ),
  })
}

export function useCostAnomalies() {
  return useQuery({
    queryKey: ['costs', 'summary'],
    queryFn: () => fetchWithMockFallback<CostSummary>(
      '/costs/summary',
      () => Promise.resolve({ default: costsData as unknown as CostSummary }),
      'useCostAnomalies',
    ),
    select: (data) => data.anomalies,
  })
}
