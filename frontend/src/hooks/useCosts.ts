import { useQuery } from '@tanstack/react-query'
import { apiClient } from '@/lib/api'
import type { CostSummary } from '@/types/finops'

export function useCostSummary() {
  return useQuery({
    queryKey: ['costs', 'summary'],
    queryFn: () => apiClient.get<CostSummary>('/costs/summary'),
  })
}

export function useCostAnomalies() {
  return useQuery({
    queryKey: ['costs', 'anomalies'],
    queryFn: async () => {
      const summary = await apiClient.get<CostSummary>('/costs/summary')
      return summary.anomalies
    },
  })
}
