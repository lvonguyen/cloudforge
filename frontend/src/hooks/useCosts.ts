import { useQuery } from '@tanstack/react-query'
import { apiClient, ApiError } from '@/lib/api'
import type { CostSummary } from '@/types/finops'

export function useCostSummary() {
  return useQuery({
    queryKey: ['costs', 'summary'],
    queryFn: async () => {
      try {
        return await apiClient.get<CostSummary>('/costs/summary')
      } catch (err) {
        if (err instanceof ApiError && err.status < 500) throw err
        console.warn('[useCostSummary] API unavailable, using mock data')
        const mod = await import('@/lib/mock/costs.json')
        return mod.default as unknown as CostSummary
      }
    },
  })
}

export function useCostAnomalies() {
  return useQuery({
    queryKey: ['costs', 'anomalies'],
    queryFn: async () => {
      try {
        return await apiClient.get<CostSummary>('/costs/summary')
      } catch (err) {
        if (err instanceof ApiError && err.status < 500) throw err
        console.warn('[useCostAnomalies] API unavailable, using mock data')
        const mod = await import('@/lib/mock/costs.json')
        return mod.default as unknown as CostSummary
      }
    },
    select: (data) => data.anomalies,
  })
}
