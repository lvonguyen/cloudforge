import { useQuery } from '@tanstack/react-query'
import costsData from '@/lib/mock/costs.json'
import type { CostSummary } from '@/types/finops'

const costSummary = costsData as unknown as CostSummary

export function useCostSummary() {
  return useQuery({
    queryKey: ['costs', 'summary'],
    queryFn: async () => costSummary,
  })
}

export function useCostAnomalies() {
  return useQuery({
    queryKey: ['costs', 'anomalies'],
    queryFn: async () => costSummary.anomalies,
  })
}
