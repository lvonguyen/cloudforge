import { useQuery } from '@tanstack/react-query'
import remediationsData from '@/lib/mock/remediations.json'
import type { RemediationRecord } from '@/types/remediation'

const remediations = remediationsData as RemediationRecord[]

export function useRemediations(filters?: { status?: string; tier?: number }) {
  return useQuery({
    queryKey: ['remediations', filters],
    queryFn: async () => {
      let result = remediations
      if (filters?.status) result = result.filter(r => r.status === filters.status)
      if (filters?.tier) result = result.filter(r => r.tier === filters.tier)
      return result
    },
  })
}

export function useRemediation(id: string) {
  return useQuery({
    queryKey: ['remediations', id],
    queryFn: async () => remediations.find(r => r.id === id) ?? null,
    enabled: Boolean(id),
  })
}
