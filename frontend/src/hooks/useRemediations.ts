import { useQuery } from '@tanstack/react-query'
import { apiClient } from '@/lib/api'
import type { RemediationRecord } from '@/types/remediation'

export function useRemediations(filters?: { status?: string; tier?: number }) {
  const params = new URLSearchParams()
  if (filters?.status) params.set('status', filters.status)
  if (filters?.tier) params.set('tier', String(filters.tier))
  const qs = params.toString()
  return useQuery({
    queryKey: ['remediations', filters],
    queryFn: () => apiClient.get<RemediationRecord[]>(`/remediations${qs ? `?${qs}` : ''}`),
  })
}

export function useRemediation(id: string) {
  return useQuery({
    queryKey: ['remediations', id],
    queryFn: () => apiClient.get<RemediationRecord>(`/remediations/${id}`),
    enabled: Boolean(id),
  })
}
