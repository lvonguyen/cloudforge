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
    queryFn: async () => {
      try {
        return await apiClient.get<RemediationRecord[]>(`/remediations${qs ? `?${qs}` : ''}`)
      } catch {
        const mod = await import('@/lib/mock/remediations.json')
        return mod.default as RemediationRecord[]
      }
    },
  })
}

export function useRemediation(id: string) {
  return useQuery({
    queryKey: ['remediations', id],
    queryFn: async () => {
      try {
        return await apiClient.get<RemediationRecord>(`/remediations/${id}`)
      } catch {
        const mod = await import('@/lib/mock/remediations.json')
        return (mod.default as RemediationRecord[]).find((r) => r.id === id) ?? null
      }
    },
    enabled: Boolean(id),
  })
}
