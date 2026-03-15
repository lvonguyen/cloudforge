import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { apiClient, ApiError } from '@/lib/api'
import type { RemediationRecord } from '@/types/remediation'
import { useToast } from '@/hooks/useToast'

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
      } catch (err) {
        if (err instanceof ApiError && err.status < 500) throw err
        console.warn('[useRemediations] API unavailable, using mock data')
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
      } catch (err) {
        if (err instanceof ApiError && err.status < 500) throw err
        console.warn('[useRemediation] API unavailable, using mock data')
        const mod = await import('@/lib/mock/remediations.json')
        return (mod.default as RemediationRecord[]).find((r) => r.id === id) ?? null
      }
    },
    enabled: Boolean(id),
  })
}

export function useExecuteRemediation() {
  const qc = useQueryClient()
  const { toast } = useToast()
  return useMutation({
    mutationFn: (id: string) =>
      apiClient.post<RemediationRecord>(`/remediations/${id}/execute`, {}),
    onSuccess: () => { void qc.invalidateQueries({ queryKey: ['remediations'] }) },
    onError: (err: Error) => {
      if (err instanceof ApiError && err.status === 403) {
        toast('Remediation execution requires admin role', 'error')
      } else {
        toast(`Remediation failed: ${err.message}`, 'error')
      }
    },
  })
}
