import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { apiClient, ApiError, fetchWithMockFallback, isMockFallbackEnabled } from '@/lib/api'
import type { RemediationRecord } from '@/types/remediation'
import { useToast } from '@/hooks/useToast'
import remediationsData from '@/lib/mock/remediations.json'

export function useRemediations(filters?: { status?: string; tier?: number }) {
  const params = new URLSearchParams()
  if (filters?.status) params.set('status', filters.status)
  if (filters?.tier) params.set('tier', String(filters.tier))
  const qs = params.toString()
  return useQuery({
    queryKey: ['remediations', 'list', filters],
    queryFn: () => fetchWithMockFallback<RemediationRecord[]>(
      `/remediations${qs ? `?${qs}` : ''}`,
      () => Promise.resolve({ default: remediationsData as unknown as RemediationRecord[] }),
      'useRemediations',
    ),
  })
}

export function useRemediation(id: string) {
  return useQuery({
    queryKey: ['remediations', 'detail', id],
    queryFn: async () => {
      try {
        return await apiClient.get<RemediationRecord>(`/remediations/${id}`)
      } catch (err) {
        if (err instanceof ApiError && err.status < 500) throw err
        if (!isMockFallbackEnabled()) throw err
        console.warn('[useRemediation] API unavailable, using mock data')
        return (remediationsData as unknown as RemediationRecord[]).find((r) => r.id === id) ?? null
      }
    },
    enabled: Boolean(id),
  })
}

export function usePatchRemediation() {
  const qc = useQueryClient()
  const { toast } = useToast()
  return useMutation({
    mutationFn: ({ id, status }: { id: string; status: string }) =>
      apiClient.patch<RemediationRecord>(`/remediations/${id}`, { status }),
    onSuccess: () => { void qc.invalidateQueries({ queryKey: ['remediations'] }) },
    onError: (err: Error) => {
      if (err instanceof ApiError && err.status === 403) {
        toast('Status update requires operator or admin role', 'error')
      } else {
        toast('Failed to update remediation status', 'error')
      }
    },
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
      } else if (err instanceof ApiError && err.status >= 500) {
        toast('Remediation failed due to a server error', 'error')
      } else {
        console.error('[useExecuteRemediation]', err)
        toast('Remediation request failed', 'error')
      }
    },
  })
}
