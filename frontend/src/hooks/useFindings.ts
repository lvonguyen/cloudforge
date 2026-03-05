import { useQuery } from '@tanstack/react-query'
import { apiClient } from '@/lib/api'
import type { Finding } from '@/types/compliance'

export function useFindings(filters?: { severity?: string; provider?: string; status?: string }) {
  const params = new URLSearchParams()
  if (filters?.severity) params.set('severity', filters.severity)
  if (filters?.provider) params.set('provider', filters.provider)
  if (filters?.status) params.set('status', filters.status)
  const qs = params.toString()
  return useQuery({
    queryKey: ['findings', filters],
    queryFn: () => apiClient.get<Finding[]>(`/findings${qs ? `?${qs}` : ''}`),
  })
}

export function useFinding(id: string) {
  return useQuery({
    queryKey: ['findings', id],
    queryFn: () => apiClient.get<Finding>(`/findings/${id}`),
    enabled: Boolean(id),
  })
}
