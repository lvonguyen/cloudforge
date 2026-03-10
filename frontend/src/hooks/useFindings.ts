import { useQuery } from '@tanstack/react-query'
import { apiClient, ApiError } from '@/lib/api'
import type { Finding } from '@/types/compliance'

async function fetchFindings(filters?: { severity?: string; provider?: string; status?: string }): Promise<Finding[]> {
  const params = new URLSearchParams()
  if (filters?.severity) params.set('severity', filters.severity)
  if (filters?.provider) params.set('provider', filters.provider)
  if (filters?.status) params.set('status', filters.status)
  const qs = params.toString()
  try {
    return await apiClient.get<Finding[]>(`/findings${qs ? `?${qs}` : ''}`)
  } catch (err) {
    if (err instanceof ApiError && err.status < 500) throw err
    console.warn('[useFindings] API unavailable, using mock data')
    const mod = await import('@/lib/mock/findings.json')
    return mod.default as unknown as Finding[]
  }
}

export function useFindings(filters?: { severity?: string; provider?: string; status?: string }) {
  return useQuery({
    queryKey: ['findings', filters],
    queryFn: () => fetchFindings(filters),
  })
}

export function useFinding(id: string) {
  return useQuery({
    queryKey: ['findings', id],
    queryFn: async () => {
      try {
        return await apiClient.get<Finding>(`/findings/${id}`)
      } catch (err) {
        if (err instanceof ApiError && err.status < 500) throw err
        console.warn('[useFinding] API unavailable, using mock data')
        const mod = await import('@/lib/mock/findings.json')
        return (mod.default as unknown as Finding[]).find((f) => f.id === id) ?? null
      }
    },
    enabled: Boolean(id),
  })
}
