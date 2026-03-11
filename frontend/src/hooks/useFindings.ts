import { useQuery } from '@tanstack/react-query'
import { apiClient, ApiError } from '@/lib/api'
import type { Finding } from '@/types/compliance'

async function fetchMockFindings(): Promise<Finding[]> {
  const res = await fetch('/mock/findings.json')
  if (!res.ok) throw new Error(`Failed to load mock findings: ${res.status}`)
  return res.json()
}

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
    return fetchMockFindings()
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
        const findings = await fetchMockFindings()
        return findings.find((f) => f.id === id) ?? null
      }
    },
    enabled: Boolean(id),
  })
}
