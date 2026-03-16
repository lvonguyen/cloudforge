import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { apiClient, ApiError } from '@/lib/api'
import type { Finding } from '@/types/compliance'

const R2_FINDINGS_URL =
  'https://pub-878a225fb2464e2ab2e3b08d0603e04b.r2.dev/mock/findings.json'

async function fetchR2Findings(): Promise<Finding[]> {
  const res = await fetch(R2_FINDINGS_URL)
  if (!res.ok) throw new Error(`R2 fetch failed: ${res.status}`)
  return res.json()
}

async function fetchLocalMockFindings(): Promise<Finding[]> {
  const res = await fetch('/mock/findings.json')
  if (!res.ok) throw new Error(`Local mock fetch failed: ${res.status}`)
  return res.json()
}

async function fetchMockFindings(): Promise<Finding[]> {
  try {
    return await fetchR2Findings()
  } catch {
    console.warn('[useFindings] R2 unavailable, falling back to local mock')
    return fetchLocalMockFindings()
  }
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

export function useEnrichFinding() {
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: async (findingId: string) => {
      return apiClient.post<Finding>(`/findings/${findingId}/enrich`, {})
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['findings'] })
    },
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
