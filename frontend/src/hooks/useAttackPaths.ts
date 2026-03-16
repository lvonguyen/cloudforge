import { useQuery } from '@tanstack/react-query'
import { apiClient, ApiError } from '@/lib/api'
import type { AttackPath, AttackPathStats, PaginatedResponse } from '@/types/attack-path'

const EMPTY_RESPONSE: PaginatedResponse<AttackPath> = {
  data: [], page: 1, per_page: 20, total: 0, total_pages: 0,
}

const EMPTY_STATS: AttackPathStats = {
  total_findings: 0, findings_in_paths: 0, isolated_findings: 0,
  coverage_percent: 0, total_paths: 0, critical_paths: 0,
  high_paths: 0, medium_paths: 0, by_provider: {},
}

async function fetchAttackPaths(page: number, perPage: number): Promise<PaginatedResponse<AttackPath>> {
  try {
    return await apiClient.get<PaginatedResponse<AttackPath>>(`/attack-paths?page=${page}&per_page=${perPage}`)
  } catch (err) {
    if (err instanceof ApiError && err.status < 500) throw err
    if (import.meta.env.PROD) throw err
    console.warn('[useAttackPaths] API unavailable, returning empty paths')
    return EMPTY_RESPONSE
  }
}

async function fetchAttackPathStats(): Promise<AttackPathStats> {
  try {
    return await apiClient.get<AttackPathStats>('/attack-paths/stats')
  } catch (err) {
    if (err instanceof ApiError && err.status < 500) throw err
    if (import.meta.env.PROD) throw err
    console.warn('[useAttackPathStats] API unavailable, returning empty stats')
    return EMPTY_STATS
  }
}

export function useAttackPaths(page = 1, perPage = 20) {
  return useQuery({
    queryKey: ['attack-paths', page, perPage],
    queryFn: () => fetchAttackPaths(page, perPage),
  })
}

export function useAttackPath(id: string) {
  return useQuery({
    queryKey: ['attack-paths', id],
    queryFn: () => apiClient.get<AttackPath>(`/attack-paths/${id}`),
    enabled: Boolean(id),
  })
}

export function useAttackPathStats() {
  return useQuery({
    queryKey: ['attack-paths', 'stats'],
    queryFn: () => fetchAttackPathStats(),
  })
}
