import { useQuery } from '@tanstack/react-query'
import { apiClient } from '@/lib/api'
import type { AttackPath, AttackPathStats, PaginatedResponse } from '@/types/attack-path'

export function useAttackPaths(page = 1, perPage = 20) {
  return useQuery({
    queryKey: ['attack-paths', page, perPage],
    queryFn: () => apiClient.get<PaginatedResponse<AttackPath>>(`/attack-paths?page=${page}&per_page=${perPage}`),
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
    queryFn: () => apiClient.get<AttackPathStats>('/attack-paths/stats'),
  })
}
