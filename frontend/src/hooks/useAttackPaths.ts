import { useQuery } from '@tanstack/react-query'
import { apiClient } from '@/lib/api'
import type { AttackPath, AttackPathStats } from '@/types/attack-path'

export function useAttackPaths() {
  return useQuery({
    queryKey: ['attack-paths'],
    queryFn: () => apiClient.get<AttackPath[]>('/attack-paths'),
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
