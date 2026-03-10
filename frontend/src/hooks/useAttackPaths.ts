import { useQuery } from '@tanstack/react-query'
import { apiClient } from '@/lib/api'
import type { AttackPath, AttackPathStats } from '@/types/attack-path'

export function useAttackPaths() {
  return useQuery({
    queryKey: ['attack-paths'],
    queryFn: async () => {
      try {
        return await apiClient.get<AttackPath[]>('/attack-paths')
      } catch (err) {
        throw err
      }
    },
  })
}

export function useAttackPath(id: string) {
  return useQuery({
    queryKey: ['attack-paths', id],
    queryFn: async () => {
      try {
        return await apiClient.get<AttackPath>(`/attack-paths/${id}`)
      } catch (err) {
        throw err
      }
    },
    enabled: Boolean(id),
  })
}

export function useAttackPathStats() {
  return useQuery({
    queryKey: ['attack-paths', 'stats'],
    queryFn: async () => {
      try {
        return await apiClient.get<AttackPathStats>('/attack-paths/stats')
      } catch (err) {
        throw err
      }
    },
  })
}
