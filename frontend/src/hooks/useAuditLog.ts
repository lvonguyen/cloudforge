import { useQuery } from '@tanstack/react-query'
import { apiClient } from '@/lib/api'

interface AuditEvent {
  id: string
  timestamp: string
  actor: string
  actor_role: string
  action: string
  resource: string
  result: 'success' | 'denied' | 'error'
  ip: string
}

export function useAuditLog(filters?: { result?: string; actor?: string }) {
  const params = new URLSearchParams()
  if (filters?.result && filters.result !== 'all') params.set('result', filters.result)
  if (filters?.actor && filters.actor !== 'all') params.set('actor', filters.actor)
  const qs = params.toString()
  return useQuery({
    queryKey: ['audit-log', filters],
    queryFn: async () => {
      try {
        return await apiClient.get<AuditEvent[]>(`/audit-log${qs ? `?${qs}` : ''}`)
      } catch {
        const mod = await import('@/lib/mock/audit-log.json')
        return mod.default as AuditEvent[]
      }
    },
  })
}
