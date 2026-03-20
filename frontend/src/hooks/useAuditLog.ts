import { useQuery } from '@tanstack/react-query'
import { fetchWithMockFallback } from '@/lib/api'

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
    queryFn: () => fetchWithMockFallback<AuditEvent[]>(
      `/audit-log${qs ? `?${qs}` : ''}`,
      () => import('@/lib/mock/audit-log.json') as Promise<{ default: AuditEvent[] }>,
      'useAuditLog',
    ),
  })
}
