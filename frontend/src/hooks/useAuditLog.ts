import { useQuery } from '@tanstack/react-query'
import auditData from '@/lib/mock/audit-log.json'

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

const events = auditData as AuditEvent[]

export function useAuditLog(filters?: { result?: string; actor?: string }) {
  return useQuery({
    queryKey: ['audit-log', filters],
    queryFn: async () => {
      let result = events
      if (filters?.result && filters.result !== 'all') {
        result = result.filter(e => e.result === filters.result)
      }
      if (filters?.actor && filters.actor !== 'all') {
        result = result.filter(e => e.actor === filters.actor)
      }
      return result
    },
  })
}
