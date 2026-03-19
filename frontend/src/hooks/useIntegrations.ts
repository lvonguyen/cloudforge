import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { apiClient, ApiError } from '@/lib/api'
import { useToast } from '@/hooks/useToast'

export interface Ticket {
  id: string
  external_id: string
  provider: string
  finding_id: string
  title: string
  status: string
  priority: string
  assignee?: string
  url?: string
  created_at: string
  updated_at: string
  metadata?: Record<string, string>
}

interface RoutingDecision {
  priority: string
  team: string
  sla_hours: number
  reason: string
}

interface RemediateResponse {
  ticket: Ticket
  routing: RoutingDecision
  workflow_id?: string
}

const MOCK_TICKET: Ticket = {
  id: 'tkt-mock-001',
  external_id: 'MOCK-a1b2c3d4',
  provider: 'mock',
  finding_id: '',
  title: 'Remediate finding',
  status: 'open',
  priority: 'high',
  assignee: 'security-ops',
  url: 'https://mock.local/tickets/MOCK-a1b2c3d4',
  created_at: '2026-03-18T10:00:00Z',
  updated_at: '2026-03-18T10:00:00Z',
}

export function useRemediateFinding() {
  const qc = useQueryClient()
  const { toast } = useToast()
  return useMutation({
    mutationFn: ({ findingId, severity, isChokePoint }: {
      findingId: string
      severity: string
      isChokePoint?: boolean
    }) =>
      apiClient.post<RemediateResponse>(`/findings/${findingId}/remediate`, {
        severity,
        is_choke_point: isChokePoint ?? false,
      }),
    onSuccess: (data, variables) => {
      void qc.invalidateQueries({ queryKey: ['findings', variables.findingId] })
      void qc.invalidateQueries({ queryKey: ['ticket', variables.findingId] })
      const url = data.ticket.url
      toast(url ? `Ticket created: ${data.ticket.external_id}` : 'Ticket created', 'success')
    },
    onError: (err: Error) => {
      if (err instanceof ApiError && err.status === 403) {
        toast('Ticket creation requires admin role', 'error')
      } else {
        toast('Failed to create ticket', 'error')
      }
    },
  })
}

export function useFindingTicket(findingId: string) {
  return useQuery({
    queryKey: ['ticket', findingId],
    queryFn: async () => {
      try {
        return await apiClient.get<Ticket>(`/findings/${findingId}/ticket`)
      } catch (err) {
        if (err instanceof ApiError && err.status === 404) return null
        if (err instanceof ApiError && err.status < 500) throw err
        console.warn('[useFindingTicket] API unavailable, using mock data')
        return { ...MOCK_TICKET, finding_id: findingId } as Ticket
      }
    },
    enabled: Boolean(findingId),
  })
}
