import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { apiClient, ApiError, isMockFallbackEnabled } from '@/lib/api'
import { useToast } from '@/hooks/useToast'
import type { TicketComment, TicketSyncResult } from '@/types/remediation'

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

interface RemediateFindingInput {
  findingId: string
  severity?: string
  isChokePoint?: boolean
  assignee?: string
  provider?: string
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
  url: undefined,
  created_at: '2026-03-18T10:00:00Z',
  updated_at: '2026-03-18T10:00:00Z',
}

function normalizeProvider(provider?: string): string | undefined {
  const normalized = provider?.trim().toLowerCase()
  return normalized ? normalized : undefined
}

function mockExternalId(provider: string): string {
  const suffix = Math.random().toString(36).slice(2, 8).toUpperCase()
  switch (provider) {
    case 'jira':
      return `JIRA-${suffix}`
    case 'asana':
      return `ASANA-${suffix}`
    case 'servicenow':
      return `SNOW-${suffix}`
    case 'ado':
      return `ADO-${suffix}`
    default:
      return `MOCK-${suffix}`
  }
}

export function useRemediateFinding() {
  const qc = useQueryClient()
  const { toast } = useToast()
  return useMutation({
    mutationFn: async ({ findingId, severity, isChokePoint, assignee, provider }: RemediateFindingInput) => {
      const cachedFinding = qc.getQueryData<{ severity?: string } | null>(['findings', findingId])
      const normalizedProvider = normalizeProvider(provider)
      const effectiveSeverity = severity ?? cachedFinding?.severity ?? 'MEDIUM'

      if (import.meta.env.VITE_DEMO_MODE === 'true') {
        const ticketProvider = normalizedProvider ?? 'mock'
        return {
          ticket: {
            ...MOCK_TICKET,
            external_id: mockExternalId(ticketProvider),
            provider: ticketProvider,
            finding_id: findingId,
            title: `Remediate ${findingId}`,
            assignee: assignee?.trim() || MOCK_TICKET.assignee,
            metadata: {
              requested_provider: ticketProvider,
              requested_assignee: assignee?.trim() || '',
            },
          },
          routing: {
            priority: effectiveSeverity === 'CRITICAL' ? 'P1' : 'P2',
            team: 'security-ops',
            sla_hours: effectiveSeverity === 'CRITICAL' ? 4 : 24,
            reason: normalizedProvider ? `Auto-routed to ${normalizedProvider}` : 'Auto-routed',
          },
        } as RemediateResponse
      }
      return apiClient.post<RemediateResponse>(`/findings/${findingId}/remediate`, {
        severity: effectiveSeverity,
        is_choke_point: isChokePoint ?? false,
        assignee: assignee?.trim() || undefined,
        provider: normalizedProvider,
      })
    },
    onSuccess: (data, variables) => {
      void qc.invalidateQueries({ queryKey: ['findings', variables.findingId] })
      qc.setQueryData(['ticket', variables.findingId], data.ticket)
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
      if (import.meta.env.VITE_DEMO_MODE === 'true') {
        return { ...MOCK_TICKET, finding_id: findingId } as Ticket
      }
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

const MOCK_COMMENTS: TicketComment[] = [
  {
    id: 'tc-seed-1',
    ticket_id: 'tkt-mock-001',
    author: 'Sarah Chen',
    body: 'Ticket created from Aegis. Escalating to infrastructure team for remediation.',
    created_at: new Date(Date.now() - 3 * 60 * 60 * 1000).toISOString(),
  },
  {
    id: 'tc-seed-2',
    ticket_id: 'tkt-mock-001',
    author: 'Marcus Johnson',
    body: 'Confirmed scope of impact. Applying compensating controls while permanent fix is deployed.',
    created_at: new Date(Date.now() - 45 * 60 * 1000).toISOString(),
  },
]

export function useTicketComments(findingId: string) {
  return useQuery({
    queryKey: ['ticket-comments', findingId],
    queryFn: async () => {
      if (import.meta.env.VITE_DEMO_MODE === 'true') {
        return MOCK_COMMENTS
      }
      try {
        return await apiClient.get<TicketComment[]>(`/findings/${findingId}/ticket/comments`)
      } catch (err) {
        if (err instanceof ApiError && err.status < 500) throw err
        if (!isMockFallbackEnabled()) return []
        console.warn('[useTicketComments] API unavailable, using mock data')
        return MOCK_COMMENTS
      }
    },
    enabled: !!findingId,
    refetchInterval: 30_000,
  })
}

export function useAddTicketComment(findingId: string) {
  const qc = useQueryClient()
  const { toast } = useToast()
  return useMutation({
    mutationFn: async (body: string) => {
      if (import.meta.env.VITE_DEMO_MODE === 'true') {
        const comment: TicketComment = {
          id: `tc-${Date.now()}`,
          ticket_id: 'tkt-mock-001',
          author: 'Demo User',
          body,
          created_at: new Date().toISOString(),
        }
        return comment
      }
      return apiClient.post<TicketComment>(`/findings/${findingId}/ticket/comments`, { body })
    },
    onSuccess: (comment) => {
      qc.setQueryData<TicketComment[]>(['ticket-comments', findingId], (current) => {
        const existing = current ?? []
        return [...existing, comment]
      })
    },
    onError: (err: Error) => {
      if (err instanceof ApiError && err.status === 403) {
        toast('Adding ticket comments requires admin role', 'error')
      } else {
        toast('Failed to add comment', 'error')
      }
    },
  })
}

export function useSyncTicketStatus(findingId: string) {
  const qc = useQueryClient()
  const { toast } = useToast()
  return useMutation({
    mutationFn: async () => {
      if (import.meta.env.VITE_DEMO_MODE === 'true') {
        return {
          ticket_id: 'tkt-mock-001',
          status: 'in_progress',
          synced_at: new Date().toISOString(),
        } as TicketSyncResult
      }
      return apiClient.post<TicketSyncResult>(`/findings/${findingId}/ticket/sync`, {})
    },
    onSuccess: (result) => {
      qc.setQueryData<Ticket | null>(['ticket', findingId], (current) => {
        if (!current) return current
        return {
          ...current,
          status: result.status,
          updated_at: result.synced_at,
        }
      })
      toast('Ticket status synced')
    },
    onError: (err: Error) => {
      if (err instanceof ApiError && err.status === 403) {
        toast('Sync requires admin role', 'error')
      } else {
        toast('Failed to sync ticket status', 'error')
      }
    },
  })
}
