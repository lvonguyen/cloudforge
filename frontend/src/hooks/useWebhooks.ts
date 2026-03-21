import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { apiClient, ApiError, fetchWithMockFallback } from '@/lib/api'
import { useToast } from '@/hooks/useToast'

export interface WebhookEndpoint {
  id: string
  url: string
  events: string[]
  active: boolean
  created_at: string
}

export interface WebhookDelivery {
  id: string
  endpoint_id: string
  event_id: string
  event_type: string
  status: string
  status_code?: number
  error?: string
  attempted_at: string
  duration_ms: number
}

const WEBHOOK_EVENTS = [
  'finding.created', 'finding.resolved', 'finding.escalated',
  'remediation.started', 'remediation.completed',
  'compliance.drift', 'attack_path.new',
  'exception.approved', 'exception.expiring',
  'deploy.preview',
] as const

export type WebhookEventType = (typeof WEBHOOK_EVENTS)[number]
export { WEBHOOK_EVENTS }

const MOCK_ENDPOINTS: WebhookEndpoint[] = [
  { id: 'wh-001', url: 'https://hooks.slack.com/services/T00/B00/abc', events: ['finding.created', 'finding.escalated'], active: true, created_at: '2026-03-10T08:00:00Z' },
  { id: 'wh-002', url: 'https://api.pagerduty.com/webhooks/v3', events: ['remediation.completed', 'compliance.drift'], active: true, created_at: '2026-03-12T14:30:00Z' },
  { id: 'wh-003', url: 'https://example.com/dead-endpoint', events: ['finding.created'], active: false, created_at: '2026-02-28T09:00:00Z' },
]

const MOCK_DELIVERIES: WebhookDelivery[] = [
  { id: 'del-001', endpoint_id: 'wh-001', event_id: 'evt-a1', event_type: 'finding.created', status: 'success', status_code: 200, attempted_at: '2026-03-17T12:00:00Z', duration_ms: 145 },
  { id: 'del-002', endpoint_id: 'wh-001', event_id: 'evt-a2', event_type: 'finding.escalated', status: 'success', status_code: 200, attempted_at: '2026-03-17T12:05:00Z', duration_ms: 132 },
  { id: 'del-003', endpoint_id: 'wh-003', event_id: 'evt-b1', event_type: 'finding.created', status: 'failed', status_code: 502, error: 'Bad Gateway', attempted_at: '2026-03-17T11:00:00Z', duration_ms: 3012 },
]

export function useWebhooks() {
  return useQuery({
    queryKey: ['webhooks'],
    queryFn: () => fetchWithMockFallback<WebhookEndpoint[]>(
      '/webhooks',
      () => Promise.resolve({ default: MOCK_ENDPOINTS }),
      'useWebhooks',
    ),
  })
}

export function useCreateWebhook() {
  const qc = useQueryClient()
  const { toast } = useToast()
  return useMutation({
    mutationFn: (req: { url: string; secret: string; events: string[] }) =>
      apiClient.post<WebhookEndpoint>('/webhooks', req),
    onSuccess: () => {
      void qc.invalidateQueries({ queryKey: ['webhooks'] })
      toast('Webhook endpoint registered')
    },
    onError: (err: Error) => {
      if (err instanceof ApiError && err.status === 403) {
        toast('Webhook registration requires admin role', 'error')
      } else {
        toast('Failed to register webhook', 'error')
      }
    },
  })
}

export function useDeleteWebhook() {
  const qc = useQueryClient()
  const { toast } = useToast()
  return useMutation({
    mutationFn: async (id: string) => {
      await apiClient.delete(`/webhooks/${id}`)
    },
    onSuccess: () => {
      void qc.invalidateQueries({ queryKey: ['webhooks'] })
      toast('Webhook endpoint deleted')
    },
    onError: (err: Error) => {
      if (err instanceof ApiError && err.status === 403) {
        toast('Webhook deletion requires admin role', 'error')
      } else {
        toast('Failed to delete webhook', 'error')
      }
    },
  })
}

export function useWebhookDeliveries(endpointId: string) {
  return useQuery({
    queryKey: ['webhooks', 'deliveries', endpointId],
    queryFn: async () => {
      try {
        return await apiClient.get<WebhookDelivery[]>(`/webhooks/${endpointId}/deliveries`)
      } catch (err) {
        if (err instanceof ApiError && err.status < 500) throw err
        console.warn('[useWebhookDeliveries] API unavailable, using mock data')
        return MOCK_DELIVERIES.filter(d => d.endpoint_id === endpointId)
      }
    },
    enabled: Boolean(endpointId),
  })
}
