import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { apiClient, ApiError, fetchWithMockFallback } from '@/lib/api'
import type { ExceptionRequest, Approver } from '@/types/grc'

export const MOCK_EXCEPTIONS: ExceptionRequest[] = [
  {
    id: 'exc-001',
    application_id: 'app-trade-engine',
    requestor_email: 'sarah.chen@contoso.dev',
    request_type: 'UNAPPROVED_REGION',
    policy_violated: 'REGION-001',
    resource_requested: 'ap-southeast-1 (Singapore)',
    business_case: 'APAC trading desk requires sub-10ms latency to SGX. Nearest approved region (ap-northeast-1) adds 40ms.',
    status: 'PENDING',
    approver_chain: [
      { email: 'maria.santos@contoso.dev', role: 'SECURITY_LEAD', decision: 'PENDING', comments: '' },
      { email: 'james.wright@contoso.dev', role: 'GRC_ANALYST', decision: 'PENDING', comments: '' },
    ],
    compensating_controls: ['VPN tunnel to approved region', 'Daily log replication to us-east-1'],
    created_at: '2026-03-10T09:15:00Z',
    updated_at: '2026-03-10T09:15:00Z',
  },
  {
    id: 'exc-002',
    application_id: 'app-ml-pipeline',
    requestor_email: 'alex.kumar@contoso.dev',
    request_type: 'OVERSIZED_INSTANCE',
    policy_violated: 'COST-002',
    resource_requested: 'p4d.24xlarge (8x A100 GPU)',
    business_case: 'Q2 model training sprint — need 8x A100 for 72h fine-tuning run. Current p3.2xlarge would take 3 weeks.',
    status: 'APPROVED',
    approver_chain: [
      { email: 'maria.santos@contoso.dev', role: 'SECURITY_LEAD', decision: 'APPROVED', comments: 'Approved with 72h TTL', decided_at: '2026-03-08T14:00:00Z' },
    ],
    compensating_controls: ['Auto-terminate after 72h', 'Spot instance where available'],
    expiration_date: '2026-03-15T00:00:00Z',
    created_at: '2026-03-07T16:30:00Z',
    updated_at: '2026-03-08T14:00:00Z',
  },
  {
    id: 'exc-003',
    application_id: 'app-data-lake',
    requestor_email: 'sarah.chen@contoso.dev',
    request_type: 'DATA_RESIDENCY',
    policy_violated: 'DATA-001',
    resource_requested: 'Cross-region S3 replication to eu-west-1',
    business_case: 'GDPR data subject access requests require EU-resident copy for sub-72h response SLA.',
    status: 'PENDING',
    approver_chain: [
      { email: 'james.wright@contoso.dev', role: 'GRC_ANALYST', decision: 'PENDING', comments: '' },
    ],
    compensating_controls: ['Server-side encryption (SSE-KMS)', 'Bucket policy restricts to VPC endpoint'],
    created_at: '2026-03-12T11:00:00Z',
    updated_at: '2026-03-12T11:00:00Z',
  },
  {
    id: 'exc-004',
    application_id: 'app-trade-engine',
    requestor_email: 'alex.kumar@contoso.dev',
    request_type: 'NETWORK_EXPOSURE',
    policy_violated: 'NET-003',
    resource_requested: 'Public ALB with WAF for partner API',
    business_case: 'Partner integration requires public endpoint. Internal VPN not feasible for 200+ partners.',
    status: 'REJECTED',
    approver_chain: [
      { email: 'maria.santos@contoso.dev', role: 'SECURITY_LEAD', decision: 'REJECTED', comments: 'Use API Gateway with mutual TLS instead', decided_at: '2026-03-05T10:00:00Z' },
    ],
    compensating_controls: [],
    created_at: '2026-03-04T08:00:00Z',
    updated_at: '2026-03-05T10:00:00Z',
  },
  {
    id: 'exc-005',
    application_id: 'app-ml-pipeline',
    requestor_email: 'sarah.chen@contoso.dev',
    request_type: 'RESTRICTED_SERVICE',
    policy_violated: 'SVC-001',
    resource_requested: 'Amazon Bedrock (Claude Haiku)',
    business_case: 'Finding enrichment service needs LLM inference. Bedrock is FedRAMP Moderate authorized.',
    status: 'PENDING',
    approver_chain: [
      { email: 'maria.santos@contoso.dev', role: 'SECURITY_LEAD', decision: 'PENDING', comments: '' },
    ],
    compensating_controls: ['Model invocation logging enabled', 'No PII in prompts (validated by guardrail)'],
    created_at: '2026-03-14T13:45:00Z',
    updated_at: '2026-03-14T13:45:00Z',
  },
]

export function useExceptions() {
  return useQuery({
    queryKey: ['exceptions', 'pending'],
    queryFn: async () => {
      try {
        return await apiClient.get<ExceptionRequest[]>('/exceptions/pending')
      } catch (err) {
        if (err instanceof ApiError && err.status < 500) throw err
        console.warn('[useExceptions] API unavailable, using mock data')
        return MOCK_EXCEPTIONS.filter(e => e.status === 'PENDING')
      }
    },
  })
}

export function useCreateException() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: (req: Partial<ExceptionRequest>) =>
      apiClient.post<ExceptionRequest>('/exceptions', req),
    onSuccess: () => { void qc.invalidateQueries({ queryKey: ['exceptions'] }) },
  })
}

export function useApproveException() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: ({ id, approver }: { id: string; approver: Approver }) =>
      apiClient.post<ExceptionRequest>(`/exceptions/${id}/approve`, approver),
    onSuccess: () => { void qc.invalidateQueries({ queryKey: ['exceptions'] }) },
  })
}

export function useRejectException() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: ({ id, approver }: { id: string; approver: Approver }) =>
      apiClient.post<ExceptionRequest>(`/exceptions/${id}/reject`, approver),
    onSuccess: () => { void qc.invalidateQueries({ queryKey: ['exceptions'] }) },
  })
}

export function useWithdrawException() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: (id: string) =>
      apiClient.post<ExceptionRequest>(`/exceptions/${id}/withdraw`, {}),
    onSuccess: () => { void qc.invalidateQueries({ queryKey: ['exceptions'] }) },
  })
}

export function useMyExceptions() {
  return useQuery({
    queryKey: ['exceptions', 'mine'],
    queryFn: () => fetchWithMockFallback<ExceptionRequest[]>(
      '/exceptions/mine',
      () => Promise.resolve({ default: MOCK_EXCEPTIONS }),
      'useMyExceptions',
    ),
  })
}

export function useException(id: string) {
  return useQuery({
    queryKey: ['exceptions', id],
    queryFn: async () => {
      try {
        return await apiClient.get<ExceptionRequest>(`/exceptions/${id}`)
      } catch (err) {
        if (err instanceof ApiError && err.status < 500) throw err
        console.warn(`[useException] API unavailable for ${id}, using mock data`)
        return MOCK_EXCEPTIONS.find(e => e.id === id)
      }
    },
    enabled: Boolean(id),
  })
}
