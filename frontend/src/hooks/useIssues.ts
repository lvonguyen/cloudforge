import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { apiClient } from '@/lib/api'
import type { IssueListResult, IssueDetail, IssueStats, IssueUpdate } from '@/types/issue'

interface IssueListParams {
  severity?: string
  status?: string
  control_id?: string
  account_id?: string
  provider?: string
  page?: number
  per_page?: number
}

function buildIssueQuery(params: IssueListParams): string {
  const search = new URLSearchParams()
  if (params.severity) search.set('severity', params.severity)
  if (params.status) search.set('status', params.status)
  if (params.control_id) search.set('control_id', params.control_id)
  if (params.account_id) search.set('account_id', params.account_id)
  if (params.provider) search.set('provider', params.provider)
  if (params.page) search.set('page', String(params.page))
  if (params.per_page) search.set('per_page', String(params.per_page))
  const qs = search.toString()
  return `/issues${qs ? `?${qs}` : ''}`
}

export function useIssues(params: IssueListParams = {}) {
  return useQuery({
    queryKey: ['issues', params],
    queryFn: () => apiClient.get<IssueListResult>(buildIssueQuery(params)),
    staleTime: 30_000,
  })
}

export function useIssue(id: string | null) {
  return useQuery({
    queryKey: ['issues', id],
    queryFn: () => apiClient.get<IssueDetail>(`/issues/${encodeURIComponent(id!)}`),
    enabled: !!id,
    staleTime: 30_000,
  })
}

export function useIssueStats() {
  return useQuery({
    queryKey: ['issues', 'stats'],
    queryFn: () => apiClient.get<IssueStats>('/issues/stats'),
    staleTime: 60_000,
  })
}

export function useUpdateIssue() {
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: ({ id, update }: { id: string; update: IssueUpdate }) =>
      apiClient.patch<IssueDetail>(`/issues/${encodeURIComponent(id)}`, update),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['issues'] })
    },
  })
}
