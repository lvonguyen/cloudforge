import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { apiClient } from '@/lib/api'
import type { ExceptionRequest, Approver } from '@/types/grc'

export function useExceptions() {
  return useQuery({
    queryKey: ['exceptions', 'pending'],
    queryFn: () => apiClient.get<ExceptionRequest[]>('/exceptions/pending'),
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
