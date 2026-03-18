import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { apiClient, ApiError } from '@/lib/api'
import type { ExceptionRequest, Approver } from '@/types/grc'

export function useExceptions() {
  return useQuery({
    queryKey: ['exceptions', 'pending'],
    queryFn: async () => {
      try {
        return await apiClient.get<ExceptionRequest[]>('/exceptions/pending')
      } catch (err) {
        if (err instanceof ApiError && err.status < 500) throw err
        console.warn('[useExceptions] API unavailable, returning empty')
        return [] as ExceptionRequest[]
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
    queryFn: async () => {
      try {
        return await apiClient.get<ExceptionRequest[]>('/exceptions/mine')
      } catch (err) {
        if (err instanceof ApiError && err.status < 500) throw err
        console.warn('[useMyExceptions] API unavailable, returning empty')
        return [] as ExceptionRequest[]
      }
    },
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
        console.warn(`[useException] API unavailable for ${id}`)
        return null as unknown as ExceptionRequest
      }
    },
    enabled: Boolean(id),
  })
}
