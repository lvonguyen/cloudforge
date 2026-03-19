import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { apiClient, ApiError } from '@/lib/api'

export interface FindingComment {
  id: string
  finding_id: string
  author: string
  body: string
  created_at: string
}

export function useComments(findingId: string) {
  return useQuery({
    queryKey: ['comments', findingId],
    queryFn: async () => {
      try {
        return await apiClient.get<FindingComment[]>(`/findings/${findingId}/comments`)
      } catch (err) {
        if (err instanceof ApiError && err.status < 500) throw err
        console.warn('[useComments] API unavailable, using empty fallback')
        return [] as FindingComment[]
      }
    },
    enabled: Boolean(findingId),
  })
}

export function useAddComment(findingId: string) {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: (body: string) =>
      apiClient.post<FindingComment>(`/findings/${findingId}/comments`, { body }),
    onSuccess: () => {
      void qc.invalidateQueries({ queryKey: ['comments', findingId] })
    },
  })
}
