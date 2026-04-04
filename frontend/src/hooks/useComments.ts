import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { apiClient, ApiError } from '@/lib/api'

export interface FindingComment {
  id: string
  finding_id: string
  author: string
  body: string
  created_at: string
}

const STORAGE_KEY = (findingId: string) => `aegis_comments_${findingId}`

function isDemoMode(): boolean {
  return import.meta.env.VITE_DEMO_MODE === 'true'
}

function getStoredComments(findingId: string): FindingComment[] {
  try {
    const raw = sessionStorage.getItem(STORAGE_KEY(findingId))
    if (!raw) return []
    return JSON.parse(raw) as FindingComment[]
  } catch {
    return []
  }
}

function storeComment(findingId: string, comment: FindingComment): void {
  const existing = getStoredComments(findingId)
  existing.push(comment)
  sessionStorage.setItem(STORAGE_KEY(findingId), JSON.stringify(existing))
}

function seedIfEmpty(findingId: string): void {
  const existing = getStoredComments(findingId)
  if (existing.length > 0) return

  const now = Date.now()
  const twoHoursAgo = new Date(now - 2 * 60 * 60 * 1000).toISOString()
  const fortyFiveMinAgo = new Date(now - 45 * 60 * 1000).toISOString()

  const seeds: FindingComment[] = [
    {
      id: `seed-comment-1-${findingId}`,
      finding_id: findingId,
      author: 'Sarah Chen',
      body: 'Initial triage complete. Escalating to cloud infrastructure team for remediation.',
      created_at: twoHoursAgo,
    },
    {
      id: `seed-comment-2-${findingId}`,
      finding_id: findingId,
      author: 'Marcus Johnson',
      body: 'Confirmed affected resources. Applying compensating control while permanent fix is in progress.',
      created_at: fortyFiveMinAgo,
    },
  ]

  sessionStorage.setItem(STORAGE_KEY(findingId), JSON.stringify(seeds))
}

export function useComments(findingId: string) {
  return useQuery({
    queryKey: ['comments', findingId],
    queryFn: async () => {
      if (isDemoMode()) {
        seedIfEmpty(findingId)
        return getStoredComments(findingId)
      }

      try {
        return await apiClient.get<FindingComment[]>(`/findings/${findingId}/comments`)
      } catch (err) {
        if (err instanceof ApiError && err.status < 500) throw err
        console.warn('[useComments] API unavailable, using empty fallback')
        return []
      }
    },
    enabled: Boolean(findingId),
  })
}

export function useAddComment(findingId: string) {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: async (body: string) => {
      if (isDemoMode()) {
        const comment: FindingComment = {
          id: `comment-${Date.now()}`,
          finding_id: findingId,
          author: 'Demo User',
          body,
          created_at: new Date().toISOString(),
        }
        storeComment(findingId, comment)
        return comment
      }
      return apiClient.post<FindingComment>(`/findings/${findingId}/comments`, { body })
    },
    onSuccess: () => {
      void qc.invalidateQueries({ queryKey: ['comments', findingId] })
    },
  })
}
