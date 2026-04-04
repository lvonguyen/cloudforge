import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import { renderHook, waitFor } from '@testing-library/react'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import type { ReactNode } from 'react'
import React from 'react'
import { useComments, useAddComment } from '@/hooks/useComments'
import { apiClient } from '@/lib/api'
import type { FindingComment } from '@/hooks/useComments'

vi.mock('@/lib/api', () => {
  class _ApiError extends Error {
    status: number
    constructor(status: number, message: string) {
      super(message)
      this.status = status
      this.name = 'ApiError'
    }
  }
  return {
    apiClient: {
      get: vi.fn(),
      post: vi.fn(),
      put: vi.fn(),
      delete: vi.fn(),
    },
    ApiError: _ApiError,
  }
})

function makeWrapper() {
  const client = new QueryClient({
    defaultOptions: { queries: { retry: false, gcTime: 0 } },
  })
  return ({ children }: { children: ReactNode }) =>
    React.createElement(QueryClientProvider, { client }, children)
}

const mockComments: FindingComment[] = [
  {
    id: 'c-001',
    finding_id: 'f-123',
    author: 'admin@contoso.dev',
    body: 'This needs urgent attention',
    created_at: '2026-03-18T10:00:00Z',
  },
  {
    id: 'c-002',
    finding_id: 'f-123',
    author: 'operator@contoso.dev',
    body: 'Remediation in progress',
    created_at: '2026-03-18T11:00:00Z',
  },
]

describe('useComments', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    sessionStorage.clear()
  })

  afterEach(() => {
    vi.unstubAllEnvs()
    sessionStorage.clear()
  })

  it('returns comments from API', async () => {
    vi.mocked(apiClient.get).mockResolvedValue(mockComments)
    const { result } = renderHook(() => useComments('f-123'), { wrapper: makeWrapper() })
    await waitFor(() => expect(result.current.isSuccess).toBe(true))
    expect(result.current.data).toEqual(mockComments)
    expect(vi.mocked(apiClient.get)).toHaveBeenCalledWith('/findings/f-123/comments')
  })

  it('returns empty array on API failure', async () => {
    vi.mocked(apiClient.get).mockRejectedValue(new Error('network error'))
    const { result } = renderHook(() => useComments('f-123'), { wrapper: makeWrapper() })
    await waitFor(() => expect(result.current.isSuccess).toBe(true))
    expect(result.current.data).toEqual([])
  })

  it('returns seeded local comments in demo mode without calling the API', async () => {
    vi.stubEnv('VITE_DEMO_MODE', 'true')

    const { result } = renderHook(() => useComments('f-123'), { wrapper: makeWrapper() })
    await waitFor(() => expect(result.current.isSuccess).toBe(true))

    expect(result.current.data).toHaveLength(2)
    expect(vi.mocked(apiClient.get)).not.toHaveBeenCalled()
  })

  it('is disabled when findingId is empty', () => {
    const { result } = renderHook(() => useComments(''), { wrapper: makeWrapper() })
    expect(result.current.fetchStatus).toBe('idle')
  })
})

describe('useAddComment', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    sessionStorage.clear()
  })

  afterEach(() => {
    vi.unstubAllEnvs()
    sessionStorage.clear()
  })

  it('posts comment via apiClient', async () => {
    const created: FindingComment = {
      id: 'c-new',
      finding_id: 'f-123',
      author: 'test-user',
      body: 'new comment',
      created_at: '2026-03-18T12:00:00Z',
    }
    vi.mocked(apiClient.post).mockResolvedValue(created)

    const { result } = renderHook(() => useAddComment('f-123'), { wrapper: makeWrapper() })
    result.current.mutate('new comment')

    await waitFor(() => expect(result.current.isSuccess).toBe(true))
    expect(vi.mocked(apiClient.post)).toHaveBeenCalledWith('/findings/f-123/comments', { body: 'new comment' })
  })
})
