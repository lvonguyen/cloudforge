import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import { renderHook, waitFor } from '@testing-library/react'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import type { ReactNode } from 'react'
import React from 'react'
import { useRemediations, useRemediation } from '@/hooks/useRemediations'
import { apiClient, ApiError } from '@/lib/api'

vi.mock('@/lib/api', () => {
  class MockApiError extends Error {
    status: number
    constructor(status: number, message: string) {
      super(message)
      this.status = status
      this.name = 'ApiError'
    }
  }
  const client = {
    get: vi.fn(),
    post: vi.fn(),
    put: vi.fn(),
    delete: vi.fn(),
  }
  return {
    ApiError: MockApiError,
    apiClient: client,
    isMockFallbackEnabled: () =>
      import.meta.env.VITE_DEMO_MODE === 'true' || import.meta.env.VITE_ENABLE_MOCK_FALLBACK === 'true',
    fetchWithMockFallback: vi.fn(async (path, mockImport, _label) => {
      try { return await client.get(path) }
      catch (err) {
        if (err instanceof MockApiError && err.status < 500) throw err
        if (import.meta.env.VITE_DEMO_MODE !== 'true' && import.meta.env.VITE_ENABLE_MOCK_FALLBACK !== 'true') {
          throw err
        }
        const mod = await mockImport()
        return mod.default
      }
    }),
  }
})

function makeWrapper() {
  const client = new QueryClient({
    defaultOptions: { queries: { retry: false, gcTime: 0 } },
  })
  return ({ children }: { children: ReactNode }) =>
    React.createElement(QueryClientProvider, { client }, children)
}

const mockRemediations = [
  {
    id: 'rem-001',
    finding_id: 'f-001',
    status: 'pending',
    tier: 1,
    title: 'Fix S3 bucket ACL',
  },
]

describe('useRemediations', () => {
  beforeEach(() => {
    vi.clearAllMocks()
  })

  afterEach(() => {
    vi.restoreAllMocks()
    vi.unstubAllEnvs()
  })

  it('returns loading state initially', () => {
    vi.mocked(apiClient.get).mockReturnValue(new Promise(() => {}))
    const { result } = renderHook(() => useRemediations(), { wrapper: makeWrapper() })
    expect(result.current.isLoading).toBe(true)
  })

  it('returns data from apiClient.get on success', async () => {
    vi.mocked(apiClient.get).mockResolvedValue(mockRemediations)
    const { result } = renderHook(() => useRemediations(), { wrapper: makeWrapper() })
    await waitFor(() => expect(result.current.isSuccess).toBe(true))
    expect(result.current.data).toEqual(mockRemediations)
  })

  it('calls /remediations without query string when no filters', async () => {
    vi.mocked(apiClient.get).mockResolvedValue(mockRemediations)
    const { result } = renderHook(() => useRemediations(), { wrapper: makeWrapper() })
    await waitFor(() => expect(result.current.isSuccess).toBe(true))
    expect(vi.mocked(apiClient.get)).toHaveBeenCalledWith('/remediations')
  })

  it('includes status filter in query string', async () => {
    vi.mocked(apiClient.get).mockResolvedValue(mockRemediations)
    const { result } = renderHook(() => useRemediations({ status: 'pending' }), { wrapper: makeWrapper() })
    await waitFor(() => expect(result.current.isSuccess).toBe(true))
    expect(vi.mocked(apiClient.get)).toHaveBeenCalledWith('/remediations?status=pending')
  })

  it('includes tier filter in query string', async () => {
    vi.mocked(apiClient.get).mockResolvedValue(mockRemediations)
    const { result } = renderHook(() => useRemediations({ tier: 1 }), { wrapper: makeWrapper() })
    await waitFor(() => expect(result.current.isSuccess).toBe(true))
    expect(vi.mocked(apiClient.get)).toHaveBeenCalledWith('/remediations?tier=1')
  })

  it('falls back to mock data when API returns 500', async () => {
    vi.stubEnv('VITE_ENABLE_MOCK_FALLBACK', 'true')
    vi.mocked(apiClient.get).mockRejectedValue(new ApiError(500, 'Server Error'))
    const warnSpy = vi.spyOn(console, 'warn').mockImplementation(() => {})
    const { result } = renderHook(() => useRemediations(), { wrapper: makeWrapper() })
    await waitFor(() => expect(result.current.isSuccess).toBe(true))
    expect(result.current.data).toBeDefined()
    warnSpy.mockRestore()
  })

  it('surfaces 500 errors when mock fallback is disabled', async () => {
    vi.mocked(apiClient.get).mockRejectedValue(new ApiError(500, 'Server Error'))
    const { result } = renderHook(() => useRemediations(), { wrapper: makeWrapper() })
    await waitFor(() => expect(result.current.isError).toBe(true))
    expect((result.current.error as ApiError).status).toBe(500)
  })

  it('rethrows 4xx ApiErrors', async () => {
    vi.mocked(apiClient.get).mockRejectedValue(new ApiError(403, 'Forbidden'))
    const { result } = renderHook(() => useRemediations(), { wrapper: makeWrapper() })
    await waitFor(() => expect(result.current.isError).toBe(true))
    expect((result.current.error as ApiError).status).toBe(403)
  })
})

describe('useRemediation', () => {
  beforeEach(() => {
    vi.clearAllMocks()
  })

  it('is disabled when id is empty string', () => {
    const { result } = renderHook(() => useRemediation(''), { wrapper: makeWrapper() })
    expect(result.current.fetchStatus).toBe('idle')
  })

  it('fetches single remediation by id', async () => {
    vi.mocked(apiClient.get).mockResolvedValue(mockRemediations[0])
    const { result } = renderHook(() => useRemediation('rem-001'), { wrapper: makeWrapper() })
    await waitFor(() => expect(result.current.isSuccess).toBe(true))
    expect(vi.mocked(apiClient.get)).toHaveBeenCalledWith('/remediations/rem-001')
  })
})
