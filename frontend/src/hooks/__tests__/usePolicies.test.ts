import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import { renderHook, waitFor } from '@testing-library/react'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import type { ReactNode } from 'react'
import React from 'react'
import { usePolicies } from '@/hooks/usePolicies'
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
    fetchWithMockFallback: vi.fn(async (path, mockImport, _label) => {
      try { return await client.get(path) }
      catch (err) {
        if (err instanceof MockApiError && err.status < 500) throw err
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

const mockPolicies = [
  {
    id: 'pol-001',
    name: 'No Public S3',
    namespace: 'aws',
    status: 'active',
    category: 'storage',
    evaluations: 100,
    denials: 5,
    last_updated: '2024-01-01T00:00:00Z',
  },
]

describe('usePolicies', () => {
  beforeEach(() => {
    vi.clearAllMocks()
  })

  afterEach(() => {
    vi.restoreAllMocks()
  })

  it('returns loading state initially', () => {
    vi.mocked(apiClient.get).mockReturnValue(new Promise(() => {}))
    const { result } = renderHook(() => usePolicies(), { wrapper: makeWrapper() })
    expect(result.current.isLoading).toBe(true)
  })

  it('returns data from apiClient.get on success', async () => {
    vi.mocked(apiClient.get).mockResolvedValue(mockPolicies)
    const { result } = renderHook(() => usePolicies(), { wrapper: makeWrapper() })
    await waitFor(() => expect(result.current.isSuccess).toBe(true))
    expect(result.current.data).toEqual(mockPolicies)
  })

  it('calls /policies without status param when filter is "all"', async () => {
    vi.mocked(apiClient.get).mockResolvedValue(mockPolicies)
    const { result } = renderHook(() => usePolicies('all'), { wrapper: makeWrapper() })
    await waitFor(() => expect(result.current.isSuccess).toBe(true))
    expect(vi.mocked(apiClient.get)).toHaveBeenCalledWith('/policies')
  })

  it('calls /policies without status param when no filter given', async () => {
    vi.mocked(apiClient.get).mockResolvedValue(mockPolicies)
    const { result } = renderHook(() => usePolicies(), { wrapper: makeWrapper() })
    await waitFor(() => expect(result.current.isSuccess).toBe(true))
    expect(vi.mocked(apiClient.get)).toHaveBeenCalledWith('/policies')
  })

  it('includes status param when specific filter is given', async () => {
    vi.mocked(apiClient.get).mockResolvedValue(mockPolicies)
    const { result } = renderHook(() => usePolicies('active'), { wrapper: makeWrapper() })
    await waitFor(() => expect(result.current.isSuccess).toBe(true))
    expect(vi.mocked(apiClient.get)).toHaveBeenCalledWith('/policies?status=active')
  })

  it('falls back to mock data when API returns 500', async () => {
    vi.mocked(apiClient.get).mockRejectedValue(new ApiError(500, 'Server Error'))
    const warnSpy = vi.spyOn(console, 'warn').mockImplementation(() => {})
    const { result } = renderHook(() => usePolicies(), { wrapper: makeWrapper() })
    await waitFor(() => expect(result.current.isSuccess).toBe(true))
    expect(result.current.data).toBeDefined()
    warnSpy.mockRestore()
  })

  it('rethrows 4xx ApiErrors', async () => {
    vi.mocked(apiClient.get).mockRejectedValue(new ApiError(403, 'Forbidden'))
    const { result } = renderHook(() => usePolicies(), { wrapper: makeWrapper() })
    await waitFor(() => expect(result.current.isError).toBe(true))
    expect((result.current.error as ApiError).status).toBe(403)
  })
})
