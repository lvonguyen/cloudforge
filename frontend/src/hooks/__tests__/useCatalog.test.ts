import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import { renderHook, waitFor } from '@testing-library/react'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import type { ReactNode } from 'react'
import React from 'react'
import { useCatalog } from '@/hooks/useCatalog'
import { apiClient, ApiError } from '@/lib/api'

vi.mock('@/lib/api', () => ({
  ApiError: class ApiError extends Error {
    status: number
    constructor(status: number, message: string) {
      super(message)
      this.status = status
      this.name = 'ApiError'
    }
  },
  apiClient: {
    get: vi.fn(),
    post: vi.fn(),
    put: vi.fn(),
    delete: vi.fn(),
  },
}))

function makeWrapper() {
  const client = new QueryClient({
    defaultOptions: { queries: { retry: false, gcTime: 0 } },
  })
  return ({ children }: { children: ReactNode }) =>
    React.createElement(QueryClientProvider, { client }, children)
}

const mockCatalog = [
  {
    id: 'm-001',
    name: 'S3 Static Website',
    provider: 'aws',
    category: 'web',
    description: 'Static website hosted on S3',
    compliance_baseline: 'NIST-800-53',
  },
]

describe('useCatalog', () => {
  beforeEach(() => {
    vi.clearAllMocks()
  })

  afterEach(() => {
    vi.restoreAllMocks()
  })

  it('returns loading state initially', () => {
    vi.mocked(apiClient.get).mockReturnValue(new Promise(() => {}))

    const { result } = renderHook(() => useCatalog(), { wrapper: makeWrapper() })
    expect(result.current.isLoading).toBe(true)
  })

  it('returns data from apiClient.get on success', async () => {
    vi.mocked(apiClient.get).mockResolvedValue(mockCatalog)

    const { result } = renderHook(() => useCatalog(), { wrapper: makeWrapper() })
    await waitFor(() => expect(result.current.isSuccess).toBe(true))

    expect(result.current.data).toHaveLength(1)
    expect(result.current.data![0].id).toBe('m-001')
  })

  it('calls /catalog/modules with provider filter in query string', async () => {
    vi.mocked(apiClient.get).mockResolvedValue(mockCatalog)

    const filters = { provider: 'aws' }
    const { result } = renderHook(() => useCatalog(filters), { wrapper: makeWrapper() })
    await waitFor(() => expect(result.current.isSuccess).toBe(true))

    expect(vi.mocked(apiClient.get)).toHaveBeenCalledWith('/catalog/modules?provider=aws')
  })

  it('calls /catalog/modules with category filter in query string', async () => {
    vi.mocked(apiClient.get).mockResolvedValue(mockCatalog)

    const filters = { category: 'web' }
    const { result } = renderHook(() => useCatalog(filters), { wrapper: makeWrapper() })
    await waitFor(() => expect(result.current.isSuccess).toBe(true))

    expect(vi.mocked(apiClient.get)).toHaveBeenCalledWith('/catalog/modules?category=web')
  })

  it('calls /catalog/modules with search filter in query string', async () => {
    vi.mocked(apiClient.get).mockResolvedValue(mockCatalog)

    const filters = { search: 's3' }
    const { result } = renderHook(() => useCatalog(filters), { wrapper: makeWrapper() })
    await waitFor(() => expect(result.current.isSuccess).toBe(true))

    expect(vi.mocked(apiClient.get)).toHaveBeenCalledWith('/catalog/modules?search=s3')
  })

  it('includes all three filter params when provided', async () => {
    vi.mocked(apiClient.get).mockResolvedValue(mockCatalog)

    const filters = { provider: 'azure', category: 'compute', search: 'vm' }
    const { result } = renderHook(() => useCatalog(filters), { wrapper: makeWrapper() })
    await waitFor(() => expect(result.current.isSuccess).toBe(true))

    expect(vi.mocked(apiClient.get)).toHaveBeenCalledWith(
      '/catalog/modules?provider=azure&category=compute&search=vm'
    )
  })

  it('calls /catalog/modules without query string when no filters given', async () => {
    vi.mocked(apiClient.get).mockResolvedValue(mockCatalog)

    const { result } = renderHook(() => useCatalog(), { wrapper: makeWrapper() })
    await waitFor(() => expect(result.current.isSuccess).toBe(true))

    expect(vi.mocked(apiClient.get)).toHaveBeenCalledWith('/catalog/modules')
  })

  it('falls back to mock data when API returns 500', async () => {
    vi.mocked(apiClient.get).mockRejectedValue(new ApiError(500, 'Server Error'))

    const warnSpy = vi.spyOn(console, 'warn').mockImplementation(() => {})

    global.fetch = vi.fn()

    const { result } = renderHook(() => useCatalog(), { wrapper: makeWrapper() })
    await waitFor(() => expect(result.current.isSuccess).toBe(true))

    expect(result.current.data).toBeDefined()
    warnSpy.mockRestore()
  })

  it('does not suppress 4xx ApiErrors (rethrows them)', async () => {
    vi.mocked(apiClient.get).mockRejectedValue(new ApiError(404, 'Not Found'))

    const { result } = renderHook(() => useCatalog(), { wrapper: makeWrapper() })
    await waitFor(() => expect(result.current.isError).toBe(true))

    expect(result.current.error).toBeInstanceOf(ApiError)
    expect((result.current.error as ApiError).status).toBe(404)
  })
})
