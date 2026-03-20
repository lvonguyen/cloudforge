import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import { renderHook, waitFor } from '@testing-library/react'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import type { ReactNode } from 'react'
import React from 'react'
import { useAuditLog } from '@/hooks/useAuditLog'
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

const mockAuditEvents = [
  {
    id: 'e-001',
    timestamp: '2024-01-01T00:00:00Z',
    actor: 'admin1@contoso.dev',
    actor_role: 'admin',
    action: 'policy.create',
    resource: 'policy-001',
    result: 'success',
    ip: '10.0.0.1',
  },
]

describe('useAuditLog', () => {
  beforeEach(() => {
    vi.clearAllMocks()
  })

  afterEach(() => {
    vi.restoreAllMocks()
  })

  it('returns loading state initially', () => {
    vi.mocked(apiClient.get).mockReturnValue(new Promise(() => {}))

    const { result } = renderHook(() => useAuditLog(), { wrapper: makeWrapper() })
    expect(result.current.isLoading).toBe(true)
  })

  it('returns data from apiClient.get on success', async () => {
    vi.mocked(apiClient.get).mockResolvedValue(mockAuditEvents)

    const { result } = renderHook(() => useAuditLog(), { wrapper: makeWrapper() })
    await waitFor(() => expect(result.current.isSuccess).toBe(true))

    expect(result.current.data).toHaveLength(1)
    expect(result.current.data![0].id).toBe('e-001')
  })

  it('calls /audit-log with result filter in query string', async () => {
    vi.mocked(apiClient.get).mockResolvedValue(mockAuditEvents)

    const filters = { result: 'success' }
    const { result } = renderHook(() => useAuditLog(filters), { wrapper: makeWrapper() })
    await waitFor(() => expect(result.current.isSuccess).toBe(true))

    expect(vi.mocked(apiClient.get)).toHaveBeenCalledWith('/audit-log?result=success')
  })

  it('calls /audit-log with actor filter in query string', async () => {
    vi.mocked(apiClient.get).mockResolvedValue(mockAuditEvents)

    const filters = { actor: 'admin1@contoso.dev' }
    const { result } = renderHook(() => useAuditLog(filters), { wrapper: makeWrapper() })
    await waitFor(() => expect(result.current.isSuccess).toBe(true))

    expect(vi.mocked(apiClient.get)).toHaveBeenCalledWith('/audit-log?actor=admin1%40contoso.dev')
  })

  it('strips all value from result filter', async () => {
    vi.mocked(apiClient.get).mockResolvedValue(mockAuditEvents)

    const filters = { result: 'all' }
    const { result } = renderHook(() => useAuditLog(filters), { wrapper: makeWrapper() })
    await waitFor(() => expect(result.current.isSuccess).toBe(true))

    expect(vi.mocked(apiClient.get)).toHaveBeenCalledWith('/audit-log')
  })

  it('strips all value from actor filter', async () => {
    vi.mocked(apiClient.get).mockResolvedValue(mockAuditEvents)

    const filters = { actor: 'all' }
    const { result } = renderHook(() => useAuditLog(filters), { wrapper: makeWrapper() })
    await waitFor(() => expect(result.current.isSuccess).toBe(true))

    expect(vi.mocked(apiClient.get)).toHaveBeenCalledWith('/audit-log')
  })

  it('includes both result and actor filters when provided', async () => {
    vi.mocked(apiClient.get).mockResolvedValue(mockAuditEvents)

    const filters = { result: 'denied', actor: 'operator@contoso.dev' }
    const { result } = renderHook(() => useAuditLog(filters), { wrapper: makeWrapper() })
    await waitFor(() => expect(result.current.isSuccess).toBe(true))

    expect(vi.mocked(apiClient.get)).toHaveBeenCalledWith(
      '/audit-log?result=denied&actor=operator%40contoso.dev'
    )
  })

  it('falls back to mock data when API returns 500', async () => {
    vi.mocked(apiClient.get).mockRejectedValue(new ApiError(500, 'Server Error'))

    const warnSpy = vi.spyOn(console, 'warn').mockImplementation(() => {})

    global.fetch = vi.fn()

    const { result } = renderHook(() => useAuditLog(), { wrapper: makeWrapper() })
    await waitFor(() => expect(result.current.isSuccess).toBe(true))

    expect(result.current.data).toBeDefined()
    warnSpy.mockRestore()
  })

  it('does not suppress 4xx ApiErrors (rethrows them)', async () => {
    vi.mocked(apiClient.get).mockRejectedValue(new ApiError(403, 'Forbidden'))

    const { result } = renderHook(() => useAuditLog(), { wrapper: makeWrapper() })
    await waitFor(() => expect(result.current.isError).toBe(true))

    expect(result.current.error).toBeInstanceOf(ApiError)
    expect((result.current.error as ApiError).status).toBe(403)
  })
})
