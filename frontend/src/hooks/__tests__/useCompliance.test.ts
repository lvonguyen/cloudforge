import { describe, it, expect, vi, beforeEach } from 'vitest'
import { renderHook, waitFor } from '@testing-library/react'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import type { ReactNode } from 'react'
import React from 'react'
import { useCompliance } from '@/hooks/useCompliance'
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

const mockFrameworks = [
  {
    id: 'soc2',
    name: 'SOC 2 Type II',
    description: 'SOC 2 compliance framework',
    total_controls: 64,
    controls_passing: 58,
    controls_failing: 6,
    score: 90.6,
    category: 'security',
  },
  {
    id: 'pci-dss',
    name: 'PCI DSS v4.0',
    description: 'Payment card industry standard',
    total_controls: 300,
    controls_passing: 261,
    controls_failing: 39,
    score: 87.0,
    category: 'payment',
  },
]

describe('useCompliance', () => {
  beforeEach(() => {
    vi.clearAllMocks()
  })

  it('is in loading state initially', () => {
    vi.mocked(apiClient.get).mockReturnValue(new Promise(() => {}))

    const { result } = renderHook(() => useCompliance(), { wrapper: makeWrapper() })
    expect(result.current.isLoading).toBe(true)
  })

  it('returns framework data on success', async () => {
    vi.mocked(apiClient.get).mockResolvedValue(mockFrameworks)

    const { result } = renderHook(() => useCompliance(), { wrapper: makeWrapper() })
    await waitFor(() => expect(result.current.isSuccess).toBe(true))

    expect(result.current.data).toHaveLength(2)
    expect(result.current.data![0].id).toBe('soc2')
    expect(result.current.data![1].id).toBe('pci-dss')
  })

  it('calls the correct API endpoint', async () => {
    vi.mocked(apiClient.get).mockResolvedValue(mockFrameworks)

    const { result } = renderHook(() => useCompliance(), { wrapper: makeWrapper() })
    await waitFor(() => expect(result.current.isSuccess).toBe(true))

    expect(vi.mocked(apiClient.get)).toHaveBeenCalledWith('/compliance/frameworks')
  })

  it('framework data includes expected fields', async () => {
    vi.mocked(apiClient.get).mockResolvedValue(mockFrameworks)

    const { result } = renderHook(() => useCompliance(), { wrapper: makeWrapper() })
    await waitFor(() => expect(result.current.isSuccess).toBe(true))

    const first = result.current.data![0]
    expect(first).toHaveProperty('id')
    expect(first).toHaveProperty('name')
    expect(first).toHaveProperty('score')
    expect(first).toHaveProperty('total_controls')
    expect(first).toHaveProperty('controls_passing')
    expect(first).toHaveProperty('controls_failing')
  })

  it('uses the correct react-query key ["compliance", "frameworks"]', async () => {
    vi.mocked(apiClient.get).mockResolvedValue(mockFrameworks)

    const client = new QueryClient({
      defaultOptions: { queries: { retry: false, gcTime: 0 } },
    })
    const wrapper = ({ children }: { children: ReactNode }) =>
      React.createElement(QueryClientProvider, { client }, children)

    const { result } = renderHook(() => useCompliance(), { wrapper })
    await waitFor(() => expect(result.current.isSuccess).toBe(true))

    // If the query key is correct, the cache will have data at that key
    const cached = client.getQueryData(['compliance', 'frameworks'])
    expect(cached).toBeDefined()
    expect(Array.isArray(cached)).toBe(true)
  })

  it('rethrows 4xx errors without falling back', async () => {
    vi.mocked(apiClient.get).mockRejectedValue(new ApiError(403, 'Forbidden'))

    const { result } = renderHook(() => useCompliance(), { wrapper: makeWrapper() })
    await waitFor(() => expect(result.current.isError).toBe(true))

    expect((result.current.error as ApiError).status).toBe(403)
  })

  it('score is a number between 0 and 100', async () => {
    vi.mocked(apiClient.get).mockResolvedValue(mockFrameworks)

    const { result } = renderHook(() => useCompliance(), { wrapper: makeWrapper() })
    await waitFor(() => expect(result.current.isSuccess).toBe(true))

    for (const f of result.current.data!) {
      expect(f.score).toBeGreaterThanOrEqual(0)
      expect(f.score).toBeLessThanOrEqual(100)
    }
  })
})
