import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import { renderHook, waitFor, act } from '@testing-library/react'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import type { ReactNode } from 'react'
import React from 'react'
import { useEnrichFinding } from '@/hooks/useFindings'
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
    defaultOptions: { queries: { retry: false, gcTime: 0 }, mutations: { retry: false } },
  })
  return ({ children }: { children: ReactNode }) =>
    React.createElement(QueryClientProvider, { client }, children)
}

describe('useEnrichFinding', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    sessionStorage.clear()
  })

  afterEach(() => {
    vi.restoreAllMocks()
    vi.unstubAllEnvs()
    sessionStorage.clear()
  })

  it('calls POST /findings/{id}/enrich on mutate', async () => {
    const enrichedFinding = { id: 'f-001', ai_risk_rationale: 'Enriched analysis' }
    vi.mocked(apiClient.post).mockResolvedValue(enrichedFinding)

    const { result } = renderHook(() => useEnrichFinding(), { wrapper: makeWrapper() })

    act(() => {
      result.current.mutate('f-001')
    })

    await waitFor(() => expect(result.current.isSuccess).toBe(true))
    expect(vi.mocked(apiClient.post)).toHaveBeenCalledWith('/findings/f-001/enrich', {})
  })

  it('transitions through isPending state', async () => {
    const enrichedFinding = { id: 'f-001', ai_risk_rationale: 'Done' }
    vi.mocked(apiClient.post).mockResolvedValue(enrichedFinding)

    const { result } = renderHook(() => useEnrichFinding(), { wrapper: makeWrapper() })

    // Before mutation: idle
    expect(result.current.isPending).toBe(false)
    expect(result.current.isIdle).toBe(true)

    act(() => {
      result.current.mutate('f-001')
    })

    // Eventually resolves
    await waitFor(() => expect(result.current.isSuccess).toBe(true))
    expect(result.current.isPending).toBe(false)
  })

  it('sets isError on API failure', async () => {
    vi.mocked(apiClient.post).mockRejectedValue(new ApiError(403, 'Forbidden'))

    const { result } = renderHook(() => useEnrichFinding(), { wrapper: makeWrapper() })

    act(() => {
      result.current.mutate('f-001')
    })

    await waitFor(() => expect(result.current.isError).toBe(true))
    expect(result.current.error).toBeInstanceOf(ApiError)
    expect((result.current.error as ApiError).status).toBe(403)
  })

  it('sets isError on 500 server error', async () => {
    vi.mocked(apiClient.post).mockRejectedValue(new ApiError(500, 'Internal Server Error'))

    const { result } = renderHook(() => useEnrichFinding(), { wrapper: makeWrapper() })

    act(() => {
      result.current.mutate('f-001')
    })

    await waitFor(() => expect(result.current.isError).toBe(true))
  })

  it('reuses mock findings in demo mode instead of POSTing', async () => {
    vi.stubEnv('VITE_DEMO_MODE', 'true')
    sessionStorage.setItem('aegis_findings_source', 'local')
    global.fetch = vi.fn().mockResolvedValue(
      new Response(JSON.stringify([{ id: 'f-001', title: 'demo finding' }]), { status: 200 }),
    )

    const { result } = renderHook(() => useEnrichFinding(), { wrapper: makeWrapper() })

    act(() => {
      result.current.mutate('f-001')
    })

    await waitFor(() => expect(result.current.isSuccess).toBe(true))
    expect(result.current.data).toMatchObject({ id: 'f-001' })
    expect(vi.mocked(apiClient.post)).not.toHaveBeenCalled()
  })
})
