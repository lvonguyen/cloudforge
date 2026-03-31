import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import { renderHook, waitFor } from '@testing-library/react'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import type { ReactNode } from 'react'
import React from 'react'
import { useFindings, useFinding } from '@/hooks/useFindings'
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
    unwrapPaginated: <T>(response: T[] | { data: T[] }): T[] => {
      if (Array.isArray(response)) return response
      return response.data
    },
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

const mockFindings = [
  {
    id: 'f-001',
    title: 'S3 bucket public',
    severity: 'HIGH',
    status: 'open',
    cloud_provider: 'aws',
    category: 'MISCONFIGURATION',
    service_name: 'S3',
    line_of_business: 'Platform',
    deduplication_key: 'key-001',
    canonical_rule_id: 'rule-001',
    source: 'SecurityHub',
    source_finding_id: 'src-001',
    type: 'Software and Configuration Checks',
    description: 'Bucket is public',
    resource_type: 'storage',
    resource_id: 'arn:aws:s3:::my-bucket',
    resource_name: 'my-bucket',
    platform: 'AWS',
    region: 'us-east-1',
    account_id: '123456789',
    environment_type: 'production',
    static_severity: 'HIGH',
    ai_risk_score: 8.5,
    ai_risk_level: 'HIGH',
    ai_risk_rationale: 'Public bucket',
    ai_contextual_factors: [],
    exploit_available: false,
    auto_remediatable: true,
    remediation: 'Block public access',
    suppressed: false,
    workflow_status: 'new',
    first_found_at: '2024-01-01T00:00:00Z',
    last_seen_at: '2024-01-02T00:00:00Z',
  },
]

describe('useFindings', () => {
  beforeEach(() => {
    vi.clearAllMocks()
  })

  afterEach(() => {
    vi.restoreAllMocks()
    vi.unstubAllEnvs()
  })

  it('returns loading state initially', () => {
    vi.mocked(apiClient.get).mockReturnValue(new Promise(() => {})) // never resolves

    const { result } = renderHook(() => useFindings(), { wrapper: makeWrapper() })
    expect(result.current.isLoading).toBe(true)
  })

  it('returns data from apiClient.get on success', async () => {
    vi.mocked(apiClient.get).mockResolvedValue(mockFindings)

    const { result } = renderHook(() => useFindings(), { wrapper: makeWrapper() })
    await waitFor(() => expect(result.current.isSuccess).toBe(true))

    expect(result.current.data).toHaveLength(1)
    expect(result.current.data![0].id).toBe('f-001')
  })

  it('calls /findings with severity filter in query string', async () => {
    vi.mocked(apiClient.get).mockResolvedValue(mockFindings)

    const filters = { severity: 'HIGH' }
    const { result } = renderHook(() => useFindings(filters), { wrapper: makeWrapper() })
    await waitFor(() => expect(result.current.isSuccess).toBe(true))

    expect(vi.mocked(apiClient.get)).toHaveBeenCalledWith('/findings?severity=HIGH')
  })

  it('calls /findings without query string when no filters given', async () => {
    vi.mocked(apiClient.get).mockResolvedValue(mockFindings)

    const { result } = renderHook(() => useFindings(), { wrapper: makeWrapper() })
    await waitFor(() => expect(result.current.isSuccess).toBe(true))

    expect(vi.mocked(apiClient.get)).toHaveBeenCalledWith('/findings')
  })

  it('falls back to mock data when API returns 500', async () => {
    vi.stubEnv('VITE_ENABLE_MOCK_FALLBACK', 'true')
    vi.mocked(apiClient.get).mockRejectedValue(new ApiError(500, 'Server Error'))

    const warnSpy = vi.spyOn(console, 'warn').mockImplementation(() => {})

    global.fetch = vi.fn().mockResolvedValue(
      new Response(JSON.stringify(mockFindings), { status: 200 })
    )

    const { result } = renderHook(() => useFindings(), { wrapper: makeWrapper() })
    await waitFor(() => expect(result.current.isSuccess).toBe(true))

    expect(result.current.data).toBeDefined()
    warnSpy.mockRestore()
  })

  it('surfaces 500 errors when mock fallback is not enabled', async () => {
    vi.mocked(apiClient.get).mockRejectedValue(new ApiError(500, 'Server Error'))

    const { result } = renderHook(() => useFindings(), { wrapper: makeWrapper() })
    await waitFor(() => expect(result.current.isError).toBe(true))

    expect((result.current.error as ApiError).status).toBe(500)
  })

  it('does not suppress 4xx ApiErrors (rethrows them)', async () => {
    vi.mocked(apiClient.get).mockRejectedValue(new ApiError(401, 'Unauthorized'))

    const { result } = renderHook(() => useFindings(), { wrapper: makeWrapper() })
    await waitFor(() => expect(result.current.isError).toBe(true))

    expect(result.current.error).toBeInstanceOf(ApiError)
    expect((result.current.error as ApiError).status).toBe(401)
  })

  it('includes provider filter in query string when provided', async () => {
    vi.mocked(apiClient.get).mockResolvedValue(mockFindings)

    const filters = { provider: 'aws' }
    const { result } = renderHook(() => useFindings(filters), { wrapper: makeWrapper() })
    await waitFor(() => expect(result.current.isSuccess).toBe(true))

    expect(vi.mocked(apiClient.get)).toHaveBeenCalledWith('/findings?provider=aws')
  })
})

describe('useFinding', () => {
  const singleFinding = {
    id: 'f-002',
    title: 'Overly permissive IAM policy',
    severity: 'CRITICAL',
  }

  beforeEach(() => {
    vi.clearAllMocks()
  })

  it('is disabled when id is empty string', () => {
    const { result } = renderHook(() => useFinding(''), { wrapper: makeWrapper() })
    expect(result.current.fetchStatus).toBe('idle')
  })

  it('fetches single finding by id when id is provided', async () => {
    vi.mocked(apiClient.get).mockResolvedValue(singleFinding)

    const { result } = renderHook(() => useFinding('f-002'), { wrapper: makeWrapper() })
    await waitFor(() => expect(result.current.isSuccess).toBe(true))

    expect(vi.mocked(apiClient.get)).toHaveBeenCalledWith('/findings/f-002')
  })

  it('returns the finding data with correct id', async () => {
    vi.mocked(apiClient.get).mockResolvedValue(singleFinding)

    const { result } = renderHook(() => useFinding('f-002'), { wrapper: makeWrapper() })
    await waitFor(() => expect(result.current.isSuccess).toBe(true))

    expect(result.current.data).toMatchObject({ id: 'f-002' })
  })
})
