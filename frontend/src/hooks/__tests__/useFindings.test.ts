import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import { renderHook, waitFor } from '@testing-library/react'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import type { ReactNode } from 'react'
import React from 'react'
import { normalizeDemoFindings, useFindings, useFinding, useFindingEnrichment, useFindingsStats } from '@/hooks/useFindings'
import { apiClient, ApiError } from '@/lib/api'
import type { Finding } from '@/types/compliance'

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

function buildUniformFinding(index: number, severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW', status: 'open' | 'in_progress' | 'resolved' | 'suppressed', autoRemediatable: boolean): Finding {
  return {
    id: `f-${index.toString().padStart(5, '0')}`,
    title: `Synthetic finding ${index}`,
    severity,
    status,
    cloud_provider: index % 3 === 0 ? 'aws' : index % 3 === 1 ? 'azure' : 'gcp',
    category: 'MISCONFIGURATION',
    service_name: 'S3',
    line_of_business: 'Platform',
    deduplication_key: `key-${index}`,
    canonical_rule_id: `rule-${index}`,
    source: 'SecurityHub',
    source_finding_id: `src-${index}`,
    type: 'Software and Configuration Checks',
    description: `Synthetic finding ${index}`,
    resource_type: 'storage',
    resource_id: `arn:aws:s3:::bucket-${index}`,
    resource_name: `bucket-${index}`,
    platform: 'AWS',
    region: 'us-east-1',
    account_id: '123456789',
    environment_type: 'production',
    static_severity: severity,
    ai_risk_score: severity === 'CRITICAL' ? 9.5 : severity === 'HIGH' ? 7.5 : severity === 'MEDIUM' ? 5.1 : 2.4,
    ai_risk_level: severity,
    ai_risk_rationale: `Synthetic ${severity.toLowerCase()} risk`,
    ai_contextual_factors: [],
    exploit_available: severity === 'CRITICAL',
    auto_remediatable: autoRemediatable,
    remediation: 'Fix the issue',
    suppressed: status === 'suppressed',
    workflow_status: status === 'open' ? 'new' : status === 'in_progress' ? 'in_progress' : status === 'resolved' ? 'closed' : 'suppressed',
    first_found_at: '2024-01-01T00:00:00Z',
    last_seen_at: '2024-01-02T00:00:00Z',
    due_date: '2024-01-03T00:00:00Z',
  }
}

function buildUniformR2Corpus(): Finding[] {
  const findings: Finding[] = []
  const severities: Array<[Finding['severity'], number]> = [
    ['CRITICAL', 2000],
    ['HIGH', 5000],
    ['MEDIUM', 7000],
    ['LOW', 6000],
  ]
  const statuses: Array<[Finding['status'], number]> = [
    ['open', 12500],
    ['in_progress', 3750],
    ['resolved', 2500],
    ['suppressed', 1250],
  ]

  let index = 0
  for (const [severity, count] of severities) {
    for (let i = 0; i < count; i += 1) {
      let running = index
      let status: Finding['status'] = 'suppressed'
      for (const [candidate, candidateCount] of statuses) {
        if (running < candidateCount) {
          status = candidate
          break
        }
        running -= candidateCount
      }
      findings.push(buildUniformFinding(index, severity, status, index < 6000))
      index += 1
    }
  }
  return findings
}

describe('useFindings', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    sessionStorage.clear()
  })

  afterEach(() => {
    vi.restoreAllMocks()
    vi.unstubAllEnvs()
    sessionStorage.clear()
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

  it('allows larger local demo pages for analyst views', async () => {
    vi.stubEnv('VITE_DEMO_MODE', 'true')
    const largeCorpus = Array.from({ length: 1500 }, (_, index) =>
      buildUniformFinding(index, 'HIGH', 'open', true),
    )

    global.fetch = vi.fn().mockResolvedValue(
      new Response(JSON.stringify(largeCorpus), { status: 200 }),
    )

    const { result } = renderHook(
      () => useFindings({ page: 1, perPage: 1000, sort: 'ai_risk', order: 'desc' }),
      { wrapper: makeWrapper() },
    )
    await waitFor(() => expect(result.current.isSuccess).toBe(true))

    expect(result.current.data).toHaveLength(1000)
    expect(result.current.total).toBe(1500)
  })

  it('derives findings stats from mock data in demo mode without probing the API', async () => {
    vi.stubEnv('VITE_DEMO_MODE', 'true')
    sessionStorage.setItem('aegis_findings_source', 'local')
    global.fetch = vi.fn().mockResolvedValue(
      new Response(JSON.stringify(mockFindings), { status: 200 }),
    )

    const { result } = renderHook(() => useFindingsStats(), { wrapper: makeWrapper() })
    await waitFor(() => expect(result.current.isSuccess).toBe(true))

    expect(result.current.data).toMatchObject({
      total: 1,
      by_severity: { HIGH: 1 },
      by_status: { open: 1 },
      by_provider: { aws: 1 },
      by_category: { MISCONFIGURATION: 1 },
      sla_breached: 0,
      auto_remedial: 1,
    })
    expect(vi.mocked(apiClient.get)).not.toHaveBeenCalled()
  })

  it('skips enrichment API calls in demo mode', async () => {
    vi.stubEnv('VITE_DEMO_MODE', 'true')

    const { result } = renderHook(() => useFindingEnrichment('f-001'), { wrapper: makeWrapper() })
    await waitFor(() => expect(result.current.isSuccess).toBe(true))

    expect(result.current.data).toBeNull()
    expect(vi.mocked(apiClient.post)).not.toHaveBeenCalled()
  })
})

describe('normalizeDemoFindings', () => {
  it('deterministically de-uniforms the stale 20k R2 demo corpus', () => {
    const findings = buildUniformR2Corpus()

    const normalizedA = normalizeDemoFindings(findings)
    const normalizedB = normalizeDemoFindings(findings)
    const severityCounts = normalizedA.reduce<Record<string, number>>((counts, finding) => {
      counts[finding.severity] = (counts[finding.severity] ?? 0) + 1
      return counts
    }, {})

    expect(normalizedA).toHaveLength(normalizedB.length)
    expect(normalizedA).not.toHaveLength(findings.length)
    expect(severityCounts).not.toEqual({
      CRITICAL: 2000,
      HIGH: 5000,
      MEDIUM: 7000,
      LOW: 6000,
    })
    expect(normalizedA.map((finding) => finding.id)).toEqual(normalizedB.map((finding) => finding.id))
  })

  it('leaves already non-uniform corpora unchanged', () => {
    expect(normalizeDemoFindings(mockFindings as Finding[])).toEqual(mockFindings)
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
