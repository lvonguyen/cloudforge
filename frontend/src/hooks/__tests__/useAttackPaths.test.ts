import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import { renderHook, waitFor } from '@testing-library/react'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import type { ReactNode } from 'react'
import React from 'react'
import { useAttackPaths, useAttackPath, useAttackPathStats } from '@/hooks/useAttackPaths'
import { apiClient } from '@/lib/api'

vi.mock('@/lib/api', () => ({
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

const mockAttackPaths = [
  {
    id: 'ap-001',
    name: 'IAM Privilege Escalation',
    severity: 'CRITICAL',
    steps: 3,
    exploitability: 0.85,
    mitigated: false,
  },
]

const mockAttackPath = {
  id: 'ap-001',
  name: 'IAM Privilege Escalation',
  severity: 'CRITICAL',
  steps: 3,
  exploitability: 0.85,
  mitigated: false,
  nodes: [
    { id: 'n-001', type: 'user', name: 'User A' },
    { id: 'n-002', type: 'role', name: 'Role Admin' },
  ],
  edges: [{ from: 'n-001', to: 'n-002', label: 'AssumeRole' }],
}

const mockStats = {
  total_paths: 42,
  critical_paths: 8,
  high_paths: 15,
  mitigated_paths: 12,
  avg_exploitability: 0.65,
}

describe('useAttackPaths', () => {
  beforeEach(() => {
    vi.clearAllMocks()
  })

  afterEach(() => {
    vi.restoreAllMocks()
  })

  it('returns loading state initially', () => {
    vi.mocked(apiClient.get).mockReturnValue(new Promise(() => {}))

    const { result } = renderHook(() => useAttackPaths(), { wrapper: makeWrapper() })
    expect(result.current.isLoading).toBe(true)
  })

  it('returns data from apiClient.get on success', async () => {
    vi.mocked(apiClient.get).mockResolvedValue(mockAttackPaths)

    const { result } = renderHook(() => useAttackPaths(), { wrapper: makeWrapper() })
    await waitFor(() => expect(result.current.isSuccess).toBe(true))

    expect(result.current.data).toHaveLength(1)
    expect(result.current.data![0].id).toBe('ap-001')
  })

  it('calls /attack-paths endpoint', async () => {
    vi.mocked(apiClient.get).mockResolvedValue(mockAttackPaths)

    const { result } = renderHook(() => useAttackPaths(), { wrapper: makeWrapper() })
    await waitFor(() => expect(result.current.isSuccess).toBe(true))

    expect(vi.mocked(apiClient.get)).toHaveBeenCalledWith('/attack-paths?page=1&per_page=20')
  })
})

describe('useAttackPath', () => {
  beforeEach(() => {
    vi.clearAllMocks()
  })

  afterEach(() => {
    vi.restoreAllMocks()
  })

  it('returns loading state initially when id is provided', () => {
    vi.mocked(apiClient.get).mockReturnValue(new Promise(() => {}))

    const { result } = renderHook(() => useAttackPath('ap-001'), { wrapper: makeWrapper() })
    expect(result.current.isLoading).toBe(true)
  })

  it('is disabled when id is empty string', () => {
    const { result } = renderHook(() => useAttackPath(''), { wrapper: makeWrapper() })
    expect(result.current.fetchStatus).toBe('idle')
  })

  it('returns single attack path by id', async () => {
    vi.mocked(apiClient.get).mockResolvedValue(mockAttackPath)

    const { result } = renderHook(() => useAttackPath('ap-001'), { wrapper: makeWrapper() })
    await waitFor(() => expect(result.current.isSuccess).toBe(true))

    expect(result.current.data).toBeDefined()
    expect(result.current.data!.id).toBe('ap-001')
  })

  it('calls /attack-paths/:id endpoint', async () => {
    vi.mocked(apiClient.get).mockResolvedValue(mockAttackPath)

    const { result } = renderHook(() => useAttackPath('ap-001'), { wrapper: makeWrapper() })
    await waitFor(() => expect(result.current.isSuccess).toBe(true))

    expect(vi.mocked(apiClient.get)).toHaveBeenCalledWith('/attack-paths/ap-001')
  })
})

describe('useAttackPathStats', () => {
  beforeEach(() => {
    vi.clearAllMocks()
  })

  afterEach(() => {
    vi.restoreAllMocks()
  })

  it('returns loading state initially', () => {
    vi.mocked(apiClient.get).mockReturnValue(new Promise(() => {}))

    const { result } = renderHook(() => useAttackPathStats(), { wrapper: makeWrapper() })
    expect(result.current.isLoading).toBe(true)
  })

  it('returns stats data from apiClient.get on success', async () => {
    vi.mocked(apiClient.get).mockResolvedValue(mockStats)

    const { result } = renderHook(() => useAttackPathStats(), { wrapper: makeWrapper() })
    await waitFor(() => expect(result.current.isSuccess).toBe(true))

    expect(result.current.data).toBeDefined()
    expect(result.current.data!.total_paths).toBe(42)
  })

  it('calls /attack-paths/stats endpoint', async () => {
    vi.mocked(apiClient.get).mockResolvedValue(mockStats)

    const { result } = renderHook(() => useAttackPathStats(), { wrapper: makeWrapper() })
    await waitFor(() => expect(result.current.isSuccess).toBe(true))

    expect(vi.mocked(apiClient.get)).toHaveBeenCalledWith('/attack-paths/stats')
  })
})
