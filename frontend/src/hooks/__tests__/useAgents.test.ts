import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import { renderHook, waitFor } from '@testing-library/react'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import type { ReactNode } from 'react'
import React from 'react'
import { useAgents, useAgent, useAgentTraces } from '@/hooks/useAgents'
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

const mockAgents = [
  {
    id: 'agent-001',
    name: 'Remediation Agent',
    status: 'active',
    framework: 'langchain',
    version: '1.0.0',
    owner: 'secops',
    team: 'platform',
    environment: 'production',
    capabilities: [],
    tools: [],
    policies: [],
    risk_level: 'medium',
    created_at: '2024-01-01T00:00:00Z',
    updated_at: '2024-01-01T00:00:00Z',
    description: 'Handles automated remediations',
  },
]

describe('useAgents', () => {
  beforeEach(() => {
    vi.clearAllMocks()
  })

  afterEach(() => {
    vi.restoreAllMocks()
  })

  it('returns loading state initially', () => {
    vi.mocked(apiClient.get).mockReturnValue(new Promise(() => {}))
    const { result } = renderHook(() => useAgents(), { wrapper: makeWrapper() })
    expect(result.current.isLoading).toBe(true)
  })

  it('returns data from apiClient.get on success', async () => {
    vi.mocked(apiClient.get).mockResolvedValue(mockAgents)
    const { result } = renderHook(() => useAgents(), { wrapper: makeWrapper() })
    await waitFor(() => expect(result.current.isSuccess).toBe(true))
    expect(result.current.data).toEqual(mockAgents)
  })

  it('calls /agents endpoint', async () => {
    vi.mocked(apiClient.get).mockResolvedValue(mockAgents)
    const { result } = renderHook(() => useAgents(), { wrapper: makeWrapper() })
    await waitFor(() => expect(result.current.isSuccess).toBe(true))
    expect(vi.mocked(apiClient.get)).toHaveBeenCalledWith('/agents')
  })

  it('falls back to mock data when API returns 500', async () => {
    vi.mocked(apiClient.get).mockRejectedValue(new ApiError(500, 'Server Error'))
    const warnSpy = vi.spyOn(console, 'warn').mockImplementation(() => {})
    const { result } = renderHook(() => useAgents(), { wrapper: makeWrapper() })
    await waitFor(() => expect(result.current.isSuccess).toBe(true))
    expect(result.current.data).toBeDefined()
    warnSpy.mockRestore()
  })

  it('rethrows 4xx ApiErrors', async () => {
    vi.mocked(apiClient.get).mockRejectedValue(new ApiError(401, 'Unauthorized'))
    const { result } = renderHook(() => useAgents(), { wrapper: makeWrapper() })
    await waitFor(() => expect(result.current.isError).toBe(true))
    expect((result.current.error as ApiError).status).toBe(401)
  })
})

describe('useAgent', () => {
  beforeEach(() => {
    vi.clearAllMocks()
  })

  it('is disabled when id is empty string', () => {
    const { result } = renderHook(() => useAgent(''), { wrapper: makeWrapper() })
    expect(result.current.fetchStatus).toBe('idle')
  })

  it('fetches single agent by id when id is provided', async () => {
    vi.mocked(apiClient.get).mockResolvedValue(mockAgents[0])
    const { result } = renderHook(() => useAgent('agent-001'), { wrapper: makeWrapper() })
    await waitFor(() => expect(result.current.isSuccess).toBe(true))
    expect(vi.mocked(apiClient.get)).toHaveBeenCalledWith('/agents/agent-001')
  })
})

describe('useAgentTraces', () => {
  beforeEach(() => {
    vi.clearAllMocks()
  })

  afterEach(() => {
    vi.restoreAllMocks()
  })

  it('is disabled when agentId is empty string', () => {
    const { result } = renderHook(() => useAgentTraces(''), { wrapper: makeWrapper() })
    expect(result.current.fetchStatus).toBe('idle')
  })

  it('fetches traces for a given agentId', async () => {
    vi.mocked(apiClient.get).mockResolvedValue([])
    const { result } = renderHook(() => useAgentTraces('agent-001'), { wrapper: makeWrapper() })
    await waitFor(() => expect(result.current.isSuccess).toBe(true))
    expect(vi.mocked(apiClient.get)).toHaveBeenCalledWith('/agents/agent-001/traces')
  })

  it('falls back to mock data when API returns 500', async () => {
    vi.mocked(apiClient.get).mockRejectedValue(new ApiError(500, 'Server Error'))
    const warnSpy = vi.spyOn(console, 'warn').mockImplementation(() => {})
    const { result } = renderHook(() => useAgentTraces('agent-001'), { wrapper: makeWrapper() })
    await waitFor(() => expect(result.current.isSuccess).toBe(true))
    expect(result.current.data).toBeDefined()
    warnSpy.mockRestore()
  })
})
