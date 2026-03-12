import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import { renderHook, waitFor } from '@testing-library/react'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import type { ReactNode } from 'react'
import React from 'react'
import { useExceptions, useCreateException, useApproveException } from '@/hooks/useExceptions'
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

const mockExceptions = [
  {
    id: 'ex-001',
    application_id: 'app-001',
    policy_violated: 'IAM-001',
    resource_requested: 'arn:aws:iam::123456789:role/admin',
    requestor_email: 'user@contoso.dev',
    status: 'pending',
    created_at: '2024-01-01T00:00:00Z',
  },
]

describe('useExceptions', () => {
  beforeEach(() => {
    vi.clearAllMocks()
  })

  afterEach(() => {
    vi.restoreAllMocks()
  })

  it('returns loading state initially', () => {
    vi.mocked(apiClient.get).mockReturnValue(new Promise(() => {}))

    const { result } = renderHook(() => useExceptions(), { wrapper: makeWrapper() })
    expect(result.current.isLoading).toBe(true)
  })

  it('returns data from apiClient.get on success', async () => {
    vi.mocked(apiClient.get).mockResolvedValue(mockExceptions)

    const { result } = renderHook(() => useExceptions(), { wrapper: makeWrapper() })
    await waitFor(() => expect(result.current.isSuccess).toBe(true))

    expect(result.current.data).toHaveLength(1)
    expect(result.current.data![0].id).toBe('ex-001')
  })

  it('calls /exceptions/pending endpoint', async () => {
    vi.mocked(apiClient.get).mockResolvedValue(mockExceptions)

    const { result } = renderHook(() => useExceptions(), { wrapper: makeWrapper() })
    await waitFor(() => expect(result.current.isSuccess).toBe(true))

    expect(vi.mocked(apiClient.get)).toHaveBeenCalledWith('/exceptions/pending')
  })
})

describe('useCreateException', () => {
  beforeEach(() => {
    vi.clearAllMocks()
  })

  afterEach(() => {
    vi.restoreAllMocks()
  })

  it('calls apiClient.post with correct endpoint', async () => {
    vi.mocked(apiClient.post).mockResolvedValue(mockExceptions[0])

    const { result } = renderHook(() => useCreateException(), { wrapper: makeWrapper() })

    const newException = {
      application_id: 'app-002',
      policy_violated: 'IAM-002',
      resource_requested: 'arn:aws:iam::123456789:role/developer',
      requestor_email: 'dev@contoso.dev',
    }

    result.current.mutate(newException)

    await waitFor(() => expect(result.current.isSuccess).toBe(true))

    expect(vi.mocked(apiClient.post)).toHaveBeenCalledWith('/exceptions', newException)
  })

  it('invalidates exceptions query on success', async () => {
    vi.mocked(apiClient.post).mockResolvedValue(mockExceptions[0])

    const wrapper = makeWrapper()
    const client = new QueryClient({
      defaultOptions: { queries: { retry: false, gcTime: 0 } },
    })

    const invalidateSpy = vi.spyOn(client, 'invalidateQueries')

    const { result } = renderHook(() => useCreateException(), {
      wrapper: ({ children }: { children: ReactNode }) =>
        React.createElement(QueryClientProvider, { client }, children),
    })

    result.current.mutate({ application_id: 'app-002' })

    await waitFor(() => expect(result.current.isSuccess).toBe(true))

    expect(invalidateSpy).toHaveBeenCalledWith({ queryKey: ['exceptions'] })
  })
})

describe('useApproveException', () => {
  beforeEach(() => {
    vi.clearAllMocks()
  })

  afterEach(() => {
    vi.restoreAllMocks()
  })

  it('calls apiClient.post with correct endpoint and payload', async () => {
    vi.mocked(apiClient.post).mockResolvedValue(mockExceptions[0])

    const { result } = renderHook(() => useApproveException(), { wrapper: makeWrapper() })

    const approval = {
      id: 'ex-001',
      approver: { name: 'Manager', email: 'manager@contoso.dev', decision: 'approve' as const },
    }

    result.current.mutate(approval)

    await waitFor(() => expect(result.current.isSuccess).toBe(true))

    expect(vi.mocked(apiClient.post)).toHaveBeenCalledWith(
      '/exceptions/ex-001/approve',
      approval.approver
    )
  })

  it('invalidates exceptions query on success', async () => {
    vi.mocked(apiClient.post).mockResolvedValue(mockExceptions[0])

    const client = new QueryClient({
      defaultOptions: { queries: { retry: false, gcTime: 0 } },
    })

    const invalidateSpy = vi.spyOn(client, 'invalidateQueries')

    const { result } = renderHook(() => useApproveException(), {
      wrapper: ({ children }: { children: ReactNode }) =>
        React.createElement(QueryClientProvider, { client }, children),
    })

    const approval = {
      id: 'ex-001',
      approver: { name: 'Manager', email: 'manager@contoso.dev', decision: 'approve' as const },
    }

    result.current.mutate(approval)

    await waitFor(() => expect(result.current.isSuccess).toBe(true))

    expect(invalidateSpy).toHaveBeenCalledWith({ queryKey: ['exceptions'] })
  })
})
