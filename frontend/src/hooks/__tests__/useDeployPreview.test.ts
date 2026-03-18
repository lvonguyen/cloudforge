import { describe, it, expect, vi, beforeEach } from 'vitest'
import { renderHook, act, waitFor } from '@testing-library/react'
import { useDeployPreview } from '@/hooks/useDeployPreview'
import type { Envelope } from '@/hooks/useChannel'
import type { DeployPreviewConfig } from '@/types/deploy'

// Mock useChannel
const mockUseChannel = vi.fn()
vi.mock('@/hooks/useChannel', () => ({
  useChannel: (...args: unknown[]) => mockUseChannel(...args),
}))

// Mock apiClient
vi.mock('@/lib/api', () => ({
  apiClient: {
    get: vi.fn(),
    post: vi.fn(),
    put: vi.fn(),
    delete: vi.fn(),
  },
}))

import { apiClient } from '@/lib/api'

const mockConfig: DeployPreviewConfig = {
  resourceType: 's3',
  provider: 'aws',
  region: 'us-east-1',
  appId: 'test-app',
  configuration: {},
}

function makeEnvelope(event: string, data: Record<string, unknown> = {}): Envelope {
  return {
    channel: 'deploy:exec-abc',
    event,
    data: { message: 'test message', ...data },
    id: crypto.randomUUID(),
    ts: new Date().toISOString(),
  }
}

beforeEach(() => {
  vi.clearAllMocks()
  mockUseChannel.mockReturnValue({ events: [], connected: false, error: null })
})

describe('useDeployPreview', () => {
  it('starts in idle state', () => {
    const { result } = renderHook(() => useDeployPreview())
    expect(result.current.phase).toBe('idle')
    expect(result.current.isRunning).toBe(false)
    expect(result.current.countdown).toBeNull()
    expect(result.current.events).toEqual([])
  })

  it('run() calls API and sets executionId', async () => {
    vi.mocked(apiClient.post).mockResolvedValue({ execution_id: 'exec-abc' })

    const { result } = renderHook(() => useDeployPreview())
    await act(async () => { await result.current.run(mockConfig) })

    expect(apiClient.post).toHaveBeenCalledWith('/deploy/preview', mockConfig)
    expect(result.current.isRunning).toBe(true)
    expect(result.current.phase).toBe('planning')
  })

  it('abort() calls API and clears state', async () => {
    vi.mocked(apiClient.post).mockResolvedValue({ execution_id: 'exec-abc' })

    const { result } = renderHook(() => useDeployPreview())
    await act(async () => { await result.current.run(mockConfig) })
    await act(async () => { await result.current.abort() })

    expect(apiClient.post).toHaveBeenCalledWith('/deploy/preview/exec-abc/abort', {})
    expect(result.current.isRunning).toBe(false)
  })

  it('reset() returns to idle', async () => {
    vi.mocked(apiClient.post).mockResolvedValue({ execution_id: 'exec-abc' })

    const { result } = renderHook(() => useDeployPreview())
    await act(async () => { await result.current.run(mockConfig) })

    act(() => result.current.reset())
    expect(result.current.phase).toBe('idle')
    expect(result.current.isRunning).toBe(false)
    expect(result.current.countdown).toBeNull()
  })

  it('derives phase from latest envelope event', async () => {
    const envelopes = [makeEnvelope('planning'), makeEnvelope('creating')]
    mockUseChannel.mockReturnValue({ events: envelopes, connected: true, error: null })

    const { result } = renderHook(() => useDeployPreview())
    // Phase should follow the last envelope's event
    await waitFor(() => expect(result.current.phase).toBe('creating'))
  })

  it('extracts countdown from envelope data', async () => {
    const envelopes = [makeEnvelope('live', { countdown: 45 })]
    mockUseChannel.mockReturnValue({ events: envelopes, connected: true, error: null })

    const { result } = renderHook(() => useDeployPreview())
    await waitFor(() => expect(result.current.countdown).toBe(45))
  })

  it('sets isRunning to false on complete event', async () => {
    vi.mocked(apiClient.post).mockResolvedValue({ execution_id: 'exec-abc' })
    const completeEnvelopes = [makeEnvelope('complete')]

    const { result, rerender } = renderHook(() => useDeployPreview())
    await act(async () => { await result.current.run(mockConfig) })
    expect(result.current.isRunning).toBe(true)

    // Simulate useChannel returning a complete event
    mockUseChannel.mockReturnValue({ events: completeEnvelopes, connected: true, error: null })
    rerender()
    await waitFor(() => {
      expect(result.current.phase).toBe('complete')
      expect(result.current.isRunning).toBe(false)
    })
  })

  it('sets isRunning to false on error event', async () => {
    vi.mocked(apiClient.post).mockResolvedValue({ execution_id: 'exec-err' })
    const errorEnvelopes = [makeEnvelope('error')]

    const { result, rerender } = renderHook(() => useDeployPreview())
    await act(async () => { await result.current.run(mockConfig) })

    mockUseChannel.mockReturnValue({ events: errorEnvelopes, connected: true, error: null })
    rerender()
    await waitFor(() => {
      expect(result.current.phase).toBe('error')
      expect(result.current.isRunning).toBe(false)
    })
  })

  it('passes correct channel to useChannel', async () => {
    vi.mocked(apiClient.post).mockResolvedValue({ execution_id: 'exec-xyz' })

    const { result } = renderHook(() => useDeployPreview())
    await act(async () => { await result.current.run(mockConfig) })

    // useChannel should have been called with the deploy channel
    expect(mockUseChannel).toHaveBeenCalledWith(
      'deploy:exec-xyz',
      expect.objectContaining({ enabled: true }),
    )
  })
})
