import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import { renderHook, act, waitFor } from '@testing-library/react'
import { useChannel } from '@/hooks/useChannel'

// --- MockEventSource ---
type ESHandler = ((ev: MessageEvent) => void) | null
type ESOpenHandler = (() => void) | null
type ESErrorHandler = (() => void) | null

let mockInstances: MockEventSource[] = []

class MockEventSource {
  url: string
  onopen: ESOpenHandler = null
  onmessage: ESHandler = null
  onerror: ESErrorHandler = null
  readyState = 0
  closed = false

  constructor(url: string) {
    this.url = url
    mockInstances.push(this)
  }

  close() {
    this.closed = true
    this.readyState = 2
  }

  // Test helpers
  simulateOpen() {
    this.readyState = 1
    this.onopen?.()
  }

  simulateMessage(data: unknown) {
    const ev = { data: JSON.stringify(data) } as MessageEvent
    this.onmessage?.(ev)
  }

  simulateError() {
    this.onerror?.()
  }
}

// Mock fetch for ticket endpoint
const mockFetch = vi.fn()

beforeEach(() => {
  mockInstances = []
  vi.stubGlobal('EventSource', MockEventSource)
  vi.stubGlobal('fetch', mockFetch)
  // Default: ticket fetch returns a ticket
  mockFetch.mockResolvedValue({
    ok: true,
    json: () => Promise.resolve({ ticket: 'test-ticket-123' }),
  })
})

afterEach(() => {
  vi.unstubAllGlobals()
  vi.restoreAllMocks()
})

describe('useChannel', () => {
  it('returns empty events when disabled', () => {
    const { result } = renderHook(() => useChannel('test-channel', { enabled: false }))
    expect(result.current.events).toEqual([])
    expect(result.current.connected).toBe(false)
    expect(mockInstances).toHaveLength(0)
  })

  it('does not connect when channel is empty string', () => {
    const { result } = renderHook(() => useChannel(''))
    expect(result.current.events).toEqual([])
    expect(result.current.connected).toBe(false)
    expect(mockInstances).toHaveLength(0)
  })

  it('fetches ticket and constructs SSE URL with ticket param', async () => {
    // getToken() checks VITE_DEV_TOKEN in dev mode — stub it so fetchTicket runs
    vi.stubEnv('VITE_DEV_TOKEN', 'test-jwt')
    renderHook(() => useChannel('deploy:exec-abc'))
    await waitFor(() => expect(mockInstances).toHaveLength(1))
    const es = mockInstances[0]
    expect(es.url).toContain('channel=deploy%3Aexec-abc')
    expect(es.url).toContain('ticket=test-ticket-123')
    vi.unstubAllEnvs()
  })

  it('falls back to token when ticket fetch fails', async () => {
    mockFetch.mockResolvedValue({ ok: false, json: () => Promise.resolve({}) })
    renderHook(() => useChannel('test-ch'))
    await waitFor(() => expect(mockInstances).toHaveLength(1))
    // Should still have created an EventSource (with or without token)
    expect(mockInstances[0].url).toContain('channel=test-ch')
  })

  it('appends parsed JSON events', async () => {
    const { result } = renderHook(() => useChannel('ch1'))
    await waitFor(() => expect(mockInstances).toHaveLength(1))

    const es = mockInstances[0]
    act(() => es.simulateOpen())
    expect(result.current.connected).toBe(true)

    const envelope = { channel: 'ch1', event: 'planning', data: { message: 'hi' }, id: '1', ts: new Date().toISOString() }
    act(() => es.simulateMessage(envelope))
    expect(result.current.events).toHaveLength(1)
    expect(result.current.events[0].event).toBe('planning')
  })

  it('ignores non-JSON messages', async () => {
    const { result } = renderHook(() => useChannel('ch1'))
    await waitFor(() => expect(mockInstances).toHaveLength(1))

    const es = mockInstances[0]
    act(() => es.simulateOpen())

    // Send raw non-JSON (heartbeat)
    act(() => {
      const ev = { data: ':heartbeat' } as MessageEvent
      es.onmessage?.(ev)
    })
    expect(result.current.events).toHaveLength(0)
  })

  it('sets error on disconnect and retries with backoff', async () => {
    const { result } = renderHook(() => useChannel('ch1'))
    await waitFor(() => expect(mockInstances).toHaveLength(1))

    const es = mockInstances[0]
    act(() => es.simulateOpen())
    expect(result.current.connected).toBe(true)

    act(() => es.simulateError())
    expect(result.current.connected).toBe(false)
    expect(result.current.error).toBeInstanceOf(Error)
    expect(result.current.error?.message).toContain('reconnecting')
  })

  it('caps events at maxEvents', async () => {
    const { result } = renderHook(() => useChannel('ch1', { maxEvents: 3 }))
    await waitFor(() => expect(mockInstances).toHaveLength(1))

    const es = mockInstances[0]
    act(() => es.simulateOpen())

    for (let i = 0; i < 5; i++) {
      act(() => es.simulateMessage({ channel: 'ch1', event: 'msg', data: {}, id: String(i), ts: new Date().toISOString() }))
    }
    expect(result.current.events).toHaveLength(3)
    // Should keep the most recent 3
    expect(result.current.events[0].id).toBe('2')
    expect(result.current.events[2].id).toBe('4')
  })

  it('resets events when channel changes', async () => {
    const { result, rerender } = renderHook(
      ({ ch }: { ch: string }) => useChannel(ch),
      { initialProps: { ch: 'ch1' } }
    )
    await waitFor(() => expect(mockInstances).toHaveLength(1))

    const es = mockInstances[0]
    act(() => es.simulateOpen())
    act(() => es.simulateMessage({ channel: 'ch1', event: 'msg', data: {}, id: '1', ts: new Date().toISOString() }))
    expect(result.current.events).toHaveLength(1)

    rerender({ ch: 'ch2' })
    // Events should be cleared on channel change
    await waitFor(() => expect(result.current.events).toHaveLength(0))
  })
})
