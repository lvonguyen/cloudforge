import { useState, useEffect, useRef, useCallback } from 'react'
import { TOKEN_KEY } from '@/lib/auth'

export interface Envelope {
  channel: string
  event: string
  data: unknown
  id: string
  ts: string
}

interface UseChannelOptions {
  enabled?: boolean
  maxEvents?: number
}

interface UseChannelReturn {
  events: Envelope[]
  connected: boolean
  error: Error | null
}

const WS_URL = (import.meta.env.VITE_WS_URL as string | undefined) ?? ''
const MAX_BACKOFF = 30_000

function getToken(): string | null {
  const isDev = import.meta.env.DEV || import.meta.env.VITE_DEMO_MODE === 'true'
  if (isDev) return (import.meta.env.VITE_DEV_TOKEN as string | undefined) ?? null
  return sessionStorage.getItem(TOKEN_KEY)
}

async function fetchTicket(): Promise<string | null> {
  const jwt = getToken()
  if (!jwt) return null
  try {
    const res = await fetch(`${WS_URL}/api/session/ticket`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Authorization: `Bearer ${jwt}`,
      },
      body: JSON.stringify({ user_id: 'cloudforge' }),
    })
    if (!res.ok) return null
    const data = (await res.json()) as { ticket?: string }
    return data.ticket ?? null
  } catch {
    return null
  }
}

export function useChannel(channel: string, opts?: UseChannelOptions): UseChannelReturn {
  const enabled = opts?.enabled ?? true
  const maxEvents = opts?.maxEvents ?? 200

  const [events, setEvents] = useState<Envelope[]>([])
  const [connected, setConnected] = useState(false)
  const [error, setError] = useState<Error | null>(null)

  const esRef = useRef<EventSource | null>(null)
  const retryRef = useRef(0)
  const timerRef = useRef<ReturnType<typeof setTimeout> | undefined>(undefined)

  const cleanup = useCallback(() => {
    if (timerRef.current) clearTimeout(timerRef.current)
    if (esRef.current) {
      esRef.current.close()
      esRef.current = null
    }
    setConnected(false)
  }, [])

  useEffect(() => {
    if (!enabled || !channel) {
      cleanup()
      return
    }

    async function connect() {
      // Fetch a single-use ticket (60s TTL) — safer than passing JWT in URL
      const ticket = await fetchTicket()
      const params = new URLSearchParams({ channel })
      if (ticket) {
        params.set('ticket', ticket)
      } else {
        // Fallback to token query param for dev/environments without ticket endpoint
        const token = getToken()
        if (token) params.set('token', token)
      }

      const url = `${WS_URL}/sse?${params}`
      const es = new EventSource(url)
      esRef.current = es

      es.onopen = () => {
        setConnected(true)
        setError(null)
        retryRef.current = 0
      }

      es.onmessage = (ev) => {
        try {
          const envelope = JSON.parse(ev.data) as Envelope
          setEvents(prev => {
            const next = [...prev, envelope]
            return next.length > maxEvents ? next.slice(-maxEvents) : next
          })
        } catch {
          // ignore non-JSON heartbeats
        }
      }

      es.onerror = () => {
        es.close()
        esRef.current = null
        setConnected(false)

        const backoff = Math.min(1000 * 2 ** retryRef.current, MAX_BACKOFF)
        retryRef.current++
        setError(new Error(`SSE disconnected, reconnecting in ${Math.round(backoff / 1000)}s`))

        // Re-fetch ticket on reconnect (previous ticket expired)
        timerRef.current = setTimeout(() => { void connect() }, backoff)
      }
    }

    void connect()

    return cleanup
  }, [channel, enabled, maxEvents, cleanup])

  // Reset events when channel changes
  useEffect(() => {
    setEvents([])
  }, [channel])

  return { events, connected, error }
}
