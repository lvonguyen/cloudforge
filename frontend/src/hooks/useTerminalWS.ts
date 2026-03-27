import { useCallback, useEffect, useRef, useState } from 'react'
import { apiClient } from '@/lib/api'
import { TOKEN_KEY } from '@/lib/auth'

export interface ServerMessage {
  type: 'output' | 'exit' | 'error' | 'ping'
  id?: string
  stream?: 'stdout' | 'stderr'
  data?: string
  code?: number
  elapsed_ms?: number
  message?: string
}

interface UseTerminalWSOptions {
  enabled?: boolean
  onMessage?: (msg: ServerMessage) => void
  onConnected?: () => void
  onDisconnected?: () => void
}

interface UseTerminalWSReturn {
  send: (msg: unknown) => void
  isConnected: boolean
}

/** Derive WebSocket URL from the API base URL. */
function getWsUrl(): string {
  const apiUrl = (import.meta.env.VITE_API_URL as string | undefined) ?? ''

  // If empty or relative, use current host.
  if (!apiUrl || apiUrl.startsWith('/')) {
    const proto = location.protocol === 'https:' ? 'wss:' : 'ws:'
    return `${proto}//${location.host}/api/v1/terminal/ws`
  }

  // Absolute URL: swap http(s) -> ws(s).
  return apiUrl
    .replace(/^https:/, 'wss:')
    .replace(/^http:/, 'ws:')
    .replace(/\/api\/v1\/?$/, '') + '/api/v1/terminal/ws'
}

/**
 * Fetch a short-lived ticket nonce from the backend (SA-002).
 * Falls back to the raw JWT token if the ticket endpoint is unavailable
 * (backward compatibility with older backends).
 */
async function acquireTicket(): Promise<{ ticket: string } | { token: string } | null> {
  const token = sessionStorage.getItem(TOKEN_KEY)
  if (!token) return null

  try {
    const resp = await apiClient.post<{ ticket: string }>('/terminal/ticket', {})
    if (resp?.ticket) return { ticket: resp.ticket }
  } catch {
    // Ticket endpoint unavailable — fall back to legacy JWT-in-URL.
  }

  return { token }
}

const isDemoMode = import.meta.env.DEV || import.meta.env.VITE_DEMO_MODE === 'true'

const MOCK_RESPONSES: Record<string, string> = {
  'help': 'Available commands: aws, kubectl, gcloud, terraform, whoami, date, help\nNote: This is a demo terminal — commands return sample output.',
  'whoami': 'demo-operator@aegis.contoso.dev',
  'date': new Date().toISOString(),
  'aws s3 ls': '2026-01-15 aegis-findings-prod\n2026-02-01 aegis-config-backup\n2026-03-10 aegis-audit-logs',
  'aws sts get-caller-identity': '{\n  "UserId": "AROA3XFRBF23YPEXAMPLE",\n  "Account": "431330216246",\n  "Arn": "arn:aws:sts::431330216246:assumed-role/aegis-operator/session"\n}',
  'kubectl get pods': 'NAME                          READY   STATUS    RESTARTS   AGE\naegis-api-7d4f8b6c9-x2k4p    1/1     Running   0          2d\naegis-worker-5c8d9f7-m3n1q    1/1     Running   0          2d\nredis-master-0                1/1     Running   0          5d',
  'kubectl get nodes': 'NAME                          STATUS   ROLES    AGE   VERSION\nip-10-0-1-42.ec2.internal     Ready    <none>   14d   v1.31.2\nip-10-0-2-87.ec2.internal     Ready    <none>   14d   v1.31.2',
  'gcloud projects list': 'PROJECT_ID        NAME              PROJECT_NUMBER\nlvn-dev-483106    lvn-dev           483106\naegis-prod        aegis-prod        219847',
  'terraform plan': 'No changes. Your infrastructure matches the configuration.\n\nNo changes. Infrastructure is up-to-date.',
}

function mockExecute(cmd: string): string {
  const trimmed = cmd.trim().toLowerCase()
  if (MOCK_RESPONSES[trimmed]) return MOCK_RESPONSES[trimmed]
  if (trimmed.startsWith('aws ')) return `aws: command output simulated for: ${cmd.trim()}`
  if (trimmed.startsWith('kubectl ')) return `kubectl: command output simulated for: ${cmd.trim()}`
  if (trimmed === '') return ''
  return `command not found: ${cmd.trim()}\nType "help" for available commands.`
}

export function useTerminalWS(opts: UseTerminalWSOptions = {}): UseTerminalWSReturn {
  const { enabled = true, onMessage, onConnected, onDisconnected } = opts
  const wsRef = useRef<WebSocket | null>(null)
  const reconnectTimer = useRef<ReturnType<typeof setTimeout> | null>(null)
  const backoffRef = useRef(1000) // Start at 1s, max 30s.
  const [isConnected, setIsConnected] = useState(false)

  // Stable refs for callbacks.
  const onMessageRef = useRef(onMessage)
  onMessageRef.current = onMessage
  const onConnectedRef = useRef(onConnected)
  onConnectedRef.current = onConnected
  const onDisconnectedRef = useRef(onDisconnected)
  onDisconnectedRef.current = onDisconnected

  // Track whether the hook is still mounted to prevent reconnect after cleanup.
  const mountedRef = useRef(true)

  const connect = useCallback(async () => {
    if (!mountedRef.current) return

    const cred = await acquireTicket()
    if (!cred || !mountedRef.current) return

    // Build WS URL with ticket (preferred) or legacy token.
    const param = 'ticket' in cred
      ? `ticket=${encodeURIComponent(cred.ticket)}`
      : `token=${encodeURIComponent(cred.token)}`
    const url = `${getWsUrl()}?${param}`
    const ws = new WebSocket(url)
    wsRef.current = ws

    ws.onopen = () => {
      setIsConnected(true)
      backoffRef.current = 1000
      onConnectedRef.current?.()
    }

    ws.onmessage = (ev) => {
      try {
        const msg: ServerMessage = JSON.parse(ev.data)
        // Auto-respond to server pings.
        if (msg.type === 'ping') {
          ws.send(JSON.stringify({ type: 'pong' }))
          return
        }
        onMessageRef.current?.(msg)
      } catch {
        // Ignore malformed messages.
      }
    }

    ws.onclose = () => {
      setIsConnected(false)
      onDisconnectedRef.current?.()

      // Only reconnect if still mounted and enabled.
      if (mountedRef.current && wsRef.current === ws) {
        wsRef.current = null
        reconnectTimer.current = setTimeout(() => {
          backoffRef.current = Math.min(backoffRef.current * 2, 30000)
          connect()
        }, backoffRef.current)
      }
    }

    ws.onerror = () => {
      ws.close()
    }
  }, [])

  useEffect(() => {
    mountedRef.current = true
    if (!enabled) {
      wsRef.current?.close()
      wsRef.current = null
      setIsConnected(false)
      return
    }
    if (isDemoMode) {
      setIsConnected(true)
      onConnectedRef.current?.()
      return () => { mountedRef.current = false }
    }
    connect()
    return () => {
      mountedRef.current = false
      if (reconnectTimer.current) clearTimeout(reconnectTimer.current)
      wsRef.current?.close()
      wsRef.current = null
    }
  }, [enabled, connect])

  const send = useCallback((msg: unknown) => {
    if (isDemoMode) {
      const parsed = typeof msg === 'string' ? JSON.parse(msg) : msg
      const cmd = (parsed as { command?: string }).command ?? ''
      const output = mockExecute(cmd)
      setTimeout(() => {
        if (output) onMessageRef.current?.({ type: 'output', data: output + '\n', stream: 'stdout' })
        onMessageRef.current?.({ type: 'exit', code: 0, elapsed_ms: Math.floor(Math.random() * 200 + 50) })
      }, 150)
      return
    }
    if (wsRef.current?.readyState === WebSocket.OPEN) {
      wsRef.current.send(JSON.stringify(msg))
    }
  }, [])

  return { send, isConnected }
}
