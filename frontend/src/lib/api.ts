import { QueryClient } from '@tanstack/react-query'
import { TOKEN_KEY } from './auth'

const BASE_URL = (import.meta.env.VITE_API_URL as string | undefined) ?? '/api/v1'

// Generate a W3C traceparent header for distributed tracing.
// Format: 00-<trace-id>-<span-id>-01
function generateTraceparent(): string {
  const traceId = Array.from(crypto.getRandomValues(new Uint8Array(16)))
    .map(b => b.toString(16).padStart(2, '0')).join('')
  const spanId = Array.from(crypto.getRandomValues(new Uint8Array(8)))
    .map(b => b.toString(16).padStart(2, '0')).join('')
  return `00-${traceId}-${spanId}-01`
}

// Last generated trace ID for display in error toasts or dev tools.
let lastTraceId = ''

/** Returns the trace ID from the most recent API request. */
export function getLastTraceId(): string {
  return lastTraceId
}

export const queryClient = new QueryClient({
  defaultOptions: {
    queries: {
      staleTime: 5 * 60 * 1000, // 5 minutes
      retry: (failureCount, error) => {
        if (failureCount >= 3) return false
        if (error instanceof ApiError) {
          return [408, 429, 500, 502, 503, 504].includes(error.status)
        }
        return true
      },
      retryDelay: (attempt) => Math.min(1000 * 2 ** attempt, 30_000),
    },
  },
})

export class ApiError extends Error {
  status: number
  constructor(status: number, message: string) {
    super(message)
    this.status = status
    this.name = 'ApiError'
  }
}

function authHeaders(): Record<string, string> {
  const isDev = import.meta.env.DEV
  const token = isDev
    ? (import.meta.env.VITE_DEV_TOKEN as string | undefined)
    : sessionStorage.getItem(TOKEN_KEY)
  const headers: Record<string, string> = token ? { Authorization: `Bearer ${token}` } : {}

  // In dev/demo mode, forward the frontend role override so the backend
  // RoleEnforcer (which checks X-Aegis-Role in dev mode) stays in sync.
  if (isDev) {
    const role = sessionStorage.getItem(`${import.meta.env.VITE_STORAGE_PREFIX || 'aegis'}_role`)
    if (role) headers['X-Aegis-Role'] = role
  }

  return headers
}

async function request<T>(path: string, options?: RequestInit): Promise<T> {
  const controller = new AbortController()
  const timeout = setTimeout(() => controller.abort(), 30_000)

  // Generate trace context for distributed tracing
  const traceparent = generateTraceparent()
  lastTraceId = traceparent.split('-')[1]

  try {
    const res = await fetch(`${BASE_URL}${path}`, {
      headers: { 'Content-Type': 'application/json', traceparent, ...authHeaders(), ...options?.headers },
      ...options,
      signal: controller.signal,
    })
    if (!res.ok) {
      const text = await res.text().catch(() => res.statusText)
      throw new ApiError(res.status, text)
    }
    // 204 No Content has no body — avoid SyntaxError from res.json()
    if (res.status === 204 || res.headers.get('content-length') === '0') {
      return undefined as T
    }
    return res.json() as Promise<T>
  } catch (err) {
    if (err instanceof ApiError) throw err
    if (controller.signal.aborted) {
      throw new ApiError(408, 'Request timed out')
    }
    throw err
  } finally {
    clearTimeout(timeout)
  }
}

/**
 * Fetch from API with automatic mock-data fallback in dev/demo mode.
 * Re-throws client errors (4xx) so they surface in the UI. In dev mode,
 * swallows 5xx / network errors and returns mock data. In production,
 * propagates all errors so React Query retry/error UI handles them.
 *
 * For single-item lookups that need post-filtering, use the inline
 * try/catch pattern instead (see useAgent, usePolicy).
 */
export async function fetchWithMockFallback<T>(
  path: string,
  mockImport: () => Promise<{ default: T }>,
  label: string,
): Promise<T> {
  // In demo mode, skip API entirely — no backend to call
  if (import.meta.env.VITE_DEMO_MODE === 'true') {
    console.warn(`[${label}] Demo mode, using mock data`)
    const mod = await mockImport()
    return mod.default
  }

  try {
    const raw = await apiClient.get<T | { data: T }>(path)
    // Backend list endpoints return paginated {data, page, ...} envelopes.
    // Unwrap if the response is an object with a data property and T is expected to be an array.
    if (raw != null && typeof raw === 'object' && !Array.isArray(raw) && 'data' in raw) {
      return (raw as { data: T }).data
    }
    return raw as T
  } catch (err) {
    if (err instanceof ApiError && err.status < 500) throw err
    if (import.meta.env.PROD && import.meta.env.VITE_DEMO_MODE !== 'true') throw err
    console.warn(`[${label}] API unavailable, using mock data`)
    try {
      const mod = await mockImport()
      return mod.default
    } catch {
      console.error(`[${label}] Mock import also failed`)
      throw err
    }
  }
}

/**
 * Unwrap paginated API responses. The Go backend wraps list endpoints in
 * {data, page, per_page, total, total_pages}. Mock fallbacks return raw arrays.
 * This helper handles both shapes transparently.
 */
export function unwrapPaginated<T>(response: T[] | { data: T[] }): T[] {
  if (Array.isArray(response)) return response
  return response.data
}

export const apiClient = {
  get<T>(path: string): Promise<T> {
    return request<T>(path)
  },
  post<T>(path: string, body: unknown): Promise<T> {
    return request<T>(path, { method: 'POST', body: JSON.stringify(body) })
  },
  put<T>(path: string, body: unknown): Promise<T> {
    return request<T>(path, { method: 'PUT', body: JSON.stringify(body) })
  },
  patch<T>(path: string, body: unknown): Promise<T> {
    return request<T>(path, { method: 'PATCH', body: JSON.stringify(body) })
  },
  delete<T>(path: string): Promise<T> {
    return request<T>(path, { method: 'DELETE' })
  },
}
