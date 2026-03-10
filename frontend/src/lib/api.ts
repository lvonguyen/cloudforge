import { QueryClient } from '@tanstack/react-query'
import { TOKEN_KEY } from './auth'

const BASE_URL = (import.meta.env.VITE_API_URL as string | undefined) ?? '/api/v1'

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
  const token = import.meta.env.DEV
    ? (import.meta.env.VITE_DEV_TOKEN as string | undefined)
    : sessionStorage.getItem(TOKEN_KEY)
  return token ? { Authorization: `Bearer ${token}` } : {}
}

async function request<T>(path: string, options?: RequestInit): Promise<T> {
  const controller = new AbortController()
  const timeout = setTimeout(() => controller.abort(), 30_000)

  try {
    const res = await fetch(`${BASE_URL}${path}`, {
      headers: { 'Content-Type': 'application/json', ...authHeaders(), ...options?.headers },
      ...options,
      signal: controller.signal,
    })
    if (!res.ok) {
      const text = await res.text().catch(() => res.statusText)
      throw new ApiError(res.status, text)
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
  delete<T>(path: string): Promise<T> {
    return request<T>(path, { method: 'DELETE' })
  },
}
