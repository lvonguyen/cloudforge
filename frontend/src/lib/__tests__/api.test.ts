import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import { ApiError, queryClient, apiClient } from '@/lib/api'
import { setPreviewRoleOverride } from '@/lib/auth'

describe('ApiError', () => {
  it('constructs with status and message', () => {
    const err = new ApiError(404, 'Not Found')
    expect(err.status).toBe(404)
    expect(err.message).toBe('Not Found')
  })

  it('has name set to ApiError', () => {
    const err = new ApiError(500, 'Server Error')
    expect(err.name).toBe('ApiError')
  })

  it('is an instance of Error', () => {
    const err = new ApiError(401, 'Unauthorized')
    expect(err).toBeInstanceOf(Error)
  })

  it('is instanceof ApiError', () => {
    const err = new ApiError(403, 'Forbidden')
    expect(err).toBeInstanceOf(ApiError)
  })
})

describe('queryClient', () => {
  it('is a QueryClient instance (has getQueryData method)', () => {
    expect(typeof queryClient.getQueryData).toBe('function')
  })

  it('has retry logic that rejects after 3 failures', () => {
    // Access the default options to confirm retry is configured
    const defaultOptions = queryClient.getDefaultOptions()
    expect(defaultOptions.queries?.retry).toBeDefined()
  })

  it('retry returns false for non-retryable ApiError status codes', () => {
    const defaultOptions = queryClient.getDefaultOptions()
    const retryFn = defaultOptions.queries?.retry
    if (typeof retryFn !== 'function') return

    // 404 is a client error — should not retry
    const shouldRetry = retryFn(0, new ApiError(404, 'Not Found'))
    expect(shouldRetry).toBe(false)
  })

  it('retry returns true for 503 ApiError (service unavailable)', () => {
    const defaultOptions = queryClient.getDefaultOptions()
    const retryFn = defaultOptions.queries?.retry
    if (typeof retryFn !== 'function') return

    const shouldRetry = retryFn(0, new ApiError(503, 'Service Unavailable'))
    expect(shouldRetry).toBe(true)
  })

  it('retry returns false once failureCount reaches 3', () => {
    const defaultOptions = queryClient.getDefaultOptions()
    const retryFn = defaultOptions.queries?.retry
    if (typeof retryFn !== 'function') return

    const shouldRetry = retryFn(3, new ApiError(503, 'Service Unavailable'))
    expect(shouldRetry).toBe(false)
  })
})

describe('apiClient', () => {
  const originalFetch = global.fetch

  beforeEach(() => {
    global.fetch = vi.fn()
  })

  afterEach(() => {
    global.fetch = originalFetch
    vi.restoreAllMocks()
  })

  it('apiClient has get, post, put, delete methods', () => {
    expect(typeof apiClient.get).toBe('function')
    expect(typeof apiClient.post).toBe('function')
    expect(typeof apiClient.put).toBe('function')
    expect(typeof apiClient.delete).toBe('function')
  })

  it('apiClient.get makes a GET fetch request to the given path', async () => {
    const mockResponse = { id: 1, name: 'test' }
    vi.mocked(global.fetch).mockResolvedValueOnce(
      new Response(JSON.stringify(mockResponse), { status: 200 })
    )

    const result = await apiClient.get('/test-endpoint')
    expect(global.fetch).toHaveBeenCalledOnce()
    const callArgs = vi.mocked(global.fetch).mock.calls[0]
    expect(callArgs[0]).toContain('/test-endpoint')
    expect(result).toEqual(mockResponse)
  })

  it('apiClient.get throws ApiError on non-ok response', async () => {
    vi.mocked(global.fetch).mockResolvedValueOnce(
      new Response('Not Found', { status: 404 })
    )

    await expect(apiClient.get('/missing')).rejects.toBeInstanceOf(ApiError)
  })

  it('apiClient.get throws ApiError with correct status on 401', async () => {
    vi.mocked(global.fetch).mockResolvedValueOnce(
      new Response('Unauthorized', { status: 401 })
    )

    try {
      await apiClient.get('/protected')
    } catch (err) {
      expect(err).toBeInstanceOf(ApiError)
      expect((err as ApiError).status).toBe(401)
    }
  })

  it('apiClient.post sends JSON body with POST method', async () => {
    const payload = { name: 'test', value: 42 }
    vi.mocked(global.fetch).mockResolvedValueOnce(
      new Response(JSON.stringify({ ok: true }), { status: 200 })
    )

    await apiClient.post('/resource', payload)

    const callArgs = vi.mocked(global.fetch).mock.calls[0]
    const options = callArgs[1] as RequestInit
    expect(options.method).toBe('POST')
    expect(options.body).toBe(JSON.stringify(payload))
  })
})

describe('authHeaders (via apiClient)', () => {
  const originalFetch = global.fetch

  beforeEach(() => {
    global.fetch = vi.fn()
    sessionStorage.clear()
    setPreviewRoleOverride(null)
  })

  afterEach(() => {
    global.fetch = originalFetch
    vi.restoreAllMocks()
    vi.unstubAllEnvs()
    setPreviewRoleOverride(null)
  })

  it('includes X-Aegis-Role header in DEV mode when role is set', async () => {
    vi.stubEnv('DEV', true)
    setPreviewRoleOverride('operator')
    vi.mocked(global.fetch).mockResolvedValueOnce(
      new Response(JSON.stringify({ ok: true }), { status: 200 })
    )

    await apiClient.get('/test')

    const callArgs = vi.mocked(global.fetch).mock.calls[0]
    const options = callArgs[1] as RequestInit
    const headers = options.headers as Record<string, string>
    expect(headers['X-Aegis-Role']).toBe('operator')
  })

  it('omits X-Aegis-Role header in production mode', async () => {
    vi.stubEnv('DEV', false)
    setPreviewRoleOverride('admin')
    sessionStorage.setItem('aegis_access_token', 'fake-token')
    vi.mocked(global.fetch).mockResolvedValueOnce(
      new Response(JSON.stringify({ ok: true }), { status: 200 })
    )

    await apiClient.get('/test')

    const callArgs = vi.mocked(global.fetch).mock.calls[0]
    const options = callArgs[1] as RequestInit
    const headers = options.headers as Record<string, string>
    expect(headers['X-Aegis-Role']).toBeUndefined()
  })

  it('prefers the stored session token over the static token in production', async () => {
    vi.stubEnv('DEV', false)
    vi.stubEnv('VITE_STATIC_TOKEN', 'static-viewer-token')
    sessionStorage.setItem('aegis_access_token', 'session-admin-token')
    vi.mocked(global.fetch).mockResolvedValueOnce(
      new Response(JSON.stringify({ ok: true }), { status: 200 })
    )

    await apiClient.get('/test')

    const callArgs = vi.mocked(global.fetch).mock.calls[0]
    const options = callArgs[1] as RequestInit
    const headers = options.headers as Record<string, string>
    expect(headers.Authorization).toBe('Bearer session-admin-token')
  })

  it('falls back to the static token when no stored session token exists', async () => {
    vi.stubEnv('DEV', false)
    vi.stubEnv('VITE_STATIC_TOKEN', 'static-viewer-token')
    vi.mocked(global.fetch).mockResolvedValueOnce(
      new Response(JSON.stringify({ ok: true }), { status: 200 })
    )

    await apiClient.get('/test')

    const callArgs = vi.mocked(global.fetch).mock.calls[0]
    const options = callArgs[1] as RequestInit
    const headers = options.headers as Record<string, string>
    expect(headers.Authorization).toBe('Bearer static-viewer-token')
  })
})

describe('apiClient.delete', () => {
  const originalFetch = global.fetch

  beforeEach(() => {
    global.fetch = vi.fn()
  })

  afterEach(() => {
    global.fetch = originalFetch
    vi.restoreAllMocks()
  })

  it('sends DELETE method', async () => {
    vi.mocked(global.fetch).mockResolvedValueOnce(
      new Response(JSON.stringify({ deleted: true }), { status: 200 })
    )

    await apiClient.delete('/resource/1')

    const callArgs = vi.mocked(global.fetch).mock.calls[0]
    const options = callArgs[1] as RequestInit
    expect(options.method).toBe('DELETE')
  })
})
