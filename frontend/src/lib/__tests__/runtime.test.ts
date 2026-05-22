import { describe, expect, it, vi, afterEach } from 'vitest'
import { getApiBaseUrl, isDemoMode, isMockFallbackEnabled, isProductionHostname } from '@/lib/runtime'

describe('runtime mode', () => {
  afterEach(() => {
    vi.unstubAllEnvs()
  })

  it('identifies the production custom domain', () => {
    expect(isProductionHostname('cloudforge.lvonguyen.com')).toBe(true)
    expect(isProductionHostname('cloudforge-demo.pages.dev')).toBe(false)
  })

  it('keeps non-production demo builds in demo mode', () => {
    vi.stubEnv('VITE_DEMO_MODE', 'true')

    expect(isDemoMode()).toBe(true)
    expect(isMockFallbackEnabled()).toBe(true)
  })

  it('uses the configured API base outside the production custom domain', () => {
    vi.stubEnv('VITE_API_URL', 'https://example.test/api/v1')

    expect(getApiBaseUrl()).toBe('https://example.test/api/v1')
  })
})
