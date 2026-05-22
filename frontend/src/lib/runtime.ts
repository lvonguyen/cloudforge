const PRODUCTION_HOSTNAME = 'cloudforge.lvonguyen.com'
const PRODUCTION_API_BASE_URL = 'https://api.cloudforge.lvonguyen.com/api/v1'

function runtimeHostname(): string {
  if (typeof window === 'undefined') return ''
  return window.location.hostname
}

export function isProductionHostname(hostname = runtimeHostname()): boolean {
  return hostname === PRODUCTION_HOSTNAME
}

export function isDemoMode(): boolean {
  return !isProductionHostname() && import.meta.env.VITE_DEMO_MODE === 'true'
}

export function isMockFallbackEnabled(): boolean {
  return !isProductionHostname() &&
    (isDemoMode() || import.meta.env.VITE_ENABLE_MOCK_FALLBACK === 'true')
}

export function shouldPreferLocalMockAssets(): boolean {
  return isDemoMode() ||
    (import.meta.env.DEV && import.meta.env.VITE_ENABLE_MOCK_FALLBACK === 'true')
}

export function getApiBaseUrl(): string {
  if (isProductionHostname()) return PRODUCTION_API_BASE_URL
  return (import.meta.env.VITE_API_URL as string | undefined) ?? '/api/v1'
}
