/**
 * Runtime configuration loader (Phase 3).
 *
 * Fetches /config.json at app startup to enable runtime branding without
 * rebuilding. This complements the Phase 2 env-var approach:
 *
 * - Phase 2 mode: branding.ts reads VITE_* env vars at build time
 * - Phase 3 mode: runtime-config.ts fetches /config.json at startup,
 *   overriding env-var defaults
 *
 * The runtime config is optional — if /config.json is missing or the
 * fetch fails, the app falls back to the build-time branding config.
 */

/** Schema for the runtime configuration JSON */
export interface RuntimeConfig {
  /** Organization display name */
  companyName: string
  /** Product name shown in nav/title */
  productName: string
  /** Logo path relative to /public */
  logoPath: string
  /** Email domain for demo/default users */
  emailDomain: string
  /** GitHub org prefix for repo links */
  repoPrefix: string
  /** Enabled module slugs */
  enabledModules: string[]
  /** LocalStorage key prefix */
  storagePrefix: string
  /** Theme customization */
  theme?: {
    primaryColor?: string
    secondaryColor?: string
    accentColor?: string
  }
  /** Feature flags */
  features?: {
    aiEnrichment?: boolean
    attackPaths?: boolean
    finops?: boolean
  }
}

/** Singleton config state */
let _config: RuntimeConfig | null = null
let _loading: Promise<RuntimeConfig | null> | null = null

/**
 * Default config values matching the Phase 2 env-var defaults.
 * Used as fallback when /config.json is unavailable.
 */
const DEFAULT_CONFIG: RuntimeConfig = {
  companyName: 'Contoso',
  productName: 'CloudForge',
  logoPath: '/icons/aegis-logo.svg',
  emailDomain: 'contoso.dev',
  repoPrefix: 'github.com/contoso',
  enabledModules: ['cloudforge', 'posture-management', 'threat-intel', 'remediation-engine', 'ops-center'],
  storagePrefix: 'aegis',
}

/**
 * Fetches runtime config from /config.json.
 * Returns null if the fetch fails (app should fall back to branding.ts).
 *
 * The result is cached — subsequent calls return the same promise.
 */
export async function loadRuntimeConfig(): Promise<RuntimeConfig | null> {
  if (_config) return _config
  if (_loading) return _loading

  _loading = (async () => {
    try {
      const res = await fetch('/config.json', {
        cache: 'no-cache', // Always get fresh config
        headers: { Accept: 'application/json' },
      })
      if (!res.ok) {
        console.info('[runtime-config] /config.json not found — using build-time branding')
        return null
      }
      const json = await res.json()
      _config = { ...DEFAULT_CONFIG, ...json }
      return _config
    } catch (err) {
      console.info('[runtime-config] Failed to load /config.json — using build-time branding', err)
      return null
    }
  })()

  return _loading
}

/**
 * Returns the cached runtime config, or null if not yet loaded.
 * Use this in synchronous contexts where the config has already been fetched.
 */
export function getRuntimeConfig(): RuntimeConfig | null {
  return _config
}

/**
 * Returns the effective config value, preferring runtime config over branding.ts.
 * This is the bridge between Phase 2 (env vars) and Phase 3 (runtime config).
 */
export function getConfigValue<K extends keyof RuntimeConfig>(
  key: K,
  fallback: RuntimeConfig[K],
): RuntimeConfig[K] {
  if (_config && _config[key] !== undefined) {
    return _config[key]
  }
  return fallback
}
