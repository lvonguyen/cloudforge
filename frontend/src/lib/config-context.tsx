/**
 * React context for runtime configuration (Phase 3).
 *
 * Wraps the app and provides runtime config values via useConfig() hook.
 * The provider fetches /config.json on mount and shows a minimal loading
 * state while waiting (FOUC prevention).
 *
 * Usage:
 *   // App.tsx (Phase 3 mode — not yet wired, shown for reference)
 *   <ConfigProvider>
 *     <AuthProvider>
 *       ...
 *     </AuthProvider>
 *   </ConfigProvider>
 *
 *   // Any component
 *   const config = useConfig()
 *   console.log(config?.productName) // "Aegis" or tenant override
 */
import { createContext, useContext, useState, useEffect, useMemo, type ReactNode } from 'react'
import { loadRuntimeConfig, type RuntimeConfig } from '@/lib/runtime-config'
import { initTheme } from '@/lib/apply-theme'

interface ConfigContextValue {
  /** Runtime config, or null if loading / unavailable */
  config: RuntimeConfig | null
  /** True while /config.json is being fetched */
  loading: boolean
}

const ConfigContext = createContext<ConfigContextValue>({
  config: null,
  loading: true,
})

/**
 * ConfigProvider — fetches runtime config on mount.
 *
 * FOUC prevention: while loading, renders a minimal blank screen
 * that matches the dark/light theme (set by the anti-flash script in index.html).
 * The loading state is intentionally minimal — no spinner, no layout shift.
 */
export function ConfigProvider({ children }: { children: ReactNode }) {
  const [config, setConfig] = useState<RuntimeConfig | null>(null)
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    let active = true

    loadRuntimeConfig().then((cfg) => {
      if (!active) return
      setConfig(cfg)
      initTheme(undefined, cfg?.theme ? {
        primary: cfg.theme.primaryColor,
        secondary: cfg.theme.secondaryColor,
        accent: cfg.theme.accentColor,
      } : undefined)
      setLoading(false)
    })

    return () => {
      active = false
    }
  }, [])

  const value = useMemo<ConfigContextValue>(
    () => ({ config, loading }),
    [config, loading],
  )

  if (loading) {
    // Minimal loading state — background matches theme to prevent FOUC
    return (
      <div
        style={{
          minHeight: '100vh',
          backgroundColor: 'var(--color-background, #E7E7E6)',
        }}
      />
    )
  }

  return (
    <ConfigContext.Provider value={value}>
      {children}
    </ConfigContext.Provider>
  )
}

/**
 * Hook to access runtime config.
 * Returns { config, loading } — config is null if runtime config is unavailable.
 */
export function useConfig(): ConfigContextValue {
  return useContext(ConfigContext)
}
