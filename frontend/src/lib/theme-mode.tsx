import {
  createContext,
  startTransition,
  useContext,
  useEffect,
  useMemo,
  useState,
  type ReactNode,
} from 'react'
import {
  getStoredThemeMode,
  getSystemThemeMedia,
  getSystemPrefersDark,
  isThemeMode,
  resolveThemeMode,
  setStoredThemeMode,
  subscribeToThemeModeChanges,
  syncThemeModeClass,
  THEME_MODE_ATTRIBUTE,
  THEME_RESOLVED_ATTRIBUTE,
  THEME_STORAGE_KEY,
  type ResolvedThemeMode,
  type ThemeMode,
} from '@/lib/theme-utils'

interface ThemeModeContextValue {
  mode: ThemeMode
  resolvedMode: ResolvedThemeMode
  setMode: (mode: ThemeMode) => void
}

const ThemeModeContext = createContext<ThemeModeContextValue | null>(null)

export function ThemeModeProvider({ children }: { children: ReactNode }) {
  const [mode, setModeState] = useState<ThemeMode>(getStoredThemeMode)
  const [systemMode, setSystemMode] = useState<ResolvedThemeMode>(getSystemPrefersDark() ? 'dark' : 'light')

  useEffect(() => {
    const media = getSystemThemeMedia()
    if (!media) return

    const handleChange = (event: MediaQueryListEvent) => {
      startTransition(() => {
        setSystemMode(event.matches ? 'dark' : 'light')
      })
    }

    setSystemMode(media.matches ? 'dark' : 'light')
    if (typeof media.addEventListener === 'function') {
      media.addEventListener('change', handleChange)
      return () => media.removeEventListener('change', handleChange)
    }

    media.addListener(handleChange)
    return () => media.removeListener(handleChange)
  }, [])

  useEffect(() => {
    return subscribeToThemeModeChanges(() => {
      startTransition(() => {
        setModeState(getStoredThemeMode())
        setSystemMode(getSystemPrefersDark() ? 'dark' : 'light')
      })
    })
  }, [])

  const resolvedMode: ResolvedThemeMode = resolveThemeMode(mode, systemMode === 'dark')

  useEffect(() => {
    syncThemeModeClass(mode)
  }, [mode, resolvedMode])

  const value = useMemo<ThemeModeContextValue>(() => ({
    mode,
    resolvedMode,
    setMode: (nextMode: ThemeMode) => {
      setModeState(nextMode)
      setStoredThemeMode(nextMode)
    },
  }), [mode, resolvedMode])

  return (
    <ThemeModeContext.Provider value={value}>
      {children}
    </ThemeModeContext.Provider>
  )
}

export function useThemeMode(): ThemeModeContextValue {
  const context = useContext(ThemeModeContext)
  if (!context) {
    throw new Error('useThemeMode must be used within ThemeModeProvider')
  }
  return context
}

export {
  isThemeMode,
  resolveThemeMode,
  syncThemeModeClass,
  THEME_MODE_ATTRIBUTE,
  THEME_RESOLVED_ATTRIBUTE,
  THEME_STORAGE_KEY,
}
export type { ResolvedThemeMode, ThemeMode }
