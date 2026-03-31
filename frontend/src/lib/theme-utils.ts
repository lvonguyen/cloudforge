import { reapplyTheme } from '@/lib/apply-theme'

export type ThemeMode = 'auto' | 'light' | 'dark'
export type ResolvedThemeMode = Exclude<ThemeMode, 'auto'>

export const THEME_STORAGE_KEY = 'theme'
export const THEME_MODE_CHANGE_EVENT = 'cloudforge:theme-mode-change'

const SYSTEM_THEME_QUERY = '(prefers-color-scheme: dark)'

function getThemeStorage(): Pick<Storage, 'getItem' | 'setItem'> | null {
  if (typeof window === 'undefined') return null
  const storage = window.localStorage
  if (!storage || typeof storage.getItem !== 'function' || typeof storage.setItem !== 'function') {
    return null
  }
  return storage
}

export function isThemeMode(value: string | null | undefined): value is ThemeMode {
  return value === 'auto' || value === 'light' || value === 'dark'
}

export function getStoredThemeMode(storage: Pick<Storage, 'getItem'> | null = getThemeStorage()): ThemeMode {
  const stored = storage?.getItem(THEME_STORAGE_KEY)
  return isThemeMode(stored) ? stored : 'auto'
}

export function setStoredThemeMode(mode: ThemeMode, storage: Pick<Storage, 'setItem'> | null = getThemeStorage()): void {
  storage?.setItem(THEME_STORAGE_KEY, mode)
}

export function getSystemThemeMedia(): MediaQueryList | null {
  if (typeof window === 'undefined' || typeof window.matchMedia !== 'function') return null
  return window.matchMedia(SYSTEM_THEME_QUERY)
}

export function getSystemPrefersDark(): boolean {
  return getSystemThemeMedia()?.matches ?? false
}

export function resolveThemeMode(mode: ThemeMode, prefersDark = getSystemPrefersDark()): ResolvedThemeMode {
  if (mode === 'auto') {
    return prefersDark ? 'dark' : 'light'
  }
  return mode
}

export function syncThemeModeClass(mode = getStoredThemeMode()): ResolvedThemeMode {
  const resolved = resolveThemeMode(mode)
  if (typeof document === 'undefined') return resolved

  const root = document.documentElement
  root.classList.toggle('dark', resolved === 'dark')
  root.dataset.themeMode = mode
  root.dataset.themeResolved = resolved
  root.style.colorScheme = resolved
  reapplyTheme()
  return resolved
}

export function announceThemeModeChange(): void {
  if (typeof window === 'undefined') return
  window.dispatchEvent(new CustomEvent(THEME_MODE_CHANGE_EVENT))
}

export function subscribeToThemeModeChanges(onChange: () => void): () => void {
  if (typeof window === 'undefined') {
    return () => {}
  }

  const handleCustom = () => onChange()
  const handleStorage = (event: StorageEvent) => {
    if (event.key === null || event.key === THEME_STORAGE_KEY) {
      onChange()
    }
  }
  const handleMedia = () => {
    if (getStoredThemeMode() === 'auto') {
      onChange()
    }
  }

  window.addEventListener(THEME_MODE_CHANGE_EVENT, handleCustom as EventListener)
  window.addEventListener('storage', handleStorage)

  const media = getSystemThemeMedia()
  if (media && typeof media.addEventListener === 'function') {
    media.addEventListener('change', handleMedia)
    return () => {
      window.removeEventListener(THEME_MODE_CHANGE_EVENT, handleCustom as EventListener)
      window.removeEventListener('storage', handleStorage)
      media.removeEventListener('change', handleMedia)
    }
  }

  return () => {
    window.removeEventListener(THEME_MODE_CHANGE_EVENT, handleCustom as EventListener)
    window.removeEventListener('storage', handleStorage)
  }
}
