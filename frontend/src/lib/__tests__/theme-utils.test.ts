import { beforeEach, describe, expect, it } from 'vitest'
import {
  getStoredThemeMode,
  resolveThemeMode,
  syncThemeModeClass,
  THEME_STORAGE_KEY,
} from '@/lib/theme-utils'

function stubLocalStorage() {
  const store = new Map<string, string>()
  Object.defineProperty(window, 'localStorage', {
    configurable: true,
    writable: true,
    value: {
      getItem: (key: string) => store.get(key) ?? null,
      setItem: (key: string, value: string) => { store.set(key, value) },
      removeItem: (key: string) => { store.delete(key) },
      clear: () => { store.clear() },
    },
  })
}

function stubMatchMedia(matches: boolean) {
  Object.defineProperty(window, 'matchMedia', {
    writable: true,
    value: (query: string) => ({
      matches,
      media: query,
      onchange: null,
      addListener: () => {},
      removeListener: () => {},
      addEventListener: () => {},
      removeEventListener: () => {},
      dispatchEvent: () => false,
    }),
  })
}

describe('theme-utils helpers', () => {
  beforeEach(() => {
    stubLocalStorage()
    stubMatchMedia(false)
    document.documentElement.className = ''
    document.documentElement.removeAttribute('data-theme-mode')
    document.documentElement.removeAttribute('data-theme-resolved')
  })

  it('defaults to auto when storage is empty or invalid', () => {
    expect(getStoredThemeMode()).toBe('auto')
    window.localStorage.setItem(THEME_STORAGE_KEY, 'invalid')
    expect(getStoredThemeMode()).toBe('auto')
  })

  it('resolves auto mode using the system preference', () => {
    expect(resolveThemeMode('auto', false)).toBe('light')
    expect(resolveThemeMode('auto', true)).toBe('dark')
  })

  it('syncs the document theme class and datasets', () => {
    window.localStorage.setItem(THEME_STORAGE_KEY, 'auto')
    stubMatchMedia(true)

    const resolved = syncThemeModeClass()

    expect(resolved).toBe('dark')
    expect(document.documentElement).toHaveClass('dark')
    expect(document.documentElement.dataset.themeMode).toBe('auto')
    expect(document.documentElement.dataset.themeResolved).toBe('dark')
  })
})
