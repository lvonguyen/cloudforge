import { beforeEach, describe, expect, it } from 'vitest'
import { fireEvent, render, screen, waitFor } from '@testing-library/react'

import { ThemeToggle } from '@/components/layout/ThemeToggle'
import { THEME_STORAGE_KEY } from '@/lib/theme-utils'

function createMatchMediaController(initialMatches: boolean) {
  let matches = initialMatches
  const listeners = new Set<(event: MediaQueryListEvent) => void>()

  Object.defineProperty(window, 'matchMedia', {
    configurable: true,
    writable: true,
    value: () => ({
      get matches() {
        return matches
      },
      media: '(prefers-color-scheme: dark)',
      onchange: null,
      addListener: (listener: (event: MediaQueryListEvent) => void) => listeners.add(listener),
      removeListener: (listener: (event: MediaQueryListEvent) => void) => listeners.delete(listener),
      addEventListener: (_type: string, listener: (event: MediaQueryListEvent) => void) => listeners.add(listener),
      removeEventListener: (_type: string, listener: (event: MediaQueryListEvent) => void) => listeners.delete(listener),
      dispatchEvent: () => true,
    }),
  })

  return {
    setMatches(nextMatches: boolean) {
      matches = nextMatches
      const event = { matches: nextMatches } as MediaQueryListEvent
      for (const listener of listeners) {
        listener(event)
      }
    },
  }
}

function openMenu() {
  fireEvent.pointerDown(screen.getByRole('button', { name: /theme:/i }), {
    button: 0,
    pointerType: 'mouse',
  })
}

describe('ThemeToggle', () => {
  beforeEach(() => {
    const store = new Map<string, string>()
    Object.defineProperty(window, 'localStorage', {
      configurable: true,
      value: {
        getItem: (key: string) => store.get(key) ?? null,
        setItem: (key: string, value: string) => { store.set(key, value) },
        removeItem: (key: string) => { store.delete(key) },
        clear: () => { store.clear() },
      },
    })
    localStorage.clear()
    document.documentElement.className = ''
    document.documentElement.removeAttribute('data-theme-mode')
    document.documentElement.removeAttribute('data-theme-resolved')
    document.documentElement.style.colorScheme = ''
  })

  it('defaults to auto and tracks system theme changes', async () => {
    const media = createMatchMediaController(true)

    render(<ThemeToggle />)

    await waitFor(() => {
      expect(screen.getByRole('button', { name: /theme: auto/i })).toBeInTheDocument()
      expect(document.documentElement).toHaveClass('dark')
      expect(document.documentElement.dataset.themeMode).toBe('auto')
    })

    media.setMatches(false)

    await waitFor(() => {
      expect(document.documentElement).not.toHaveClass('dark')
      expect(document.documentElement.dataset.themeResolved).toBe('light')
    })
  })

  it('persists explicit theme selections from the menu', async () => {
    createMatchMediaController(false)
    render(<ThemeToggle />)

    openMenu()
    fireEvent.click(screen.getByRole('menuitemradio', { name: /dark/i }))

    await waitFor(() => {
      expect(localStorage.getItem(THEME_STORAGE_KEY)).toBe('dark')
      expect(document.documentElement).toHaveClass('dark')
      expect(screen.getByRole('button', { name: /theme: dark/i })).toBeInTheDocument()
    })
  })
})
