import { beforeEach, describe, expect, it } from 'vitest'
import { fireEvent, render, screen, waitFor } from '@testing-library/react'
import { ThemeToggle } from '@/components/layout/ThemeToggle'
import { THEME_STORAGE_KEY } from '@/lib/theme-utils'

const MEDIA_QUERY = '(prefers-color-scheme: dark)'

let systemDark = false
let storage = new Map<string, string>()
const listeners = new Set<(event: MediaQueryListEvent) => void>()

function installLocalStorage() {
  Object.defineProperty(window, 'localStorage', {
    writable: true,
    value: {
      getItem: (key: string) => storage.get(key) ?? null,
      setItem: (key: string, value: string) => {
        storage.set(key, value)
      },
      removeItem: (key: string) => {
        storage.delete(key)
      },
      clear: () => {
        storage.clear()
      },
    },
  })
}

function installMatchMedia() {
  Object.defineProperty(window, 'matchMedia', {
    writable: true,
    value: (query: string) => ({
      matches: query === MEDIA_QUERY ? systemDark : false,
      media: query,
      onchange: null,
      addListener: (listener: (event: MediaQueryListEvent) => void) => listeners.add(listener),
      removeListener: (listener: (event: MediaQueryListEvent) => void) => listeners.delete(listener),
      addEventListener: (_type: string, listener: (event: MediaQueryListEvent) => void) => listeners.add(listener),
      removeEventListener: (_type: string, listener: (event: MediaQueryListEvent) => void) => listeners.delete(listener),
      dispatchEvent: () => false,
    }),
  })
}

function setSystemTheme(dark: boolean) {
  systemDark = dark
  const event = { matches: dark, media: MEDIA_QUERY } as MediaQueryListEvent
  for (const listener of listeners) listener(event)
}

function renderToggle() {
  return render(<ThemeToggle />)
}

describe('ThemeToggle', () => {
  beforeEach(() => {
    systemDark = false
    storage = new Map()
    listeners.clear()
    document.documentElement.className = ''
    document.documentElement.removeAttribute('data-theme-mode')
    document.documentElement.removeAttribute('data-theme-resolved')
    document.documentElement.style.colorScheme = ''
    installLocalStorage()
    installMatchMedia()
  })

  it('defaults to auto mode and reflects the system theme in the label', async () => {
    renderToggle()

    await waitFor(() => {
      expect(document.documentElement.getAttribute('data-theme-mode')).toBe('auto')
    })
    expect(document.documentElement.getAttribute('data-theme-resolved')).toBe('light')
    expect(screen.getByRole('button', { name: 'Theme: Auto (light system)' })).toBeInTheDocument()
  })

  it('stores the selected theme mode and updates the document class', async () => {
    renderToggle()

    fireEvent.pointerDown(screen.getByRole('button', { name: 'Theme: Auto (light system)' }), { button: 0 })
    fireEvent.click(await screen.findByRole('menuitemradio', { name: /Dark/i }))

    await waitFor(() => {
      expect(document.documentElement).toHaveClass('dark')
    })
    expect(window.localStorage.getItem(THEME_STORAGE_KEY)).toBe('dark')
    expect(screen.getByRole('button', { name: 'Theme: Dark' })).toBeInTheDocument()
  })

  it('reflects a dark system preference while auto mode is active', async () => {
    systemDark = true
    renderToggle()

    await waitFor(() => {
      expect(document.documentElement).toHaveClass('dark')
    })
    expect(screen.getByRole('button', { name: 'Theme: Auto (dark system)' })).toBeInTheDocument()

    setSystemTheme(false)

    await waitFor(() => {
      expect(document.documentElement).not.toHaveClass('dark')
    })
    expect(screen.getByRole('button', { name: 'Theme: Auto (light system)' })).toBeInTheDocument()
  })
})
