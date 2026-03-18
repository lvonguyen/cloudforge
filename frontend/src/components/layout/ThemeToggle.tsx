import { useState, useEffect, useCallback } from 'react'
import { Monitor, Sun, Moon } from 'lucide-react'
import { Button } from '@/components/ui/button'

type ThemeMode = 'system' | 'light' | 'dark'

const STORAGE_KEY = 'theme'

const CYCLE: ThemeMode[] = ['system', 'light', 'dark']

const ICON: Record<ThemeMode, typeof Monitor> = { system: Monitor, light: Sun, dark: Moon }
const LABEL: Record<ThemeMode, string> = {
  system: 'System theme',
  light: 'Light theme',
  dark: 'Dark theme',
}

function getInitialMode(): ThemeMode {
  const stored = localStorage.getItem(STORAGE_KEY) as ThemeMode | null
  if (stored === 'light' || stored === 'dark') return stored
  return 'system'
}

function resolvedDark(mode: ThemeMode): boolean {
  if (mode === 'dark') return true
  if (mode === 'light') return false
  return window.matchMedia('(prefers-color-scheme: dark)').matches
}

export function ThemeToggle() {
  const [mode, setMode] = useState<ThemeMode>(getInitialMode)

  const applyTheme = useCallback((m: ThemeMode) => {
    document.documentElement.classList.toggle('dark', resolvedDark(m))
  }, [])

  useEffect(() => {
    applyTheme(mode)
  }, [mode, applyTheme])

  // Follow OS preference changes only when in system mode
  useEffect(() => {
    if (mode !== 'system') return
    const mq = window.matchMedia('(prefers-color-scheme: dark)')
    const handler = () => applyTheme('system')
    mq.addEventListener('change', handler)
    return () => mq.removeEventListener('change', handler)
  }, [mode, applyTheme])

  const cycle = () => {
    const next = CYCLE[(CYCLE.indexOf(mode) + 1) % CYCLE.length]
    setMode(next)
    if (next === 'system') {
      localStorage.removeItem(STORAGE_KEY)
    } else {
      localStorage.setItem(STORAGE_KEY, next)
    }
  }

  const Icon = ICON[mode]

  return (
    <Button variant="ghost" size="icon" onClick={cycle} className="h-8 w-8" aria-label={LABEL[mode]}>
      <Icon className="h-4 w-4" />
    </Button>
  )
}
