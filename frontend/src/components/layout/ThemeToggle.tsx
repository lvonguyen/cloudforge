import { useState, useEffect, useCallback } from 'react'
import { Sun, Moon } from 'lucide-react'
import { Button } from '@/components/ui/button'

type ThemeMode = 'light' | 'dark'

const STORAGE_KEY = 'theme'

const LABEL: Record<ThemeMode, string> = {
  light: 'Switch to dark theme',
  dark: 'Switch to light theme',
}

function getInitialMode(): ThemeMode {
  const stored = localStorage.getItem(STORAGE_KEY) as ThemeMode | null
  if (stored === 'light' || stored === 'dark') return stored
  return window.matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light'
}

export function ThemeToggle() {
  const [mode, setMode] = useState<ThemeMode>(getInitialMode)

  const applyTheme = useCallback((m: ThemeMode) => {
    document.documentElement.classList.toggle('dark', m === 'dark')
  }, [])

  useEffect(() => {
    applyTheme(mode)
  }, [mode, applyTheme])

  const toggle = () => {
    const next: ThemeMode = mode === 'light' ? 'dark' : 'light'
    setMode(next)
    localStorage.setItem(STORAGE_KEY, next)
  }

  const Icon = mode === 'light' ? Sun : Moon

  return (
    <Button variant="ghost" size="icon" onClick={toggle} className="h-8 w-8" aria-label={LABEL[mode]}>
      <Icon className="h-4 w-4" />
    </Button>
  )
}
