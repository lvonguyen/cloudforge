import { useState, useEffect, useCallback } from 'react'
import { Sun, Moon } from 'lucide-react'
import { Button } from '@/components/ui/button'

const STORAGE_KEY = 'theme'

function getInitialTheme(): boolean {
  const stored = localStorage.getItem(STORAGE_KEY)
  if (stored) return stored === 'dark'
  return window.matchMedia('(prefers-color-scheme: dark)').matches
}

export function ThemeToggle() {
  const [isDark, setIsDark] = useState(getInitialTheme)
  const [hasExplicitPref, setHasExplicitPref] = useState(
    () => localStorage.getItem(STORAGE_KEY) !== null,
  )

  const applyTheme = useCallback((dark: boolean) => {
    document.documentElement.classList.toggle('dark', dark)
  }, [])

  useEffect(() => {
    applyTheme(isDark)
  }, [isDark, applyTheme])

  useEffect(() => {
    if (hasExplicitPref) return

    const mq = window.matchMedia('(prefers-color-scheme: dark)')
    const handler = (e: MediaQueryListEvent) => setIsDark(e.matches)
    mq.addEventListener('change', handler)
    return () => mq.removeEventListener('change', handler)
  }, [hasExplicitPref])

  const toggle = () => {
    const next = !isDark
    setIsDark(next)
    setHasExplicitPref(true)
    localStorage.setItem(STORAGE_KEY, next ? 'dark' : 'light')
  }

  return (
    <Button variant="ghost" size="icon" onClick={toggle} className="h-8 w-8" aria-label="Toggle theme">
      {isDark ? <Sun className="h-4 w-4" /> : <Moon className="h-4 w-4" />}
    </Button>
  )
}
