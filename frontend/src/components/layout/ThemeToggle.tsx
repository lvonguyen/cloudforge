import { useEffect, useMemo, useState } from 'react'
import { Check, Monitor, Moon, Sun } from 'lucide-react'
import { Button } from '@/components/ui/button'
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuLabel,
  DropdownMenuRadioGroup,
  DropdownMenuRadioItem,
  DropdownMenuSeparator,
  DropdownMenuShortcut,
  DropdownMenuTrigger,
} from '@/components/ui/dropdown-menu'
import {
  announceThemeModeChange,
  getStoredThemeMode,
  resolveThemeMode,
  setStoredThemeMode,
  subscribeToThemeModeChanges,
  syncThemeModeClass,
  type ThemeMode,
  type ResolvedThemeMode,
} from '@/lib/theme-utils'

const THEME_OPTIONS: Array<{
  value: ThemeMode
  label: string
  description: string
  icon: typeof Monitor
}> = [
  { value: 'auto', label: 'Auto', description: 'Follow the system theme', icon: Monitor },
  { value: 'light', label: 'Light', description: 'High-contrast daylight palette', icon: Sun },
  { value: 'dark', label: 'Dark', description: 'Low-glare analyst palette', icon: Moon },
]

const RESOLVED_LABEL: Record<ResolvedThemeMode, string> = {
  light: 'light system',
  dark: 'dark system',
}

function triggerLabel(mode: ThemeMode, resolvedMode: ResolvedThemeMode): string {
  if (mode === 'auto') return `Theme: Auto (${RESOLVED_LABEL[resolvedMode]})`
  return `Theme: ${mode[0].toUpperCase()}${mode.slice(1)}`
}

export function ThemeToggle() {
  const [themeState, setThemeState] = useState(() => {
    const mode = getStoredThemeMode()
    return { mode, resolvedMode: resolveThemeMode(mode) }
  })
  const { mode, resolvedMode } = themeState

  useEffect(() => {
    const sync = () => {
      const nextMode = getStoredThemeMode()
      const nextResolved = syncThemeModeClass(nextMode)
      setThemeState({ mode: nextMode, resolvedMode: nextResolved })
    }

    sync()
    return subscribeToThemeModeChanges(sync)
  }, [])

  const setMode = (nextMode: ThemeMode) => {
    setStoredThemeMode(nextMode)
    announceThemeModeChange()
  }

  const TriggerIcon = mode === 'auto'
    ? Monitor
    : resolvedMode === 'dark'
      ? Moon
      : Sun
  const ariaLabel = useMemo(() => triggerLabel(mode, resolvedMode), [mode, resolvedMode])

  return (
    <DropdownMenu>
      <DropdownMenuTrigger asChild>
        <Button
          variant="ghost"
          size="icon"
          className="h-8 w-8"
          aria-label={ariaLabel}
        >
          <TriggerIcon className="h-4 w-4" />
        </Button>
      </DropdownMenuTrigger>
      <DropdownMenuContent align="end" className="w-56">
        <DropdownMenuLabel>Theme</DropdownMenuLabel>
        <DropdownMenuSeparator />
        <DropdownMenuRadioGroup value={mode} onValueChange={(value) => setMode(value as ThemeMode)}>
          {THEME_OPTIONS.map(({ value, label, description, icon: Icon }) => (
            <DropdownMenuRadioItem key={value} value={value} className="items-start">
              <Icon className="mt-0.5 h-4 w-4" />
              <div className="flex min-w-0 flex-1 flex-col">
                <span className="flex items-center gap-1.5">
                  {label}
                  {mode === value ? <Check className="h-3.5 w-3.5 text-foreground" /> : null}
                </span>
                <span className="text-xs text-muted-foreground">{description}</span>
              </div>
              {value === 'auto' ? (
                <DropdownMenuShortcut>{resolvedMode}</DropdownMenuShortcut>
              ) : null}
            </DropdownMenuRadioItem>
          ))}
        </DropdownMenuRadioGroup>
      </DropdownMenuContent>
    </DropdownMenu>
  )
}
