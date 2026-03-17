import { useState } from 'react'
import { Button } from '@/components/ui/button'
import { Badge } from '@/components/ui/badge'
import { LayoutGrid, ChevronDown } from 'lucide-react'
import { WIDGET_PRESETS, loadDashboardLayout, saveDashboardLayout } from '@/types/dashboard'
import type { WidgetId } from '@/types/dashboard'

interface LayoutSwitcherProps {
  currentLayout: WidgetId[]
  onLayoutChange: (layout: WidgetId[]) => void
}

export function LayoutSwitcher({ currentLayout, onLayoutChange }: LayoutSwitcherProps) {
  const [open, setOpen] = useState(false)

  const activePreset = WIDGET_PRESETS.find(
    p => JSON.stringify(p.widgets) === JSON.stringify(currentLayout)
  )

  function applyPreset(widgets: WidgetId[]) {
    saveDashboardLayout(widgets)
    onLayoutChange(widgets)
    setOpen(false)
  }

  return (
    <div className="relative">
      <Button
        variant="outline"
        size="sm"
        className="text-xs gap-1.5 h-7"
        onClick={() => setOpen(v => !v)}
      >
        <LayoutGrid className="h-3 w-3" />
        {activePreset?.label ?? 'Custom Layout'}
        <ChevronDown className="h-3 w-3" />
      </Button>

      {open && (
        <>
          <div className="fixed inset-0 z-40" onClick={() => setOpen(false)} />
          <div className="absolute right-0 top-full mt-1 z-50 w-64 bg-background border border-border shadow-lg">
            {WIDGET_PRESETS.map(preset => (
              <button
                key={preset.id}
                className="w-full text-left px-3 py-2.5 hover:bg-muted/50 transition-colors border-b border-border last:border-b-0"
                onClick={() => applyPreset(preset.widgets)}
              >
                <div className="flex items-center justify-between">
                  <span className="text-xs font-medium">{preset.label}</span>
                  {activePreset?.id === preset.id && (
                    <Badge variant="secondary" className="text-[9px] px-1.5 py-0">Active</Badge>
                  )}
                </div>
                <p className="text-[10px] text-muted-foreground mt-0.5">{preset.description}</p>
              </button>
            ))}
          </div>
        </>
      )}
    </div>
  )
}

/** Load persisted layout or return default (security focus). */
export function useInitialLayout(): WidgetId[] {
  return loadDashboardLayout() ?? WIDGET_PRESETS[0].widgets
}
