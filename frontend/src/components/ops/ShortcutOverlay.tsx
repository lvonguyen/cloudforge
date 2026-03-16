import { X } from 'lucide-react'
import { useCommandCenter } from '@/contexts/CommandCenterContext'

const SHORTCUTS = [
  { key: 'Esc', description: 'Close overlay / deselect entity' },
  { key: 'L', description: 'Toggle left panel' },
  { key: 'D', description: 'Close detail panel' },
  { key: '1', description: 'Charts view' },
  { key: '2', description: 'Heatmap view' },
  { key: '?', description: 'Toggle this overlay' },
] as const

export function ShortcutOverlay() {
  const { dispatch } = useCommandCenter()

  const close = () => dispatch({ type: 'TOGGLE_SHORTCUT_OVERLAY' })

  return (
    <div
      className="fixed inset-0 z-50 flex items-center justify-center bg-black/60"
      onClick={close}
      data-testid="shortcut-overlay"
    >
      <div
        className="bg-[#0d0d14] border border-[#1e2330] w-80 shadow-2xl"
        onClick={(e) => e.stopPropagation()}
      >
        {/* Header */}
        <div className="flex items-center justify-between px-4 py-3 border-b border-[#1e2330]">
          <span className="text-xs font-semibold uppercase tracking-widest text-gray-400">
            Keyboard Shortcuts
          </span>
          <button
            onClick={close}
            className="text-gray-500 hover:text-gray-300 transition-colors"
            aria-label="Close shortcuts"
          >
            <X className="h-3.5 w-3.5" />
          </button>
        </div>

        {/* Shortcut list */}
        <div className="px-4 py-3 space-y-2">
          {SHORTCUTS.map(({ key, description }) => (
            <div key={key} className="flex items-center justify-between text-xs">
              <kbd className="bg-[#161b22] border border-[#1e2330] text-gray-300 px-2 py-0.5 font-mono text-[10px] min-w-[28px] text-center">
                {key}
              </kbd>
              <span className="text-gray-500">{description}</span>
            </div>
          ))}
        </div>
      </div>
    </div>
  )
}
