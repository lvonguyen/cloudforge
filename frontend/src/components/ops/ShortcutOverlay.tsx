import { useEffect, useId, useRef } from 'react'
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
  const closeButtonRef = useRef<HTMLButtonElement>(null)
  const titleId = useId()

  const close = () => dispatch({ type: 'TOGGLE_SHORTCUT_OVERLAY' })

  useEffect(() => {
    closeButtonRef.current?.focus()
  }, [])

  return (
    <div
      className="fixed inset-0 z-50 flex items-center justify-center bg-black/60"
      onClick={close}
      onKeyDown={(event) => {
        if (event.key === 'Escape') {
          event.stopPropagation()
          close()
        }
      }}
      data-testid="shortcut-overlay"
    >
      <div
        role="dialog"
        aria-modal="true"
        aria-labelledby={titleId}
        tabIndex={-1}
        className="bg-[#0d0d14] border border-[#1e2330] w-80 shadow-2xl"
        onClick={(e) => e.stopPropagation()}
      >
        {/* Header */}
        <div className="flex items-center justify-between px-4 py-3 border-b border-[#1e2330]">
          <h2 id={titleId} className="text-xs font-semibold uppercase tracking-widest text-gray-400">
            Keyboard Shortcuts
          </h2>
          <button
            ref={closeButtonRef}
            type="button"
            onClick={close}
            className="text-gray-500 hover:text-gray-300 transition-colors"
            aria-label="Close shortcuts"
          >
            <X className="h-3.5 w-3.5" />
          </button>
        </div>

        {/* Shortcut list */}
        <ul className="px-4 py-3 space-y-2" aria-label="Command center keyboard shortcuts">
          {SHORTCUTS.map(({ key, description }) => (
            <li key={key} className="flex items-center justify-between text-xs">
              <kbd className="bg-[#161b22] border border-[#1e2330] text-gray-300 px-2 py-0.5 font-mono text-[10px] min-w-[28px] text-center">
                {key}
              </kbd>
              <span className="text-gray-500">{description}</span>
            </li>
          ))}
        </ul>
      </div>
    </div>
  )
}
