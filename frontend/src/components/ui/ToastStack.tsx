import type { Toast } from '@/hooks/useToast'

interface ToastStackProps {
  toasts: Toast[]
  onDismiss: (id: string) => void
}

const VARIANT_CLASSES: Record<Toast['variant'], string> = {
  success: 'bg-green-900/90 border-green-700 text-green-100',
  error: 'bg-red-900/90 border-red-700 text-red-100',
  info: 'bg-zinc-800/95 border-zinc-600 text-zinc-100',
}

export function ToastStack({ toasts, onDismiss }: ToastStackProps) {
  if (toasts.length === 0) return null

  return (
    <div
      className="fixed bottom-4 right-4 z-50 flex flex-col gap-2 pointer-events-none"
      aria-live="polite"
      aria-atomic="false"
    >
      {toasts.map(t => (
        <div
          key={t.id}
          className={`flex items-center gap-3 rounded-none border px-4 py-2.5 text-sm font-medium shadow-lg pointer-events-auto min-w-[240px] max-w-sm ${VARIANT_CLASSES[t.variant]}`}
          role="alert"
        >
          <span className="flex-1">{t.message}</span>
          <button
            type="button"
            aria-label="Dismiss"
            className="shrink-0 opacity-70 hover:opacity-100 transition-opacity text-xs"
            onClick={() => onDismiss(t.id)}
          >
            x
          </button>
        </div>
      ))}
    </div>
  )
}
