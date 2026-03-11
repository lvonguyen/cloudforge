import { useState, useCallback, useRef } from 'react'

export type ToastVariant = 'success' | 'error' | 'info'

export interface Toast {
  id: string
  message: string
  variant: ToastVariant
}

export function useToast() {
  const [toasts, setToasts] = useState<Toast[]>([])
  const timerRefs = useRef<Map<string, ReturnType<typeof setTimeout>>>(new Map())

  const dismiss = useCallback((id: string) => {
    const timer = timerRefs.current.get(id)
    if (timer !== undefined) {
      clearTimeout(timer)
      timerRefs.current.delete(id)
    }
    setToasts(prev => prev.filter(t => t.id !== id))
  }, [])

  const toast = useCallback((message: string, variant: ToastVariant = 'success') => {
    const id = `${Date.now()}-${Math.random().toString(36).slice(2, 7)}`
    setToasts(prev => [...prev, { id, message, variant }])
    const timer = setTimeout(() => dismiss(id), 4000)
    timerRefs.current.set(id, timer)
  }, [dismiss])

  return { toasts, toast, dismiss }
}
