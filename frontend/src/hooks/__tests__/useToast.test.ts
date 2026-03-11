import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest'
import { renderHook, act } from '@testing-library/react'
import { useToast } from '@/hooks/useToast'

beforeEach(() => {
  vi.useFakeTimers()
})

afterEach(() => {
  vi.useRealTimers()
})

describe('useToast', () => {
  it('starts with no toasts', () => {
    const { result } = renderHook(() => useToast())
    expect(result.current.toasts).toHaveLength(0)
  })

  it('adds a toast when toast() is called', () => {
    const { result } = renderHook(() => useToast())

    act(() => { result.current.toast('Hello world') })

    expect(result.current.toasts).toHaveLength(1)
    expect(result.current.toasts[0].message).toBe('Hello world')
    expect(result.current.toasts[0].variant).toBe('success')
  })

  it('defaults variant to success when not specified', () => {
    const { result } = renderHook(() => useToast())
    act(() => { result.current.toast('A message') })
    expect(result.current.toasts[0].variant).toBe('success')
  })

  it('respects explicit variant values', () => {
    const { result } = renderHook(() => useToast())

    act(() => { result.current.toast('Error msg', 'error') })
    expect(result.current.toasts[0].variant).toBe('error')

    act(() => { result.current.toast('Info msg', 'info') })
    expect(result.current.toasts[1].variant).toBe('info')
  })

  it('assigns a unique id to each toast', () => {
    const { result } = renderHook(() => useToast())

    act(() => {
      result.current.toast('First')
      result.current.toast('Second')
    })

    const ids = result.current.toasts.map(t => t.id)
    expect(new Set(ids).size).toBe(2)
  })

  it('stacks multiple toasts', () => {
    const { result } = renderHook(() => useToast())

    act(() => {
      result.current.toast('First')
      result.current.toast('Second')
      result.current.toast('Third')
    })

    expect(result.current.toasts).toHaveLength(3)
  })

  it('dismiss() removes the toast with the given id', () => {
    const { result } = renderHook(() => useToast())

    act(() => { result.current.toast('To remove') })
    const id = result.current.toasts[0].id

    act(() => { result.current.dismiss(id) })

    expect(result.current.toasts).toHaveLength(0)
  })

  it('dismiss() ignores unknown ids gracefully', () => {
    const { result } = renderHook(() => useToast())

    act(() => { result.current.toast('Keep me') })

    // Dismissing a non-existent id should not throw or remove others
    act(() => { result.current.dismiss('nonexistent-id') })

    expect(result.current.toasts).toHaveLength(1)
  })

  it('auto-dismisses toast after 4000ms', () => {
    const { result } = renderHook(() => useToast())

    act(() => { result.current.toast('Auto gone') })
    expect(result.current.toasts).toHaveLength(1)

    act(() => { vi.advanceTimersByTime(4000) })

    expect(result.current.toasts).toHaveLength(0)
  })

  it('toast remains before the 4000ms auto-dismiss window', () => {
    const { result } = renderHook(() => useToast())

    act(() => { result.current.toast('Still here') })
    act(() => { vi.advanceTimersByTime(3999) })

    expect(result.current.toasts).toHaveLength(1)
  })
})
