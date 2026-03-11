import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest'
import { renderHook, act } from '@testing-library/react'
import { useDebounce } from '@/hooks/useDebounce'

beforeEach(() => {
  vi.useFakeTimers()
})

afterEach(() => {
  vi.useRealTimers()
})

describe('useDebounce', () => {
  it('returns the initial value immediately without waiting', () => {
    const { result } = renderHook(() => useDebounce('initial', 300))
    expect(result.current).toBe('initial')
  })

  it('does not update value before the delay elapses', () => {
    const { result, rerender } = renderHook(
      ({ value, delay }) => useDebounce(value, delay),
      { initialProps: { value: 'first', delay: 300 } }
    )

    rerender({ value: 'second', delay: 300 })
    act(() => { vi.advanceTimersByTime(200) })

    expect(result.current).toBe('first')
  })

  it('updates to new value after the delay elapses', () => {
    const { result, rerender } = renderHook(
      ({ value, delay }) => useDebounce(value, delay),
      { initialProps: { value: 'first', delay: 300 } }
    )

    rerender({ value: 'second', delay: 300 })
    act(() => { vi.advanceTimersByTime(300) })

    expect(result.current).toBe('second')
  })

  it('resets the timer on rapid value changes (only last value committed)', () => {
    const { result, rerender } = renderHook(
      ({ value, delay }) => useDebounce(value, delay),
      { initialProps: { value: 'a', delay: 300 } }
    )

    rerender({ value: 'b', delay: 300 })
    act(() => { vi.advanceTimersByTime(100) })

    rerender({ value: 'c', delay: 300 })
    act(() => { vi.advanceTimersByTime(100) })

    // Only 200ms since 'c' was set; still debouncing
    expect(result.current).toBe('a')

    act(() => { vi.advanceTimersByTime(300) })
    expect(result.current).toBe('c')
  })

  it('respects a custom delay value', () => {
    const { result, rerender } = renderHook(
      ({ value, delay }) => useDebounce(value, delay),
      { initialProps: { value: 'x', delay: 1000 } }
    )

    rerender({ value: 'y', delay: 1000 })
    act(() => { vi.advanceTimersByTime(999) })
    expect(result.current).toBe('x')

    act(() => { vi.advanceTimersByTime(1) })
    expect(result.current).toBe('y')
  })

  it('works with numeric values', () => {
    const { result, rerender } = renderHook(
      ({ value, delay }) => useDebounce(value, delay),
      { initialProps: { value: 0, delay: 200 } }
    )

    rerender({ value: 42, delay: 200 })
    act(() => { vi.advanceTimersByTime(200) })
    expect(result.current).toBe(42)
  })
})
