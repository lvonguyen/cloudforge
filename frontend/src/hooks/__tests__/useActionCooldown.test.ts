import { describe, it, expect, beforeEach, vi, afterEach } from 'vitest'
import { renderHook, act } from '@testing-library/react'
import { useActionCooldown } from '../useActionCooldown'

// Each test uses a unique key to avoid cross-test state pollution from the module-level Maps
let keyCounter = 0
function uniqueKey(): string {
  return `test-cooldown-${++keyCounter}`
}

beforeEach(() => {
  vi.useFakeTimers()
})

afterEach(() => {
  vi.useRealTimers()
})

describe('useActionCooldown', () => {
  it('starts in a fireable state (canFire=true, remainingMs=0)', () => {
    const { result } = renderHook(() =>
      useActionCooldown({ key: uniqueKey(), cooldownMs: 1000 })
    )
    expect(result.current.canFire).toBe(true)
    expect(result.current.remainingMs).toBe(0)
  })

  it('enters cooldown after fire() is called', () => {
    const key = uniqueKey()
    const { result } = renderHook(() =>
      useActionCooldown({ key, cooldownMs: 1000 })
    )

    act(() => {
      result.current.fire()
    })

    expect(result.current.canFire).toBe(false)
    expect(result.current.remainingMs).toBeGreaterThan(0)
  })

  it('exits cooldown after the cooldown period elapses', () => {
    const key = uniqueKey()
    const { result } = renderHook(() =>
      useActionCooldown({ key, cooldownMs: 1000 })
    )

    act(() => {
      result.current.fire()
    })

    expect(result.current.canFire).toBe(false)

    // Advance past the full cooldown
    act(() => {
      vi.advanceTimersByTime(1100)
    })

    expect(result.current.canFire).toBe(true)
    expect(result.current.remainingMs).toBe(0)
  })

  it('reset() immediately clears the cooldown', () => {
    const key = uniqueKey()
    const { result } = renderHook(() =>
      useActionCooldown({ key, cooldownMs: 5000 })
    )

    act(() => {
      result.current.fire()
    })
    expect(result.current.canFire).toBe(false)

    act(() => {
      result.current.reset()
    })
    expect(result.current.canFire).toBe(true)
    expect(result.current.remainingMs).toBe(0)
  })

  it('fire() is a no-op while still in cooldown', () => {
    const key = uniqueKey()
    const { result } = renderHook(() =>
      useActionCooldown({ key, cooldownMs: 2000 })
    )

    act(() => {
      result.current.fire()
    })
    expect(result.current.canFire).toBe(false)

    act(() => {
      vi.advanceTimersByTime(500)
    })

    act(() => {
      result.current.fire() // should be blocked
    })

    // Still in cooldown — fire() didn't reset it
    expect(result.current.canFire).toBe(false)
    expect(result.current.remainingMs).toBeGreaterThan(0)
  })
})
