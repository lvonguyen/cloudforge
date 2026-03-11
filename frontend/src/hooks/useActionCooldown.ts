import { useState, useEffect, useCallback, useRef } from 'react'

interface CooldownConfig {
  key: string
  cooldownMs: number
  maxRetries?: number
  backoffMultiplier?: number
}

interface CooldownState {
  canFire: boolean
  remainingMs: number
  fire: () => void
  reset: () => void
}

const timestamps = new Map<string, number>()
const retryCounts = new Map<string, number>()

export function useActionCooldown(config: CooldownConfig): CooldownState {
  const { key, cooldownMs, maxRetries, backoffMultiplier = 2 } = config
  const configRef = useRef(config)
  configRef.current = config

  const getEffectiveCooldown = useCallback((): number => {
    if (maxRetries === undefined) return cooldownMs
    const retries = retryCounts.get(key) ?? 0
    return cooldownMs * Math.pow(backoffMultiplier, retries)
  }, [key, cooldownMs, maxRetries, backoffMultiplier])

  const calcRemaining = useCallback((): number => {
    const last = timestamps.get(key)
    if (last === undefined) return 0
    const elapsed = Date.now() - last
    const effective = getEffectiveCooldown()
    return Math.max(0, effective - elapsed)
  }, [key, getEffectiveCooldown])

  const [remainingMs, setRemainingMs] = useState<number>(() => calcRemaining())

  const fire = useCallback(() => {
    const remaining = calcRemaining()
    if (remaining > 0) return

    timestamps.set(key, Date.now())
    if (maxRetries !== undefined) {
      const current = retryCounts.get(key) ?? 0
      retryCounts.set(key, Math.min(current + 1, maxRetries))
    }
    setRemainingMs(getEffectiveCooldown())
  }, [key, maxRetries, calcRemaining, getEffectiveCooldown])

  const reset = useCallback(() => {
    timestamps.delete(key)
    retryCounts.delete(key)
    setRemainingMs(0)
  }, [key])

  useEffect(() => {
    const r = calcRemaining()
    setRemainingMs(r)

    if (r <= 0) return

    // Single timeout fires exactly when cooldown expires — no polling
    const id = setTimeout(() => setRemainingMs(0), r)
    return () => clearTimeout(id)
  }, [calcRemaining])

  return {
    canFire: remainingMs <= 0,
    remainingMs,
    fire,
    reset,
  }
}
