import { useState, useCallback, useMemo, useEffect } from 'react'
import type { DeployEvent, DeployPhase, DeployPreviewConfig } from '@/types/deploy'
import { useChannel } from '@/hooks/useChannel'
import { apiClient } from '@/lib/api'

export function useDeployPreview() {
  const [executionId, setExecutionId] = useState<string | null>(null)
  const [phase, setPhase] = useState<DeployPhase>('idle')
  const [isRunning, setIsRunning] = useState(false)
  const [countdown, setCountdown] = useState<number | null>(null)

  const { events: envelopes, connected, error } = useChannel(
    executionId ? `deploy:${executionId}` : '',
    { enabled: !!executionId },
  )

  // Map Envelope[] -> DeployEvent[] (backward-compatible shape)
  const events = useMemo<DeployEvent[]>(() =>
    envelopes.map(env => ({
      timestamp: new Date(env.ts).toLocaleTimeString('en-US', {
        hour12: false,
        hour: '2-digit',
        minute: '2-digit',
        second: '2-digit',
      }),
      phase: env.event as DeployPhase,
      message: (env.data as { message?: string })?.message ?? '',
      detail: (env.data as { detail?: string })?.detail,
    })),
    [envelopes],
  )

  // Derive phase + countdown from the latest envelope
  useEffect(() => {
    const last = envelopes[envelopes.length - 1]
    if (!last) return

    setPhase(last.event as DeployPhase)

    if (last.event === 'complete' || last.event === 'error') {
      setIsRunning(false)
    }

    const cd = (last.data as { countdown?: number })?.countdown
    if (cd != null) {
      setCountdown(cd)
    }
  }, [envelopes])

  const run = useCallback(async (config: DeployPreviewConfig) => {
    setIsRunning(true)
    setPhase('planning')
    setCountdown(null)

    const res = await apiClient.post<{ execution_id: string }>('/deploy/preview', config)
    setExecutionId(res.execution_id)
  }, [])

  const abort = useCallback(async () => {
    if (executionId) {
      await apiClient.post(`/deploy/preview/${executionId}/abort`, {})
    }
    setIsRunning(false)
    setExecutionId(null)
  }, [executionId])

  const reset = useCallback(() => {
    setExecutionId(null)
    setPhase('idle')
    setIsRunning(false)
    setCountdown(null)
  }, [])

  return { events, phase, isRunning, countdown, connected, error, run, abort, reset }
}
