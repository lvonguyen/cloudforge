import { useState, useCallback, useMemo, useEffect, useRef } from 'react'
import type { DeployEvent, DeployPhase, DeployPreviewConfig } from '@/types/deploy'
import { useChannel } from '@/hooks/useChannel'
import { apiClient } from '@/lib/api'

const SIMULATED_PHASES: { phase: DeployPhase; message: string; delay: number }[] = [
  { phase: 'planning', message: 'Initializing Terraform workspace...', delay: 800 },
  { phase: 'planning', message: 'terraform init -backend-config=...', delay: 600 },
  { phase: 'planning', message: 'Provider: hashicorp/aws v5.40.0', delay: 400 },
  { phase: 'creating', message: 'terraform apply -auto-approve', delay: 1000 },
  { phase: 'creating', message: 'Creating resources...', delay: 1200 },
  { phase: 'configuring', message: 'Applying tags and security groups...', delay: 800 },
  { phase: 'configuring', message: 'Configuring monitoring and alerts...', delay: 600 },
  { phase: 'verifying', message: 'Running post-deploy health checks...', delay: 1000 },
  { phase: 'verifying', message: 'All checks passed', delay: 500 },
  { phase: 'complete', message: 'Deploy preview complete (simulated)', delay: 0 },
]

export function useDeployPreview() {
  const [executionId, setExecutionId] = useState<string | null>(null)
  const [phase, setPhase] = useState<DeployPhase>('idle')
  const [isRunning, setIsRunning] = useState(false)
  const [countdown, setCountdown] = useState<number | null>(null)
  const [simEvents, setSimEvents] = useState<DeployEvent[]>([])
  const abortRef = useRef(false)

  const { events: envelopes, connected, error } = useChannel(
    executionId ? `deploy:${executionId}` : '',
    { enabled: !!executionId },
  )

  // Map Envelope[] -> DeployEvent[] (backward-compatible shape)
  const liveEvents = useMemo<DeployEvent[]>(() =>
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

  const events = executionId ? liveEvents : simEvents

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

  const runSimulated = useCallback(async () => {
    abortRef.current = false
    setSimEvents([])
    for (const step of SIMULATED_PHASES) {
      if (abortRef.current) break
      await new Promise(r => setTimeout(r, step.delay))
      if (abortRef.current) break
      const ts = new Date().toLocaleTimeString('en-US', { hour12: false, hour: '2-digit', minute: '2-digit', second: '2-digit' })
      setPhase(step.phase)
      setSimEvents(prev => [...prev, { timestamp: ts, phase: step.phase, message: step.message }])
    }
    if (!abortRef.current) {
      setIsRunning(false)
    }
  }, [])

  const run = useCallback(async (config: DeployPreviewConfig) => {
    setIsRunning(true)
    setPhase('planning')
    setCountdown(null)

    try {
      const res = await apiClient.post<{ execution_id: string }>('/deploy/preview', config)
      setExecutionId(res.execution_id)
    } catch {
      // API unavailable — run simulated deploy preview
      void runSimulated()
    }
  }, [runSimulated])

  const abort = useCallback(async () => {
    abortRef.current = true
    if (executionId) {
      try { await apiClient.post(`/deploy/preview/${executionId}/abort`, {}) } catch { /* ignore */ }
    }
    setIsRunning(false)
    setExecutionId(null)
  }, [executionId])

  const reset = useCallback(() => {
    abortRef.current = true
    setExecutionId(null)
    setPhase('idle')
    setIsRunning(false)
    setCountdown(null)
    setSimEvents([])
  }, [])

  return { events, phase, isRunning, countdown, connected, error, run, abort, reset }
}
