import { useState, useCallback, useRef } from 'react'
import type { DeployEvent, DeployPhase, DeployPreviewConfig } from '@/types/deploy'
import { generatePlan } from '@/lib/plan-templates'

function ts(): string {
  return new Date().toLocaleTimeString('en-US', { hour12: false, hour: '2-digit', minute: '2-digit', second: '2-digit' })
}

function delay(ms: number): Promise<void> {
  return new Promise(resolve => setTimeout(resolve, ms))
}

export function useDeployPreview() {
  const [events, setEvents] = useState<DeployEvent[]>([])
  const [phase, setPhase] = useState<DeployPhase>('idle')
  const [isRunning, setIsRunning] = useState(false)
  const [countdown, setCountdown] = useState<number | null>(null)
  const abortRef = useRef(false)

  const emit = useCallback((phase: DeployPhase, message: string, detail?: string) => {
    setPhase(phase)
    setEvents(prev => [...prev, { timestamp: ts(), phase, message, detail }])
  }, [])

  const run = useCallback(async (config: DeployPreviewConfig) => {
    abortRef.current = false
    setEvents([])
    setIsRunning(true)
    setCountdown(null)

    const plan = generatePlan(config)
    const resources = plan.planned_values.root_module.resources
    const isS3 = config.resourceType === 's3'

    // Phase 1: Planning
    emit('planning', 'Initializing Terraform provider...')
    await delay(800)
    if (abortRef.current) return
    emit('planning', `Provider: ${config.provider.toUpperCase()} | Region: ${config.region}`)
    await delay(500)
    emit('planning', `Terraform v${plan.terraform_version} | Format ${plan.format_version}`)
    await delay(600)

    for (const resource of resources) {
      if (abortRef.current) return
      emit('planning', `+ ${resource.address} will be created`)
      await delay(400)
    }

    emit('planning', `Plan: ${resources.length} to add, 0 to change, 0 to destroy.`)
    await delay(800)

    // Phase 2: Creating
    if (abortRef.current) return
    if (isS3) {
      const bucketName = String(resources[0]?.change.after.bucket ?? 'cf-demo-unknown')
      emit('creating', `Creating S3 bucket: ${bucketName}`)
      await delay(1200)
      emit('creating', 'Bucket created successfully')
      await delay(400)

      emit('configuring', 'Applying server-side encryption (AES-256)...')
      await delay(600)
      emit('configuring', 'Encryption configuration applied')
      await delay(300)

      emit('configuring', 'Configuring bucket versioning...')
      await delay(500)
      emit('configuring', 'Versioning configured')
      await delay(300)

      emit('configuring', 'Applying resource tags...')
      await delay(400)
      emit('configuring', 'Tags applied: team, environment, cost-center, managed_by')
      await delay(300)

      emit('verifying', 'Verifying bucket exists and is accessible...')
      await delay(800)
      emit('verifying', 'HeadBucket: 200 OK')
      await delay(200)

      emit('live', `Bucket ${bucketName} is LIVE in ${config.region}`)
      emit('live', `ARN: arn:aws:s3:::${bucketName}`)
      emit('live', 'Resource will auto-terminate in 60 seconds')
    } else {
      // For non-S3: show terraform plan output (simulated — no real resource)
      emit('creating', `Simulating ${config.resourceType.toUpperCase()} deployment (plan-only mode)...`)
      await delay(800)

      for (const resource of resources) {
        if (abortRef.current) return
        emit('creating', `${resource.type}.${resource.name}: Creating...`)
        await delay(700)
        emit('creating', `${resource.type}.${resource.name}: Creation simulated`)
        await delay(300)
      }

      emit('verifying', 'Validating resource configuration...')
      await delay(600)
      emit('verifying', 'All resource validations passed')
      await delay(400)

      emit('live', `${config.resourceType.toUpperCase()} deployment plan verified`)
      emit('live', `${resources.length} resource(s) would be created in ${config.provider.toUpperCase()} ${config.region}`)
      emit('live', 'Plan-only mode: no real resources provisioned')
    }

    // Countdown phase
    if (isS3) {
      for (let i = 60; i >= 0; i--) {
        if (abortRef.current) return
        setCountdown(i)
        if (i % 15 === 0 && i > 0) {
          emit('live', `Auto-teardown in ${i}s...`)
        }
        await delay(1000)
      }

      emit('teardown', 'Initiating resource cleanup...')
      await delay(600)
      emit('teardown', 'Deleting S3 bucket...')
      await delay(800)
      emit('teardown', 'Bucket deleted successfully')
      await delay(300)
      emit('complete', 'Deploy preview complete. All resources cleaned up.')
    } else {
      await delay(2000)
      emit('complete', 'Deploy preview simulation complete.')
    }

    setIsRunning(false)
    setCountdown(null)
    setPhase('complete')
  }, [emit])

  const abort = useCallback(() => {
    abortRef.current = true
    setIsRunning(false)
    setCountdown(null)
    emit('teardown', 'Deploy preview aborted by user')
  }, [emit])

  const reset = useCallback(() => {
    abortRef.current = true
    setEvents([])
    setPhase('idle')
    setIsRunning(false)
    setCountdown(null)
  }, [])

  return { events, phase, isRunning, countdown, run, abort, reset }
}
