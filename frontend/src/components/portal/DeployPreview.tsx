import { useEffect } from 'react'
import { Button } from '@/components/ui/button'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
import { Badge } from '@/components/ui/badge'
import { TerminalOutput } from './TerminalOutput'
import { useDeployPreview } from '@/hooks/useDeployPreview'
import { generatePlan } from '@/lib/plan-templates'
import type { DeployPreviewConfig, DeployPhase } from '@/types/deploy'
import { Play, Square, RotateCcw } from 'lucide-react'

const PHASE_LABELS: Record<DeployPhase, { label: string; color: string }> = {
  idle: { label: 'IDLE', color: 'bg-gray-100 text-gray-700 dark:bg-gray-900/30 dark:text-gray-300' },
  planning: { label: 'PLANNING', color: 'bg-blue-100 text-blue-700 dark:bg-blue-900/30 dark:text-blue-300' },
  creating: { label: 'CREATING', color: 'bg-yellow-100 text-yellow-700 dark:bg-yellow-900/30 dark:text-yellow-300' },
  configuring: { label: 'CONFIGURING', color: 'bg-cyan-100 text-cyan-700 dark:bg-cyan-900/30 dark:text-cyan-300' },
  verifying: { label: 'VERIFYING', color: 'bg-indigo-100 text-indigo-700 dark:bg-indigo-900/30 dark:text-indigo-300' },
  live: { label: 'LIVE', color: 'bg-green-100 text-green-700 dark:bg-green-900/30 dark:text-green-300' },
  teardown: { label: 'TEARDOWN', color: 'bg-orange-100 text-orange-700 dark:bg-orange-900/30 dark:text-orange-300' },
  complete: { label: 'COMPLETE', color: 'bg-green-100 text-green-700 dark:bg-green-900/30 dark:text-green-300' },
  error: { label: 'ERROR', color: 'bg-red-100 text-red-700 dark:bg-red-900/30 dark:text-red-300' },
}

export function DeployPreview({ config }: { config: DeployPreviewConfig }) {
  const { events, phase, isRunning, countdown, run, abort, reset } = useDeployPreview()
  const plan = generatePlan(config)
  const resources = plan.planned_values.root_module.resources
  const phaseInfo = PHASE_LABELS[phase]

  useEffect(() => {
    return () => { abort() }
  }, [abort])

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <div>
          <h2 className="text-sm font-semibold">Deploy Preview</h2>
          <p className="text-xs text-muted-foreground mt-0.5">
            {config.resourceType === 's3'
              ? 'Live S3 bucket creation with auto-teardown after 60s'
              : `Simulated ${config.resourceType.toUpperCase()} deployment (plan-only)`}
          </p>
        </div>
        <div className="flex items-center gap-2">
          <Badge variant="secondary" className={`text-[10px] ${phaseInfo.color}`}>
            {phaseInfo.label}
          </Badge>
          {countdown !== null && (
            <Badge variant="outline" className="text-[10px] font-mono tabular-nums">
              {countdown}s
            </Badge>
          )}
        </div>
      </div>

      {/* Plan summary */}
      <Card>
        <CardHeader className="pb-2">
          <CardTitle className="text-xs font-medium uppercase tracking-wide text-muted-foreground">
            Terraform Plan Summary
          </CardTitle>
        </CardHeader>
        <CardContent className="space-y-2">
          <div className="flex items-center gap-4 text-xs">
            <span className="text-green-600 dark:text-green-400 font-mono font-medium">
              +{resources.length} to create
            </span>
            <span className="text-muted-foreground font-mono">0 to change</span>
            <span className="text-muted-foreground font-mono">0 to destroy</span>
          </div>
          <div className="space-y-1">
            {resources.map(r => (
              <div key={r.address} className="flex items-center gap-2 text-xs">
                <span className="text-green-600 dark:text-green-400 font-mono">+</span>
                <span className="font-mono text-muted-foreground">{r.type}</span>
                <span className="font-mono font-medium">{r.name}</span>
              </div>
            ))}
          </div>
        </CardContent>
      </Card>

      {/* Terminal */}
      <TerminalOutput events={events} isRunning={isRunning} />

      {/* Controls */}
      <div className="flex items-center gap-2">
        {phase === 'idle' && (
          <Button size="sm" className="text-xs gap-1.5" onClick={() => run(config)}>
            <Play className="h-3.5 w-3.5" />
            Run Deploy Preview
          </Button>
        )}
        {isRunning && (
          <Button size="sm" variant="destructive" className="text-xs gap-1.5" onClick={abort}>
            <Square className="h-3.5 w-3.5" />
            Stop
          </Button>
        )}
        {phase === 'complete' && (
          <Button size="sm" variant="outline" className="text-xs gap-1.5" onClick={reset}>
            <RotateCcw className="h-3.5 w-3.5" />
            Reset
          </Button>
        )}
        {config.resourceType !== 's3' && phase === 'idle' && (
          <span className="text-[10px] text-muted-foreground ml-2">
            Plan-only: no real cloud resources will be created
          </span>
        )}
        {config.resourceType === 's3' && phase === 'idle' && (
          <span className="text-[10px] text-muted-foreground ml-2">
            Live: creates a real S3 bucket that auto-deletes in 60s
          </span>
        )}
      </div>
    </div>
  )
}
