import { useMemo, useState } from 'react'
import { AlertTriangle, ChevronRight, ExternalLink, KeyRound, RotateCcw, ShieldCheck, Wrench } from 'lucide-react'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import {
  Sheet,
  SheetContent,
  SheetDescription,
  SheetFooter,
  SheetHeader,
  SheetTitle,
} from '@/components/ui/sheet'
import { RemediationTierBadge } from '@/components/remediation/RemediationTierBadge'
import { useExecuteRemediation, usePatchRemediation } from '@/hooks/useRemediations'
import { useTracePanel } from '@/lib/trace-panel-context'
import { useToast } from '@/hooks/useToast'
import { impactBadgeClass, type RemediationCandidate } from '@/lib/remediation-catalog'
import type { Finding } from '@/types/compliance'
import type { AttackPath, AttackPathNode } from '@/types/attack-path'
import type { RemediationRecord } from '@/types/remediation'

export type DrawerContext =
  | { mode: 'preview'; finding: Finding; candidate: RemediationCandidate }
  | { mode: 'approve'; remediation: RemediationRecord; candidate: RemediationCandidate }
  | { mode: 'hop'; node: AttackPathNode; path?: AttackPath; candidates: RemediationCandidate[] }

interface RemediationActionDrawerProps {
  open: boolean
  onOpenChange: (open: boolean) => void
  context: DrawerContext | null
}

const MODE_TITLES: Record<DrawerContext['mode'], string> = {
  preview: 'Stage remediation',
  approve: 'Approve staged remediation',
  hop: 'Break this attack-path hop',
}

const MODE_SUBTITLES: Record<DrawerContext['mode'], string> = {
  preview: 'Preview the dry-run-equivalent action before staging.',
  approve: 'Already-staged action awaiting approval. Reversibility window applies.',
  hop: 'Pick one remediation to break this specific hop.',
}

export function RemediationActionDrawer({ open, onOpenChange, context }: RemediationActionDrawerProps) {
  const executeMutation = useExecuteRemediation()
  const patchMutation = usePatchRemediation()
  const { openDryRun } = useTracePanel()
  const { toast } = useToast()
  const [selectedHopIdx, setSelectedHopIdx] = useState<number>(0)

  const activeCandidate = useMemo<RemediationCandidate | null>(() => {
    if (!context) return null
    if (context.mode === 'hop') {
      const clampedIdx = Math.min(selectedHopIdx, Math.max(context.candidates.length - 1, 0))
      return context.candidates[clampedIdx] ?? null
    }
    return context.candidate
  }, [context, selectedHopIdx])

  if (!context) {
    return (
      <Sheet open={open} onOpenChange={onOpenChange}>
        <SheetContent side="right" className="w-full sm:max-w-lg flex flex-col p-0" />
      </Sheet>
    )
  }

  const findingIdForTrace =
    context.mode === 'preview' ? context.finding.id
      : context.mode === 'approve' ? context.remediation.finding_id
        : context.node.finding_id

  function handleDryRun() {
    if (!activeCandidate) return
    openDryRun(`Dry run: ${activeCandidate.handler}`, {
      finding_id: findingIdForTrace,
      would_succeed: true,
      planned_actions: activeCandidate.plannedActions,
      prerequisites_met: !(activeCandidate.prerequisites?.length),
      warnings: activeCandidate.warnings,
      estimated_impact: `${activeCandidate.estimatedImpact} — scoped to ${activeCandidate.target}`,
      rollback_plan: activeCandidate.rollbackPlan,
      estimated_rollback_window: activeCandidate.estimatedRollbackWindow,
    })
    toast('Dry-run dispatched to trace panel', 'info')
  }

  function handlePrimary() {
    if (!context || !activeCandidate) return
    if (context.mode === 'approve') {
      executeMutation.mutate(context.remediation.id, {
        onSuccess: () => {
          toast('Remediation approved — executing', 'success')
          onOpenChange(false)
        },
      })
      return
    }
    if (context.mode === 'preview') {
      toast(`Staged: ${activeCandidate.handler} on ${activeCandidate.target}`, 'success')
      onOpenChange(false)
      return
    }
    toast(`Hop break staged: ${activeCandidate.handler} on ${activeCandidate.target}`, 'success')
    onOpenChange(false)
  }

  function handleReject() {
    if (context?.mode !== 'approve') return
    patchMutation.mutate(
      { id: context.remediation.id, status: 'skipped' },
      {
        onSuccess: () => {
          toast('Remediation rejected', 'info')
          onOpenChange(false)
        },
      },
    )
  }

  const isManualTier3 = activeCandidate?.handler === 'manual-escalation'
  const asanaUrl = context.mode === 'approve' ? context.remediation.asana_task_url : undefined

  return (
    <Sheet open={open} onOpenChange={onOpenChange}>
      <SheetContent side="right" className="w-full sm:max-w-lg flex flex-col p-0">
        <SheetHeader className="border-b border-border">
          <SheetTitle className="flex items-center gap-2 text-base">
            <Wrench className="h-4 w-4" />
            {MODE_TITLES[context.mode]}
          </SheetTitle>
          <SheetDescription>{MODE_SUBTITLES[context.mode]}</SheetDescription>
        </SheetHeader>

        <div className="flex-1 overflow-y-auto p-4 space-y-4">
          {context.mode === 'hop' && context.candidates.length > 1 ? (
            <HopCandidatePicker
              candidates={context.candidates}
              selectedIdx={selectedHopIdx}
              onSelect={setSelectedHopIdx}
            />
          ) : null}

          {activeCandidate ? (
            <>
              <CandidateOverview candidate={activeCandidate} />
              {activeCandidate.prerequisites?.length ? (
                <PrerequisitesCard prerequisites={activeCandidate.prerequisites} />
              ) : null}
              {activeCandidate.warnings?.length ? (
                <WarningsCard warnings={activeCandidate.warnings} />
              ) : null}
              <PermissionsCard permissions={activeCandidate.permissions} />
              <PlannedActionsCard actions={activeCandidate.plannedActions} />
              <RollbackCard
                actions={activeCandidate.rollbackPlan}
                window={activeCandidate.estimatedRollbackWindow}
                reversible={activeCandidate.reversible}
              />
            </>
          ) : null}
        </div>

        <SheetFooter className="border-t border-border flex-row justify-end gap-2 p-3">
          {context.mode === 'preview' && (
            <>
              <Button variant="outline" size="sm" onClick={() => onOpenChange(false)}>
                Cancel
              </Button>
              <Button variant="outline" size="sm" onClick={handleDryRun}>
                Dry-run
              </Button>
              <Button size="sm" onClick={handlePrimary}>
                {isManualTier3 ? 'Open ticket' : 'Stage & execute'}
              </Button>
            </>
          )}
          {context.mode === 'approve' && (
            <>
              <Button variant="outline" size="sm" onClick={handleReject} disabled={patchMutation.isPending}>
                Reject
              </Button>
              {isManualTier3 && asanaUrl ? (
                <Button size="sm" asChild>
                  <a href={asanaUrl} target="_blank" rel="noreferrer" className="inline-flex items-center gap-1.5">
                    Open ticket <ExternalLink className="h-3.5 w-3.5" />
                  </a>
                </Button>
              ) : (
                <Button size="sm" onClick={handlePrimary} disabled={executeMutation.isPending}>
                  {executeMutation.isPending ? 'Executing…' : 'Approve & execute'}
                </Button>
              )}
            </>
          )}
          {context.mode === 'hop' && (
            <>
              <Button variant="outline" size="sm" onClick={() => onOpenChange(false)}>
                Cancel
              </Button>
              <Button size="sm" onClick={handlePrimary} disabled={!activeCandidate}>
                Stage selected
              </Button>
            </>
          )}
        </SheetFooter>
      </SheetContent>
    </Sheet>
  )
}

function CandidateOverview({ candidate }: { candidate: RemediationCandidate }) {
  return (
    <section className="rounded-md border border-border p-3 space-y-3">
      <div className="flex items-center gap-2 flex-wrap">
        <RemediationTierBadge tier={candidate.tier} />
        <Badge variant="outline" className={impactBadgeClass(candidate.estimatedImpact)}>
          {candidate.estimatedImpact} impact
        </Badge>
        <Badge
          variant="outline"
          className={
            candidate.reversible
              ? 'bg-blue-50 text-blue-700 border-blue-200 dark:bg-blue-950/30 dark:text-blue-300 dark:border-blue-900/40'
              : 'bg-zinc-100 text-zinc-700 border-zinc-200 dark:bg-zinc-900/30 dark:text-zinc-300 dark:border-zinc-700'
          }
        >
          {candidate.reversible ? 'reversible' : 'no SDK rollback'}
        </Badge>
      </div>
      <div>
        <p className="text-sm font-medium leading-snug">{candidate.label}</p>
        <p className="text-xs text-muted-foreground font-mono mt-0.5 break-all">{candidate.target}</p>
      </div>
      <p className="text-[11px] text-muted-foreground">
        Handler: <code className="font-mono">{candidate.handler}</code>
      </p>
    </section>
  )
}

function PermissionsCard({ permissions }: { permissions: string[] }) {
  return (
    <section className="rounded-md border border-border p-3 space-y-2">
      <h3 className="text-[10px] font-semibold uppercase tracking-wide text-muted-foreground flex items-center gap-1.5">
        <KeyRound className="h-3 w-3" />
        Required permissions
      </h3>
      <ul className="space-y-1">
        {permissions.map((p) => (
          <li key={p} className="text-xs font-mono text-foreground/90">
            {p}
          </li>
        ))}
      </ul>
    </section>
  )
}

function PlannedActionsCard({ actions }: { actions: string[] }) {
  return (
    <section className="rounded-md border border-border p-3 space-y-2">
      <h3 className="text-[10px] font-semibold uppercase tracking-wide text-muted-foreground flex items-center gap-1.5">
        <ChevronRight className="h-3 w-3" />
        Planned actions
      </h3>
      <ol className="space-y-1.5">
        {actions.map((action, i) => (
          <li key={action} className="text-xs flex items-start gap-2">
            <span className="text-muted-foreground font-mono tabular-nums w-4 shrink-0">{i + 1}.</span>
            <span>{action}</span>
          </li>
        ))}
      </ol>
    </section>
  )
}

function RollbackCard({ actions, window, reversible }: { actions: string[]; window?: string; reversible: boolean }) {
  return (
    <section className="rounded-md border border-border p-3 space-y-2">
      <h3 className="text-[10px] font-semibold uppercase tracking-wide text-muted-foreground flex items-center gap-1.5">
        <RotateCcw className="h-3 w-3" />
        Rollback plan
        {window ? <span className="font-normal normal-case text-muted-foreground/70">· window {window}</span> : null}
      </h3>
      {!reversible ? (
        <p className="text-xs text-muted-foreground italic">
          No automated SDK rollback path. Manual reversal documented below.
        </p>
      ) : null}
      <ol className="space-y-1.5">
        {actions.map((action, i) => (
          <li key={action} className="text-xs flex items-start gap-2">
            <span className="text-muted-foreground font-mono tabular-nums w-4 shrink-0">{i + 1}.</span>
            <span>{action}</span>
          </li>
        ))}
      </ol>
    </section>
  )
}

function PrerequisitesCard({ prerequisites }: { prerequisites: string[] }) {
  return (
    <section className="rounded-md border border-amber-200 bg-amber-50/60 dark:border-amber-900/40 dark:bg-amber-950/20 p-3 space-y-2">
      <h3 className="text-[10px] font-semibold uppercase tracking-wide text-amber-700 dark:text-amber-300 flex items-center gap-1.5">
        <ShieldCheck className="h-3 w-3" />
        Prerequisites
      </h3>
      <ul className="space-y-1">
        {prerequisites.map((p) => (
          <li key={p} className="text-xs text-amber-900 dark:text-amber-100">{p}</li>
        ))}
      </ul>
    </section>
  )
}

function WarningsCard({ warnings }: { warnings: string[] }) {
  return (
    <section className="rounded-md border border-red-200 bg-red-50/50 dark:border-red-900/40 dark:bg-red-950/20 p-3 space-y-2">
      <h3 className="text-[10px] font-semibold uppercase tracking-wide text-red-700 dark:text-red-300 flex items-center gap-1.5">
        <AlertTriangle className="h-3 w-3" />
        Warnings
      </h3>
      <ul className="space-y-1">
        {warnings.map((w) => (
          <li key={w} className="text-xs text-red-900 dark:text-red-100 flex items-start gap-1.5">
            <AlertTriangle className="h-3 w-3 mt-0.5 shrink-0" />
            <span>{w}</span>
          </li>
        ))}
      </ul>
    </section>
  )
}

function HopCandidatePicker({
  candidates,
  selectedIdx,
  onSelect,
}: {
  candidates: RemediationCandidate[]
  selectedIdx: number
  onSelect: (idx: number) => void
}) {
  return (
    <section className="space-y-2">
      <h3 className="text-[10px] font-semibold uppercase tracking-wide text-muted-foreground">
        Available remediations for this hop
      </h3>
      <div className="space-y-1.5">
        {candidates.map((cand, i) => {
          const active = i === selectedIdx
          return (
            <button
              key={cand.id}
              type="button"
              onClick={() => onSelect(i)}
              className={`w-full text-left rounded-md border p-2.5 transition-colors ${
                active
                  ? 'border-primary bg-primary/5'
                  : 'border-border hover:bg-muted/40'
              }`}
            >
              <div className="flex items-center gap-2 mb-1">
                <RemediationTierBadge tier={cand.tier} />
                <span className="text-xs font-medium">{cand.label}</span>
              </div>
              <p className="text-[10px] text-muted-foreground font-mono">{cand.handler}</p>
            </button>
          )
        })}
      </div>
    </section>
  )
}
