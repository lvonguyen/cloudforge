import { cn } from '@/lib/utils'
import { useTracePanel } from '@/lib/trace-panel-context'
import { TerminalOutput } from '@/components/portal/TerminalOutput'
import { TraceTimeline } from '@/components/ai/TraceTimeline'
import { DryRunPreview } from '@/components/remediation/DryRunPreview'
import { X, ChevronUp, ChevronDown, Terminal, GitBranch, FlaskConical } from 'lucide-react'
import type { LucideIcon } from 'lucide-react'

const MODE_META: Record<string, { icon: LucideIcon; text: string }> = {
  streaming: { icon: Terminal, text: 'Execution Log' },
  timeline: { icon: GitBranch, text: 'Trace Timeline' },
  'dry-run': { icon: FlaskConical, text: 'Dry Run' },
}

export function ExecutionTracePanel() {
  const { state, toggle, close } = useTracePanel()

  if (!state.mode) return null

  const meta = MODE_META[state.mode]
  const ModeIcon = meta.icon

  return (
    <div
      className={cn(
        'fixed bottom-0 left-0 right-0 z-50 border-t border-border bg-background shadow-lg transition-[height] duration-200',
        state.isOpen ? 'h-[300px]' : 'h-9'
      )}
    >
      {/* Header bar */}
      <div
        role="button"
        tabIndex={0}
        onClick={toggle}
        onKeyDown={(e) => { if (e.key === 'Enter' || e.key === ' ') toggle() }}
        className="flex h-9 cursor-pointer items-center gap-2 border-b border-border bg-muted/50 px-3 text-xs select-none hover:bg-muted/80 transition-colors"
      >
        <ModeIcon className="h-3.5 w-3.5 text-muted-foreground" />
        <span className="font-medium text-foreground">{meta.text}</span>
        <span className="text-muted-foreground truncate max-w-[300px]">{state.actionLabel}</span>

        {state.isRunning && (
          <span className="ml-1 text-green-500 dark:text-green-400 animate-pulse font-medium">RUNNING</span>
        )}

        <div className="ml-auto flex items-center gap-1">
          {state.isOpen ? (
            <ChevronDown className="h-3.5 w-3.5 text-muted-foreground" />
          ) : (
            <ChevronUp className="h-3.5 w-3.5 text-muted-foreground" />
          )}
          <button
            onClick={(e) => { e.stopPropagation(); close() }}
            className="ml-1 rounded-sm p-0.5 text-muted-foreground hover:bg-muted hover:text-foreground transition-colors"
            aria-label="Close trace panel"
          >
            <X className="h-3.5 w-3.5" />
          </button>
        </div>
      </div>

      {/* Content area */}
      {state.isOpen && (
        <div className="h-[calc(100%-36px)] overflow-y-auto p-2">
          {state.mode === 'streaming' && (
            <TerminalOutput events={state.events} isRunning={state.isRunning} />
          )}
          {state.mode === 'timeline' && (
            <TraceTimeline spans={state.spans} />
          )}
          {state.mode === 'dry-run' && state.dryRunResult && (
            <DryRunPreview result={state.dryRunResult} />
          )}
        </div>
      )}
    </div>
  )
}
