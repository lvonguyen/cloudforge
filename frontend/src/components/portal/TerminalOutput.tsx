import { useEffect, useRef } from 'react'
import type { DeployEvent, DeployPhase } from '@/types/deploy'

const PHASE_COLORS: Record<DeployPhase, string> = {
  idle: 'text-gray-500',
  planning: 'text-blue-400',
  creating: 'text-yellow-400',
  configuring: 'text-cyan-400',
  verifying: 'text-indigo-400',
  live: 'text-green-400',
  teardown: 'text-orange-400',
  complete: 'text-green-300',
  error: 'text-red-400',
}

export function TerminalOutput({ events, isRunning }: { events: DeployEvent[]; isRunning: boolean }) {
  const bottomRef = useRef<HTMLDivElement>(null)

  useEffect(() => {
    bottomRef.current?.scrollIntoView({ behavior: 'smooth' })
  }, [events.length])

  return (
    <div className="bg-[#0d1117] border border-[#30363d] rounded-none font-mono text-xs overflow-hidden">
      <div className="flex items-center gap-2 px-3 py-1.5 bg-[#161b22] border-b border-[#30363d]">
        <div className="flex gap-1.5">
          <div className="w-2.5 h-2.5 rounded-full bg-[#ff5f56]" />
          <div className="w-2.5 h-2.5 rounded-full bg-[#ffbd2e]" />
          <div className="w-2.5 h-2.5 rounded-full bg-[#27c93f]" />
        </div>
        <span className="text-[10px] text-[#8b949e] ml-2">cloudforge deploy-preview</span>
        {isRunning && (
          <span className="ml-auto text-[10px] text-green-400 animate-pulse">RUNNING</span>
        )}
      </div>
      <div className="p-3 max-h-[320px] overflow-y-auto space-y-0.5">
        {events.map((evt, i) => (
          <div key={i} className="flex gap-2 leading-5">
            <span className="text-[#484f58] shrink-0 select-none">{evt.timestamp}</span>
            <span className={`shrink-0 ${PHASE_COLORS[evt.phase] ?? 'text-gray-400'}`}>
              [{evt.phase.toUpperCase()}]
            </span>
            <span className="text-[#c9d1d9]">{evt.message}</span>
          </div>
        ))}
        {events.length === 0 && (
          <span className="text-[#484f58]">Waiting for deploy preview to start...</span>
        )}
        {isRunning && (
          <div className="flex gap-2 leading-5">
            <span className="text-green-400 animate-pulse">{'>'}</span>
            <span className="text-[#484f58] animate-pulse">_</span>
          </div>
        )}
        <div ref={bottomRef} />
      </div>
    </div>
  )
}
