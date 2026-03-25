import { createContext, useContext, useReducer, type ReactNode } from 'react'
import type { DeployEvent } from '@/types/deploy'
import type { Span } from '@/types/ai-governance'
import type { DryRunResult } from '@/types/remediation'

export type TracePanelMode = 'streaming' | 'timeline' | 'dry-run' | null

interface TracePanelState {
  isOpen: boolean
  mode: TracePanelMode
  actionLabel: string
  events: DeployEvent[]
  spans: Span[]
  dryRunResult: DryRunResult | null
  isRunning: boolean
  panelHeight: number
}

type TracePanelAction =
  | { type: 'OPEN_STREAMING'; label: string }
  | { type: 'OPEN_TIMELINE'; label: string; spans: Span[] }
  | { type: 'OPEN_DRY_RUN'; label: string; result: DryRunResult }
  | { type: 'APPEND_EVENT'; event: DeployEvent }
  | { type: 'SET_RUNNING'; isRunning: boolean }
  | { type: 'SET_HEIGHT'; height: number }
  | { type: 'TOGGLE' }
  | { type: 'CLOSE' }

const DEFAULT_PANEL_HEIGHT = 300

const initialState: TracePanelState = {
  isOpen: false,
  mode: null,
  actionLabel: '',
  events: [],
  spans: [],
  dryRunResult: null,
  isRunning: false,
  panelHeight: DEFAULT_PANEL_HEIGHT,
}

function reducer(state: TracePanelState, action: TracePanelAction): TracePanelState {
  switch (action.type) {
    case 'OPEN_STREAMING':
      return {
        ...initialState,
        panelHeight: state.panelHeight,
        isOpen: true,
        mode: 'streaming',
        actionLabel: action.label,
        isRunning: true,
      }
    case 'OPEN_TIMELINE':
      return {
        ...initialState,
        panelHeight: state.panelHeight,
        isOpen: true,
        mode: 'timeline',
        actionLabel: action.label,
        spans: action.spans,
      }
    case 'OPEN_DRY_RUN':
      return {
        ...initialState,
        panelHeight: state.panelHeight,
        isOpen: true,
        mode: 'dry-run',
        actionLabel: action.label,
        dryRunResult: action.result,
      }
    case 'APPEND_EVENT':
      return {
        ...state,
        events: [...state.events, action.event],
      }
    case 'SET_RUNNING':
      return {
        ...state,
        isRunning: action.isRunning,
      }
    case 'SET_HEIGHT':
      return {
        ...state,
        panelHeight: Math.min(600, Math.max(150, action.height)),
      }
    case 'TOGGLE':
      return {
        ...state,
        isOpen: !state.isOpen,
      }
    case 'CLOSE':
      return { ...initialState, panelHeight: state.panelHeight }
  }
}

interface TracePanelContextValue {
  state: TracePanelState
  openStreaming: (label: string) => void
  openTimeline: (label: string, spans: Span[]) => void
  openDryRun: (label: string, result: DryRunResult) => void
  appendEvent: (event: DeployEvent) => void
  setRunning: (isRunning: boolean) => void
  setHeight: (height: number) => void
  toggle: () => void
  close: () => void
}

const TracePanelContext = createContext<TracePanelContextValue | null>(null)

export function TracePanelProvider({ children }: { children: ReactNode }) {
  const [state, dispatch] = useReducer(reducer, initialState)

  const openStreaming = (label: string) => dispatch({ type: 'OPEN_STREAMING', label })
  const openTimeline = (label: string, spans: Span[]) => dispatch({ type: 'OPEN_TIMELINE', label, spans })
  const openDryRun = (label: string, result: DryRunResult) => dispatch({ type: 'OPEN_DRY_RUN', label, result })
  const appendEvent = (event: DeployEvent) => dispatch({ type: 'APPEND_EVENT', event })
  const setRunning = (isRunning: boolean) => dispatch({ type: 'SET_RUNNING', isRunning })
  const setHeight = (height: number) => dispatch({ type: 'SET_HEIGHT', height })
  const toggle = () => dispatch({ type: 'TOGGLE' })
  const close = () => dispatch({ type: 'CLOSE' })

  return (
    <TracePanelContext.Provider value={{ state, openStreaming, openTimeline, openDryRun, appendEvent, setRunning, setHeight, toggle, close }}>
      {children}
    </TracePanelContext.Provider>
  )
}

export function useTracePanel(): TracePanelContextValue {
  const ctx = useContext(TracePanelContext)
  if (!ctx) throw new Error('useTracePanel must be used within TracePanelProvider')
  return ctx
}
