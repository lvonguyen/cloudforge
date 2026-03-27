import { createContext, useContext, useReducer, useCallback, useMemo, type ReactNode } from 'react'

interface TerminalPanelState {
  isOpen: boolean
  isConnected: boolean
  isExecuting: boolean
  panelHeight: number
}

type TerminalPanelAction =
  | { type: 'OPEN' }
  | { type: 'CLOSE' }
  | { type: 'TOGGLE' }
  | { type: 'SET_HEIGHT'; height: number }
  | { type: 'SET_CONNECTED'; connected: boolean }
  | { type: 'SET_EXECUTING'; executing: boolean }

const DEFAULT_PANEL_HEIGHT = 300

const initialState: TerminalPanelState = {
  isOpen: false,
  isConnected: false,
  isExecuting: false,
  panelHeight: DEFAULT_PANEL_HEIGHT,
}

function reducer(state: TerminalPanelState, action: TerminalPanelAction): TerminalPanelState {
  switch (action.type) {
    case 'OPEN':
      return { ...state, isOpen: true }
    case 'CLOSE':
      return { ...state, isOpen: false }
    case 'TOGGLE':
      return { ...state, isOpen: !state.isOpen }
    case 'SET_HEIGHT':
      return { ...state, panelHeight: Math.min(600, Math.max(150, action.height)) }
    case 'SET_CONNECTED':
      return { ...state, isConnected: action.connected }
    case 'SET_EXECUTING':
      return { ...state, isExecuting: action.executing }
  }
}

interface TerminalPanelContextValue {
  state: TerminalPanelState
  open: () => void
  close: () => void
  toggle: () => void
  setHeight: (height: number) => void
  setConnected: (connected: boolean) => void
  setExecuting: (executing: boolean) => void
}

const TerminalPanelContext = createContext<TerminalPanelContextValue | null>(null)

export function TerminalPanelProvider({ children }: { children: ReactNode }) {
  const [state, dispatch] = useReducer(reducer, initialState)

  const open = useCallback(() => dispatch({ type: 'OPEN' }), [])
  const close = useCallback(() => dispatch({ type: 'CLOSE' }), [])
  const toggle = useCallback(() => dispatch({ type: 'TOGGLE' }), [])
  const setHeight = useCallback((height: number) => dispatch({ type: 'SET_HEIGHT', height }), [])
  const setConnected = useCallback((connected: boolean) => dispatch({ type: 'SET_CONNECTED', connected }), [])
  const setExecuting = useCallback((executing: boolean) => dispatch({ type: 'SET_EXECUTING', executing }), [])

  const value = useMemo(
    () => ({ state, open, close, toggle, setHeight, setConnected, setExecuting }),
    [state, open, close, toggle, setHeight, setConnected, setExecuting],
  )

  return (
    <TerminalPanelContext.Provider value={value}>
      {children}
    </TerminalPanelContext.Provider>
  )
}

export function useTerminalPanel(): TerminalPanelContextValue {
  const ctx = useContext(TerminalPanelContext)
  if (!ctx) throw new Error('useTerminalPanel must be used within TerminalPanelProvider')
  return ctx
}
